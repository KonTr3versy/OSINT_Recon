import { getAgentByName, routeAgentRequest, type AgentNamespace } from "agents";
import { authenticateRequest, identityAuditPayload, type AccessIdentity } from "./auth";
import { jobSummary, normalizeDomain, parseJsonRecord, summarizeJobResult } from "./mvp";
import { canQueuePlan, proposeReconPlan } from "./policy";
import { ReconAgent } from "./recon-agent";
import type { AssetRecord, DnsPolicy, Env, ReconMode, ReconPlanProposal } from "./types";

export { ReconAgent };

const jsonHeaders = {
  "content-type": "application/json; charset=utf-8",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const auth = authenticateRequest(request, env, {
      allowAnonymous: url.pathname === "/",
      serviceCallback: url.pathname.match(/^\/api\/jobs\/\d+\/result$/) !== null,
    });
    if (!auth.ok) {
      return auth.response;
    }

    const agentResponse = await routeAgentRequest(request, env);
    if (agentResponse) {
      return agentResponse;
    }

    if (url.pathname === "/") {
      return new Response(renderDashboard(), { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    if (request.method === "GET" && url.pathname === "/api/assets") {
      return listAssets(env, request);
    }
    if (request.method === "POST" && url.pathname === "/api/assets") {
      return createAsset(env, request, auth.identity);
    }
    if (request.method === "POST" && url.pathname === "/api/recon-plans") {
      return createReconPlan(env, request, auth.identity);
    }
    if (request.method === "POST" && url.pathname === "/api/recon/start") {
      return startPassiveRecon(env, request, auth.identity);
    }
    if (request.method === "GET" && url.pathname === "/api/jobs") {
      return listJobs(env, request);
    }
    if (request.method === "GET" && url.pathname.match(/^\/api\/jobs\/\d+$/)) {
      const jobId = Number(url.pathname.split("/")[3]);
      return getJob(env, request, jobId);
    }
    if (request.method === "GET" && url.pathname.match(/^\/api\/jobs\/\d+\/artifacts$/)) {
      const jobId = Number(url.pathname.split("/")[3]);
      return getJobArtifacts(env, request, jobId);
    }
    if (request.method === "POST" && url.pathname.match(/^\/api\/approvals\/\d+\/approve$/)) {
      const approvalId = Number(url.pathname.split("/")[3]);
      return decideApproval(env, request, auth.identity, approvalId, "approved");
    }
    if (request.method === "POST" && url.pathname.match(/^\/api\/approvals\/\d+\/reject$/)) {
      const approvalId = Number(url.pathname.split("/")[3]);
      return decideApproval(env, request, auth.identity, approvalId, "rejected");
    }
    if (request.method === "POST" && url.pathname.match(/^\/api\/recon-plans\/\d+\/queue$/)) {
      const planId = Number(url.pathname.split("/")[3]);
      return queuePlan(env, auth.identity, planId);
    }
    if (request.method === "POST" && url.pathname.match(/^\/api\/jobs\/\d+\/result$/)) {
      const jobId = Number(url.pathname.split("/")[3]);
      return recordJobResult(env, request, auth.identity, jobId);
    }
    if (request.method === "POST" && url.pathname.match(/^\/api\/agents\/[^/]+\/schedule$/)) {
      const orgId = decodeURIComponent(url.pathname.split("/")[3]);
      const agent = await getAgentByName(env.OSINT_AGENT as unknown as AgentNamespace<ReconAgent>, orgId);
      return agent.fetch(new Request(new URL("/schedule", request.url), request));
    }
    if (request.method === "POST" && url.pathname.match(/^\/api\/agents\/[^/]+\/chat$/)) {
      const orgId = decodeURIComponent(url.pathname.split("/")[3]);
      const agent = await getAgentByName(env.OSINT_AGENT as unknown as AgentNamespace<ReconAgent>, orgId);
      return agent.fetch(new Request(new URL("/chat", request.url), request));
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;

async function listAssets(env: Env, request: Request): Promise<Response> {
  const orgId = requireOrg(request);
  const result = await env.DB.prepare("SELECT * FROM assets WHERE org_id = ? ORDER BY domain").bind(orgId).all();
  return Response.json(result.results ?? [], { headers: jsonHeaders });
}

async function createAsset(env: Env, request: Request, identity: AccessIdentity): Promise<Response> {
  const orgId = requireOrg(request);
  const body = (await request.json()) as {
    domain: string;
    company?: string;
    allowedMode?: ReconMode;
    dnsPolicyCeiling?: DnsPolicy;
    thirdPartyIntelAllowed?: boolean;
    defaultSchedule?: string;
  };
  const result = await env.DB.prepare(
    `INSERT INTO assets (
      org_id, domain, company, allowed_mode, dns_policy_ceiling,
      third_party_intel_allowed, default_schedule
    ) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`,
  )
    .bind(
      orgId,
      body.domain.toLowerCase().trim(),
      body.company ?? null,
      body.allowedMode ?? "passive",
      body.dnsPolicyCeiling ?? "minimal",
      body.thirdPartyIntelAllowed ? 1 : 0,
      body.defaultSchedule ?? "0 9 * * 1",
    )
    .first<AssetRecord>();
  await audit(env, orgId, "asset.created", "asset", result?.id ?? null, withActor(identity, body));
  return Response.json(result, { status: 201, headers: jsonHeaders });
}

async function createReconPlan(env: Env, request: Request, identity: AccessIdentity): Promise<Response> {
  const orgId = requireOrg(request);
  const body = (await request.json()) as {
    assetId: number;
    requestedMode?: ReconMode;
    requestedDnsPolicy?: DnsPolicy;
    enableThirdPartyIntel?: boolean;
    budgets?: Record<string, number>;
  };
  const asset = await env.DB.prepare("SELECT * FROM assets WHERE org_id = ? AND id = ?")
    .bind(orgId, body.assetId)
    .first<AssetRecord>();
  if (!asset) {
    return Response.json({ error: "asset_not_found" }, { status: 404 });
  }
  const proposal = proposeReconPlan(
    asset,
    body.requestedMode ?? "passive",
    body.requestedDnsPolicy ?? "minimal",
    Boolean(body.enableThirdPartyIntel),
    body.budgets ?? {},
  );
  const planId = await persistPlan(env, orgId, proposal, identity);
  if (proposal.requiresApproval) {
    await env.DB.prepare(
      "INSERT INTO approval_requests (org_id, recon_plan_id, status, reason) VALUES (?, ?, 'pending', ?)",
    )
      .bind(orgId, planId, proposal.rationale)
      .run();
  }
  return Response.json({ id: planId, ...proposal }, { status: 201, headers: jsonHeaders });
}

async function startPassiveRecon(env: Env, request: Request, identity: AccessIdentity): Promise<Response> {
  const orgId = requireOrg(request);
  const body = (await request.json()) as { domain?: string; company?: string };
  const domain = normalizeDomain(body.domain ?? "");
  if (!domain) {
    return Response.json({ error: "domain_required" }, { status: 400 });
  }
  const company = (body.company ?? "").trim() || null;
  const asset = await findOrCreatePassiveAsset(env, orgId, domain, company, identity);
  const proposal = proposeReconPlan(asset, "passive", "minimal", false, {});
  const planId = await persistPlan(env, orgId, proposal, identity);
  const job = await enqueuePlan(env, identity, planId);
  await audit(env, orgId, "recon.one_click_started", "recon_job", job.cloudflareJobId, withActor(identity, {
    domain,
    company,
    assetId: asset.id,
    planId,
  }));
  return Response.json({ asset, plan: { id: planId, ...proposal }, job }, { status: 201, headers: jsonHeaders });
}

async function findOrCreatePassiveAsset(
  env: Env,
  orgId: string,
  domain: string,
  company: string | null,
  identity: AccessIdentity,
): Promise<AssetRecord> {
  const existing = await env.DB.prepare("SELECT * FROM assets WHERE org_id = ? AND domain = ? ORDER BY id LIMIT 1")
    .bind(orgId, domain)
    .first<AssetRecord>();
  if (existing) {
    if (company && company !== existing.company) {
      await env.DB.prepare("UPDATE assets SET company = ? WHERE id = ?").bind(company, existing.id).run();
      return { ...existing, company };
    }
    return existing;
  }
  const inserted = await env.DB.prepare(
    `INSERT INTO assets (
      org_id, domain, company, allowed_mode, dns_policy_ceiling,
      third_party_intel_allowed, default_schedule
    ) VALUES (?, ?, ?, 'passive', 'minimal', 0, '0 9 * * 1') RETURNING *`,
  )
    .bind(orgId, domain, company)
    .first<AssetRecord>();
  if (!inserted) {
    throw new Error("Failed to create asset");
  }
  await audit(env, orgId, "asset.created", "asset", inserted.id, withActor(identity, {
    domain,
    company,
    allowedMode: "passive",
    dnsPolicyCeiling: "minimal",
    thirdPartyIntelAllowed: false,
  }));
  return inserted;
}

async function decideApproval(
  env: Env,
  request: Request,
  identity: AccessIdentity,
  approvalId: number,
  status: "approved" | "rejected",
): Promise<Response> {
  const orgId = requireOrg(request);
  const body = await request.json().catch(() => ({}));
  const approval = await env.DB.prepare("SELECT * FROM approval_requests WHERE org_id = ? AND id = ?")
    .bind(orgId, approvalId)
    .first<{ recon_plan_id: number; status: string }>();
  if (!approval) {
    return Response.json({ error: "approval_not_found" }, { status: 404 });
  }
  if (approval.status !== "pending") {
    return Response.json({ error: "approval_already_decided" }, { status: 409 });
  }
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE approval_requests SET status = ?, decision_note = ?, decided_at = CURRENT_TIMESTAMP WHERE id = ?",
    ).bind(status, JSON.stringify(body), approvalId),
    env.DB.prepare("UPDATE recon_plans SET approval_status = ? WHERE id = ?").bind(
      status,
      approval.recon_plan_id,
    ),
  ]);
  await audit(env, orgId, `approval.${status}`, "approval_request", approvalId, withActor(identity, body));
  return Response.json({ id: approvalId, status }, { headers: jsonHeaders });
}

async function queuePlan(env: Env, identity: AccessIdentity, planId: number): Promise<Response> {
  try {
    const payload = await enqueuePlan(env, identity, planId);
    return Response.json(payload, { status: 201, headers: jsonHeaders });
  } catch (error) {
    if (error instanceof HttpError) {
      return Response.json({ error: error.message }, { status: error.status });
    }
    throw error;
  }
}

async function enqueuePlan(env: Env, identity: AccessIdentity, planId: number) {
  const plan = await env.DB.prepare(
    `SELECT p.*, a.domain, a.company
     FROM recon_plans p
     JOIN assets a ON a.id = p.asset_id
     WHERE p.id = ?`,
  )
    .bind(planId)
    .first<Record<string, string | number>>();
  if (!plan) {
    throw new HttpError("plan_not_found", 404);
  }
  if (!canQueuePlan(Boolean(plan.requires_approval), String(plan.approval_status))) {
    throw new HttpError("approval_required", 409);
  }
  const partialPayload = {
    orgId: String(plan.org_id),
    assetId: Number(plan.asset_id),
    reconPlanId: Number(plan.id),
    domain: String(plan.domain),
    company: plan.company ? String(plan.company) : null,
    mode: String(plan.requested_mode) as ReconMode,
    dnsPolicy: String(plan.requested_dns_policy) as DnsPolicy,
    enableThirdPartyIntel: Boolean(plan.enable_third_party_intel),
    budgets: JSON.parse(String(plan.budgets_json)),
  };
  const inserted = await env.DB.prepare(
    "INSERT INTO recon_jobs (org_id, asset_id, recon_plan_id, status, payload_json) VALUES (?, ?, ?, 'queued', ?) RETURNING id",
  )
    .bind(partialPayload.orgId, partialPayload.assetId, partialPayload.reconPlanId, JSON.stringify(partialPayload))
    .first<{ id: number }>();
  if (!inserted) {
    throw new HttpError("job_create_failed", 500);
  }
  const payload = { ...partialPayload, cloudflareJobId: inserted.id };
  await env.RECON_JOBS.send(payload);
  await audit(env, partialPayload.orgId, "job.queued", "recon_job", inserted.id, withActor(identity, payload));
  return payload;
}

async function listJobs(env: Env, request: Request): Promise<Response> {
  const orgId = requireOrg(request);
  const result = await env.DB.prepare(
    `SELECT j.*, a.domain, a.company
     FROM recon_jobs j
     JOIN assets a ON a.id = j.asset_id
     WHERE j.org_id = ?
     ORDER BY j.created_at DESC
     LIMIT 25`,
  )
    .bind(orgId)
    .all<Record<string, unknown>>();
  return Response.json((result.results ?? []).map(jobSummary), { headers: jsonHeaders });
}

async function getJob(env: Env, request: Request, jobId: number): Promise<Response> {
  const orgId = requireOrg(request);
  const row = await env.DB.prepare(
    `SELECT j.*, a.domain, a.company
     FROM recon_jobs j
     JOIN assets a ON a.id = j.asset_id
     WHERE j.org_id = ? AND j.id = ?`,
  )
    .bind(orgId, jobId)
    .first<Record<string, unknown>>();
  if (!row) {
    return Response.json({ error: "job_not_found" }, { status: 404 });
  }
  return Response.json(jobSummary(row), { headers: jsonHeaders });
}

async function getJobArtifacts(env: Env, request: Request, jobId: number): Promise<Response> {
  const orgId = requireOrg(request);
  const row = await env.DB.prepare("SELECT result_json FROM recon_jobs WHERE org_id = ? AND id = ?")
    .bind(orgId, jobId)
    .first<{ result_json: string | null }>();
  if (!row) {
    return Response.json({ error: "job_not_found" }, { status: 404 });
  }
  const result = parseJsonRecord(row.result_json);
  return Response.json(
    {
      jobId,
      artifactPrefix: typeof result.artifactPrefix === "string" ? result.artifactPrefix : "",
      artifacts: Array.isArray(result.artifacts) ? result.artifacts : [],
    },
    { headers: jsonHeaders },
  );
}

async function recordJobResult(
  env: Env,
  request: Request,
  identity: AccessIdentity,
  jobId: number,
): Promise<Response> {
  const orgId = requireOrg(request);
  const body = (await request.json()) as {
    status: string;
    artifactPrefix?: string;
    artifacts?: unknown[];
    ledgerTotals?: unknown;
    summary?: unknown;
    agentSummary?: string;
  };
  const analysis = await summarizeJobResult(env, orgId, jobId, body);
  const storedBody = {
    ...body,
    agentSummary: body.agentSummary ?? analysis.summary,
    agentSummaryStatus: analysis.status,
    agentSummaryMeta: analysis.meta,
  };
  await env.DB.prepare(
    "UPDATE recon_jobs SET status = ?, result_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
  )
    .bind(body.status, JSON.stringify(storedBody), jobId)
    .run();
  await env.DB.prepare(
    "INSERT INTO run_summaries (org_id, recon_job_id, asset_id, artifact_prefix, summary_json, agent_summary) SELECT org_id, id, asset_id, ?, ?, ? FROM recon_jobs WHERE id = ?",
  )
    .bind(
      body.artifactPrefix ?? null,
      JSON.stringify({
        summary: body.summary ?? {},
        ledgerTotals: body.ledgerTotals ?? {},
        artifacts: body.artifacts ?? [],
      }),
      storedBody.agentSummary ?? null,
      jobId,
    )
    .run();
  if (analysis.meta) {
    await audit(env, orgId, "agent.run_summary.generated", "recon_job", jobId, analysis.meta);
  }
  await audit(env, orgId, "job.result_recorded", "recon_job", jobId, withActor(identity, storedBody));
  return Response.json({ id: jobId, status: body.status }, { headers: jsonHeaders });
}

async function persistPlan(
  env: Env,
  orgId: string,
  proposal: ReconPlanProposal,
  identity: AccessIdentity,
): Promise<number> {
  const inserted = await env.DB.prepare(
    `INSERT INTO recon_plans (
      org_id, asset_id, requested_mode, requested_dns_policy, enable_third_party_intel,
      budgets_json, expected_sources_json, requires_approval, approval_status, rationale
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
  )
    .bind(
      orgId,
      proposal.assetId,
      proposal.requestedMode,
      proposal.requestedDnsPolicy,
      proposal.enableThirdPartyIntel ? 1 : 0,
      JSON.stringify(proposal.budgets),
      JSON.stringify(proposal.expectedSources),
      proposal.requiresApproval ? 1 : 0,
      proposal.requiresApproval ? "pending" : "approved",
      proposal.rationale,
    )
    .first<{ id: number }>();
  if (!inserted) {
    throw new Error("Failed to create recon plan");
  }
  await audit(env, orgId, "plan.proposed", "recon_plan", inserted.id, withActor(identity, proposal));
  return inserted.id;
}

async function audit(
  env: Env,
  orgId: string,
  action: string,
  targetType: string,
  targetId: number | null,
  payload: unknown,
) {
  await env.DB.prepare(
    "INSERT INTO audit_events (org_id, action, target_type, target_id, payload_json) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(orgId, action, targetType, targetId, JSON.stringify(payload ?? {}))
    .run();
}

function requireOrg(request: Request): string {
  return request.headers.get("X-Org-Id") ?? "default";
}

function withActor(identity: AccessIdentity, payload: unknown): Record<string, unknown> {
  return {
    actor: identityAuditPayload(identity),
    payload,
  };
}

class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

function renderDashboard(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OSINT Recon Agent Control Plane</title>
  <style>
    :root { color-scheme: light; --ink: #172026; --muted: #5c6975; --line: #d8dee4; --panel: #f6f8f9; --accent: #0f766e; --danger: #9f1239; }
    * { box-sizing: border-box; }
    body { font-family: Arial, sans-serif; margin: 0; color: var(--ink); background: #fff; }
    main { max-width: 1120px; margin: 0 auto; padding: 32px; }
    h1 { margin: 0 0 10px; font-size: 42px; line-height: 1.1; }
    h2 { margin: 34px 0 12px; font-size: 22px; }
    p { color: var(--muted); }
    code { background: var(--panel); padding: 2px 4px; }
    form { display: grid; gap: 12px; }
    label { font-weight: 700; }
    input, textarea { width: 100%; padding: 11px 12px; font: inherit; border: 1px solid var(--line); }
    textarea { min-height: 90px; }
    button { width: fit-content; padding: 10px 14px; font: inherit; cursor: pointer; border: 1px solid #0d5f59; background: var(--accent); color: #fff; }
    button.secondary { border-color: var(--line); background: #fff; color: var(--ink); }
    button:disabled { opacity: 0.65; cursor: wait; }
    .grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 0.8fr); gap: 24px; align-items: start; }
    .panel { border: 1px solid var(--line); padding: 18px; border-radius: 6px; }
    .status { margin-top: 12px; min-height: 24px; color: var(--muted); }
    .jobs { display: grid; gap: 12px; }
    .job { border: 1px solid var(--line); border-radius: 6px; padding: 14px; }
    .job header { display: flex; justify-content: space-between; gap: 12px; align-items: start; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 999px; background: var(--panel); font-size: 13px; }
    .badge.completed { background: #dcfce7; color: #14532d; }
    .badge.failed { background: #ffe4e6; color: var(--danger); }
    .meta { color: var(--muted); font-size: 14px; margin-top: 4px; }
    pre { min-height: 90px; white-space: pre-wrap; overflow-wrap: anywhere; background: var(--panel); padding: 14px; }
    ul { padding-left: 20px; }
    @media (max-width: 820px) { main { padding: 22px; } .grid { grid-template-columns: 1fr; } h1 { font-size: 32px; } }
  </style>
</head>
<body>
  <main>
    <h1>OSINT Recon Agent Control Plane</h1>
    <p>Start passive, approval-free recon for an approved organization. The Python executor performs deterministic checks; the LLM only explains completed results.</p>

    <div class="grid">
      <section class="panel">
        <h2>Start Passive Recon</h2>
        <form id="start-form">
          <label for="domain">Domain</label>
          <input id="domain" name="domain" placeholder="example.com" autocomplete="off" required />
          <label for="company">Organization Name</label>
          <input id="company" name="company" placeholder="Example Inc." autocomplete="organization" required />
          <button id="start-button" type="submit">Start passive recon</button>
        </form>
        <div id="start-status" class="status"></div>
      </section>

      <section class="panel">
        <h2>Agent Smoke Test</h2>
        <form id="chat-form">
          <label for="message">Agent message</label>
          <textarea id="message">What is your safety boundary?</textarea>
          <button type="submit" class="secondary">Send</button>
        </form>
        <pre id="output">Waiting for a message.</pre>
      </section>
    </div>

    <section>
      <h2>Recent Jobs</h2>
      <button id="refresh-jobs" class="secondary" type="button">Refresh</button>
      <div id="jobs" class="jobs" aria-live="polite"></div>
    </section>
  </main>
  <script>
    const orgHeaders = { "content-type": "application/json", "X-Org-Id": "default" };

    function setText(id, text) {
      document.getElementById(id).textContent = text;
    }

    function statusClass(status) {
      return "badge " + (status === "completed" || status === "failed" ? status : "");
    }

    function renderJob(job) {
      const article = document.createElement("article");
      article.className = "job";
      const header = document.createElement("header");
      const title = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = job.domain || "unknown domain";
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = "Job " + job.id + " · " + (job.company || "No organization") + " · " + (job.createdAt || "");
      title.append(strong, meta);
      const badge = document.createElement("span");
      badge.className = statusClass(job.status);
      badge.textContent = job.status || "unknown";
      header.append(title, badge);
      article.append(header);

      if (job.summary && Object.keys(job.summary).length) {
        const scores = document.createElement("div");
        scores.className = "meta";
        scores.textContent = "Email score: " + (job.summary.email_posture_score ?? "n/a") + " · Exposure score: " + (job.summary.exposure_score ?? "n/a");
        article.append(scores);
      }

      if (job.ledgerTotals && Object.keys(job.ledgerTotals).length) {
        const ledger = document.createElement("div");
        ledger.className = "meta";
        const counts = job.ledgerTotals.counts || {};
        ledger.textContent = "Ledger: target_http=" + (counts.target_http || 0) + ", target_dns=" + (counts.target_dns || 0) + ", third_party_http=" + (counts.third_party_http || 0);
        article.append(ledger);
      }

      if (job.agentSummary) {
        const summary = document.createElement("pre");
        summary.textContent = job.agentSummary;
        article.append(summary);
      }

      if (Array.isArray(job.artifacts) && job.artifacts.length) {
        const list = document.createElement("ul");
        for (const artifact of job.artifacts) {
          const item = document.createElement("li");
          item.textContent = artifact.key || JSON.stringify(artifact);
          list.append(item);
        }
        article.append(list);
      }

      if (job.error) {
        const error = document.createElement("div");
        error.className = "meta";
        error.textContent = "Error: " + job.error;
        article.append(error);
      }
      return article;
    }

    async function loadJobs() {
      const container = document.getElementById("jobs");
      container.textContent = "Loading jobs...";
      const response = await fetch("/api/jobs", { headers: { "X-Org-Id": "default" } });
      const jobs = await response.json();
      container.textContent = "";
      if (!Array.isArray(jobs) || jobs.length === 0) {
        container.textContent = "No jobs yet.";
        return;
      }
      for (const job of jobs) {
        container.append(renderJob(job));
      }
    }

    document.getElementById("start-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = document.getElementById("start-button");
      button.disabled = true;
      setText("start-status", "Creating asset, plan, and queue job...");
      try {
        const response = await fetch("/api/recon/start", {
          method: "POST",
          headers: orgHeaders,
          body: JSON.stringify({
            domain: document.getElementById("domain").value,
            company: document.getElementById("company").value,
          }),
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error || "request_failed");
        }
        setText("start-status", "Queued job " + payload.job.cloudflareJobId + " for " + payload.asset.domain + ".");
        await loadJobs();
      } catch (error) {
        setText("start-status", "Failed: " + (error.message || String(error)));
      } finally {
        button.disabled = false;
      }
    });

    document.getElementById("chat-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = document.getElementById("output");
      output.textContent = "Sending...";
      const response = await fetch("/api/agents/default/chat", {
        method: "POST",
        headers: orgHeaders,
        body: JSON.stringify({ message: document.getElementById("message").value }),
      });
      output.textContent = await response.text();
    });

    document.getElementById("refresh-jobs").addEventListener("click", loadJobs);
    loadJobs();
    setInterval(loadJobs, 15000);
  </script>
</body>
</html>`;
}
