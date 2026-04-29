import { getAgentByName, routeAgentRequest, type AgentNamespace } from "agents";
import { authenticateRequest, identityAuditPayload, type AccessIdentity } from "./auth";
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
  const plan = await env.DB.prepare(
    `SELECT p.*, a.domain, a.company
     FROM recon_plans p
     JOIN assets a ON a.id = p.asset_id
     WHERE p.id = ?`,
  )
    .bind(planId)
    .first<Record<string, string | number>>();
  if (!plan) {
    return Response.json({ error: "plan_not_found" }, { status: 404 });
  }
  if (!canQueuePlan(Boolean(plan.requires_approval), String(plan.approval_status))) {
    return Response.json({ error: "approval_required" }, { status: 409 });
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
    return Response.json({ error: "job_create_failed" }, { status: 500 });
  }
  const payload = { ...partialPayload, cloudflareJobId: inserted.id };
  await env.RECON_JOBS.send(payload);
  await audit(env, partialPayload.orgId, "job.queued", "recon_job", inserted.id, withActor(identity, payload));
  return Response.json(payload, { status: 201, headers: jsonHeaders });
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
    summary?: unknown;
    agentSummary?: string;
  };
  await env.DB.prepare(
    "UPDATE recon_jobs SET status = ?, result_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
  )
    .bind(body.status, JSON.stringify(body), jobId)
    .run();
  await env.DB.prepare(
    "INSERT INTO run_summaries (org_id, recon_job_id, asset_id, artifact_prefix, summary_json, agent_summary) SELECT org_id, id, asset_id, ?, ?, ? FROM recon_jobs WHERE id = ?",
  )
    .bind(body.artifactPrefix ?? null, JSON.stringify(body.summary ?? {}), body.agentSummary ?? null, jobId)
    .run();
  await audit(env, orgId, "job.result_recorded", "recon_job", jobId, withActor(identity, body));
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

function renderDashboard(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OSINT Recon Agent Control Plane</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; color: #172026; }
    main { max-width: 960px; margin: 0 auto; padding: 32px; }
    code { background: #f6f8f9; padding: 2px 4px; }
  </style>
</head>
<body>
  <main>
    <h1>OSINT Recon Agent Control Plane</h1>
    <p>Cloudflare Agent, D1, R2, and Queue front end for approved defensive recon workflows.</p>
    <p>Connect to <code>/agents/recon-agent/&lt;org-id&gt;</code> for stateful agent sessions.</p>
  </main>
</body>
</html>`;
}
