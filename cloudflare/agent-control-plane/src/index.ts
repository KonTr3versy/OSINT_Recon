import { getAgentByName, routeAgentRequest, type AgentNamespace } from "agents";
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { authenticateRequest, identityAuditPayload, type AccessIdentity } from "./auth";
import {
  buildEnhancedReports,
  buildPhishingAnalysisMessages,
  computeRunDrift,
  jobSummary,
  normalizeDomain,
  parseJsonRecord,
  parseModelJsonObject,
  resolveReconLevel,
  sanitizeSubdomainPhishingAnalysis,
  subdomainInventory,
  summarizeJobResult,
} from "./mvp";
import { runReconModel } from "./ai";
import { canQueuePlan, proposeReconPlan } from "./policy";
import { ReconAgent } from "./recon-agent";
import type { AssetRecord, DnsPolicy, Env, ReconMode, ReconPlanProposal, ReconWorkflowParams } from "./types";

export { ReconAgent };

export class ReconRunWorkflow extends WorkflowEntrypoint<Env, ReconWorkflowParams> {
  async run(event: Readonly<WorkflowEvent<ReconWorkflowParams>>, step: WorkflowStep): Promise<unknown> {
    const { orgId, planId, workflowId } = event.payload;
    const identity = workflowIdentity();
    await step.do("workflow.started", async () => {
      await audit(this.env, orgId, "workflow.started", "recon_plan", planId, { workflowId });
    });
    const plan = await step.do("workflow.load_plan", async () => loadPlanForQueue(this.env, orgId, planId));
    if (!plan) {
      await step.do("workflow.plan_missing", async () => {
        await audit(this.env, orgId, "workflow.plan_missing", "recon_plan", planId, { workflowId });
      });
      return { status: "failed", error: "plan_not_found" };
    }
    if (Boolean(plan.requires_approval) && String(plan.approval_status) !== "approved") {
      await step.do("workflow.awaiting_approval", async () => {
        await audit(this.env, orgId, "workflow.awaiting_approval", "recon_plan", planId, { workflowId });
      });
      const decision = await step.waitForEvent("approval_decided", { type: "approval_decided", timeout: "30 days" });
      const decisionPayload = decision.payload as { approvalId?: number; status?: string; note?: unknown };
      if (decisionPayload.status !== "approved") {
        await step.do("workflow.approval_rejected", async () => {
          await audit(this.env, orgId, "workflow.rejected", "recon_plan", planId, { workflowId, decision: decisionPayload });
        });
        return { status: "rejected", workflowId, decision: decisionPayload };
      }
    }
    const job = await step.do("workflow.queue_executor_job", async () => {
      return enqueuePlan(this.env, identity, orgId, planId, workflowId);
    });
    await step.do("workflow.job_running", async () => {
      await updateJobWorkflowStatus(this.env, orgId, Number(job.cloudflareJobId), "running", workflowId);
    });
    const result = await step.waitForEvent("executor_result", {
      type: "executor_result",
      timeout: "7 days",
    });
    const processedJson = await step.do("workflow.persist_result", async () => {
      const processed = await finalizeJobResult(
        this.env,
        orgId,
        identity,
        Number(job.cloudflareJobId),
        result.payload as Record<string, unknown>,
        workflowId,
      );
      return JSON.stringify(processed);
    });
    await step.do("workflow.completed", async () => {
      await audit(this.env, orgId, "workflow.completed", "recon_job", Number(job.cloudflareJobId), { workflowId, processed: processedJson });
    });
    return { status: "completed", workflowId, jobId: Number(job.cloudflareJobId) };
  }
}

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
      return startRecon(env, request, auth.identity);
    }
    if (request.method === "GET" && url.pathname === "/api/approvals") {
      return listApprovals(env, request);
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
    if (request.method === "GET" && url.pathname.match(/^\/api\/jobs\/\d+\/artifacts\/\d+$/)) {
      const parts = url.pathname.split("/");
      return streamJobArtifact(env, request, Number(parts[3]), Number(parts[5]));
    }
    if (request.method === "POST" && url.pathname.match(/^\/api\/jobs\/\d+\/rerun$/)) {
      const jobId = Number(url.pathname.split("/")[3]);
      return rerunJob(env, request, auth.identity, jobId);
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
      return queuePlan(env, request, auth.identity, planId);
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
    await requestApprovalForPlan(env, orgId, planId, proposal.rationale);
  }
  return Response.json({ id: planId, ...proposal }, { status: 201, headers: jsonHeaders });
}

async function startRecon(env: Env, request: Request, identity: AccessIdentity): Promise<Response> {
  const orgId = requireOrg(request);
  const body = (await request.json()) as { domain?: string; company?: string; reconLevel?: string };
  const domain = normalizeDomain(body.domain ?? "");
  if (!domain) {
    return Response.json({ error: "domain_required" }, { status: 400 });
  }
  const company = (body.company ?? "").trim() || null;
  const asset = await findOrCreatePassiveAsset(env, orgId, domain, company, identity);
  const reconLevel = resolveReconLevel(body.reconLevel);
  const proposal = proposeReconPlan(
    asset,
    reconLevel.mode,
    reconLevel.dnsPolicy,
    reconLevel.enableThirdPartyIntel,
    reconLevel.budgets,
  );
  const planId = await persistPlan(env, orgId, proposal, identity);
  const workflowId = workflowIdForPlan(planId);
  await startReconWorkflow(env, orgId, planId, workflowId, identity);
  if (proposal.requiresApproval) {
    const approval = await requestApprovalForPlan(env, orgId, planId, proposal.rationale);
    await audit(env, orgId, "recon.approval_requested", "recon_plan", planId, withActor(identity, {
      domain,
      company,
      assetId: asset.id,
      planId,
      reconLevel: reconLevel.id,
      approvalId: approval.id,
      workflowId,
    }));
    return Response.json(
      {
        approvalRequired: true,
        workflowId,
        workflowStatus: "awaiting_approval",
        asset,
        plan: { id: planId, reconLevel: reconLevel.id, ...proposal },
        approval,
      },
      { status: 202, headers: jsonHeaders },
    );
  }
  await audit(env, orgId, "recon.workflow_started", "recon_plan", planId, withActor(identity, {
    domain,
    company,
    assetId: asset.id,
    planId,
    reconLevel: reconLevel.id,
    workflowId,
  }));
  return Response.json(
    {
      approvalRequired: false,
      workflowId,
      workflowStatus: "started",
      asset,
      plan: { id: planId, reconLevel: reconLevel.id, ...proposal },
    },
    { status: 202, headers: jsonHeaders },
  );
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

async function requestApprovalForPlan(
  env: Env,
  orgId: string,
  planId: number,
  reason: string,
): Promise<{ id: number; reconPlanId: number; status: "pending"; reason: string }> {
  const inserted = await env.DB.prepare(
    "INSERT INTO approval_requests (org_id, recon_plan_id, status, reason) VALUES (?, ?, 'pending', ?) RETURNING id",
  )
    .bind(orgId, planId, reason)
    .first<{ id: number }>();
  if (!inserted) {
    throw new Error("Failed to create approval request");
  }
  return { id: inserted.id, reconPlanId: planId, status: "pending", reason };
}

async function listApprovals(env: Env, request: Request): Promise<Response> {
  const orgId = requireOrg(request);
  const result = await env.DB.prepare(
    `SELECT
       ar.id,
       ar.recon_plan_id,
       ar.status,
       ar.reason,
       ar.created_at,
       ar.decided_at,
       p.requested_mode,
       p.requested_dns_policy,
       p.enable_third_party_intel,
       p.budgets_json,
       p.expected_sources_json,
       p.rationale,
       a.id AS asset_id,
       a.domain,
       a.company
     FROM approval_requests ar
     JOIN recon_plans p ON p.id = ar.recon_plan_id
     JOIN assets a ON a.id = p.asset_id
     WHERE ar.org_id = ?
     ORDER BY CASE ar.status WHEN 'pending' THEN 0 ELSE 1 END, ar.created_at DESC
     LIMIT 25`,
  )
    .bind(orgId)
    .all<Record<string, unknown>>();
  return Response.json((result.results ?? []).map(approvalSummary), { headers: jsonHeaders });
}

function approvalSummary(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: Number(row.id),
    reconPlanId: Number(row.recon_plan_id),
    assetId: Number(row.asset_id),
    status: String(row.status ?? ""),
    reason: String(row.reason ?? row.rationale ?? ""),
    createdAt: String(row.created_at ?? ""),
    decidedAt: row.decided_at ? String(row.decided_at) : null,
    domain: String(row.domain ?? ""),
    company: row.company ? String(row.company) : null,
    requestedMode: String(row.requested_mode ?? ""),
    requestedDnsPolicy: String(row.requested_dns_policy ?? ""),
    enableThirdPartyIntel: Boolean(row.enable_third_party_intel),
    budgets: parseJsonRecord(row.budgets_json),
    expectedSources: parseJsonArray(row.expected_sources_json),
  };
}

function parseJsonArray(value: unknown): unknown[] {
  if (typeof value !== "string" || !value) {
    return [];
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
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
  await sendWorkflowEvent(env, approval.recon_plan_id, "approval_decided", {
    approvalId,
    status,
    note: body,
  });
  return Response.json({ id: approvalId, reconPlanId: approval.recon_plan_id, status }, { headers: jsonHeaders });
}

async function queuePlan(env: Env, request: Request, identity: AccessIdentity, planId: number): Promise<Response> {
  const orgId = requireOrg(request);
  try {
    const payload = await enqueuePlan(env, identity, orgId, planId);
    return Response.json(payload, { status: 201, headers: jsonHeaders });
  } catch (error) {
    if (error instanceof HttpError) {
      return Response.json({ error: error.message }, { status: error.status });
    }
    throw error;
  }
}

async function enqueuePlan(env: Env, identity: AccessIdentity, orgId: string, planId: number, workflowId?: string) {
  const plan = await loadPlanForQueue(env, orgId, planId);
  if (!plan) {
    throw new HttpError("plan_not_found", 404);
  }
  if (!canQueuePlan(Boolean(plan.requires_approval), String(plan.approval_status))) {
    throw new HttpError("approval_required", 409);
  }
  const existingQueued = await env.DB.prepare(
    "SELECT id, payload_json FROM recon_jobs WHERE org_id = ? AND recon_plan_id = ? ORDER BY id DESC LIMIT 1",
  )
    .bind(orgId, planId)
    .first<{ id: number; payload_json: string }>();
  if (existingQueued) {
    return { ...parseJsonRecord(existingQueued.payload_json), cloudflareJobId: existingQueued.id };
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
    ...(workflowId ? { workflowId } : {}),
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

async function loadPlanForQueue(env: Env, orgId: string, planId: number): Promise<Record<string, string | number> | null> {
  return await env.DB.prepare(
    `SELECT p.*, a.domain, a.company
     FROM recon_plans p
     JOIN assets a ON a.id = p.asset_id
     WHERE p.org_id = ? AND p.id = ?`,
  )
    .bind(orgId, planId)
    .first<Record<string, string | number>>();
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

async function streamJobArtifact(env: Env, request: Request, jobId: number, artifactIndex: number): Promise<Response> {
  const orgId = requireOrg(request);
  const row = await env.DB.prepare("SELECT result_json FROM recon_jobs WHERE org_id = ? AND id = ?")
    .bind(orgId, jobId)
    .first<{ result_json: string | null }>();
  if (!row) {
    return Response.json({ error: "job_not_found" }, { status: 404 });
  }
  const result = parseJsonRecord(row.result_json);
  const artifacts = Array.isArray(result.artifacts) ? result.artifacts : [];
  const artifact = artifacts[artifactIndex];
  if (!isArtifactRecord(artifact)) {
    return Response.json({ error: "artifact_not_found" }, { status: 404 });
  }
  const object = await env.ARTIFACTS.get(artifact.key);
  if (!object) {
    return Response.json({ error: "artifact_object_not_found" }, { status: 404 });
  }
  const headers = new Headers();
  headers.set("content-type", artifact.contentType || object.httpMetadata?.contentType || "application/octet-stream");
  headers.set("cache-control", "private, max-age=60");
  headers.set("content-disposition", `inline; filename="${artifact.key.split("/").pop() || "artifact"}"`);
  return new Response(object.body, { headers });
}

async function rerunJob(env: Env, request: Request, identity: AccessIdentity, jobId: number): Promise<Response> {
  const orgId = requireOrg(request);
  const row = await env.DB.prepare(
    `SELECT j.asset_id, j.payload_json, a.*
     FROM recon_jobs j
     JOIN assets a ON a.id = j.asset_id
     WHERE j.org_id = ? AND j.id = ?`,
  )
    .bind(orgId, jobId)
    .first<AssetRecord & { payload_json?: string }>();
  if (!row) {
    return Response.json({ error: "job_not_found" }, { status: 404 });
  }
  const previousPayload = parseJsonRecord(row.payload_json);
  const requestedMode = previousPayload.mode === "low-noise" ? "low-noise" : "passive";
  const requestedDnsPolicy = previousPayload.dnsPolicy === "full"
    ? "full"
    : previousPayload.dnsPolicy === "none"
      ? "none"
      : "minimal";
  const proposal = proposeReconPlan(
    row,
    requestedMode,
    requestedDnsPolicy,
    Boolean(previousPayload.enableThirdPartyIntel),
    parseBudgetRecord(previousPayload.budgets),
  );
  const planId = await persistPlan(env, orgId, proposal, identity);
  if (proposal.requiresApproval) {
    const approval = await requestApprovalForPlan(env, orgId, planId, proposal.rationale);
    await audit(env, orgId, "job.rerun_approval_requested", "recon_plan", planId, withActor(identity, {
      sourceJobId: jobId,
      assetId: row.id,
      planId,
      approvalId: approval.id,
      requestedMode,
      requestedDnsPolicy,
    }));
    return Response.json(
      { approvalRequired: true, sourceJobId: jobId, plan: { id: planId, ...proposal }, approval },
      { status: 202, headers: jsonHeaders },
    );
  }
  const job = await enqueuePlan(env, identity, orgId, planId);
  await audit(env, orgId, "job.rerun_queued", "recon_job", job.cloudflareJobId, withActor(identity, {
    sourceJobId: jobId,
    assetId: row.id,
    planId,
  }));
  return Response.json(
    { approvalRequired: false, sourceJobId: jobId, plan: { id: planId, ...proposal }, job },
    { status: 201, headers: jsonHeaders },
  );
}

function parseBudgetRecord(value: unknown): Record<string, number> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {};
  }
  const budgets: Record<string, number> = {};
  for (const [key, budgetValue] of Object.entries(value)) {
    if (typeof budgetValue === "number" && Number.isFinite(budgetValue)) {
      budgets[key] = budgetValue;
    }
  }
  return budgets;
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
    findings?: unknown;
    moduleStatuses?: unknown[];
    agentSummary?: string;
  };
  const existingJob = await env.DB.prepare("SELECT id, payload_json FROM recon_jobs WHERE org_id = ? AND id = ?")
    .bind(orgId, jobId)
    .first<{ id: number; payload_json: string }>();
  if (!existingJob) {
    return Response.json({ error: "job_not_found" }, { status: 404 });
  }
  const payload = parseJsonRecord(existingJob.payload_json);
  const workflowId = typeof payload.workflowId === "string" ? payload.workflowId : "";
  if (workflowId) {
    await updateJobWorkflowStatus(env, orgId, jobId, "processing_result", workflowId);
    try {
      const instance = await env.RECON_RUN_WORKFLOW.get(workflowId);
      await instance.sendEvent({ type: "executor_result", payload: body });
      await audit(env, orgId, "job.result_event_sent", "recon_job", jobId, withActor(identity, { workflowId }));
      return Response.json({ id: jobId, status: "processing_result", workflowId }, { status: 202, headers: jsonHeaders });
    } catch (error) {
      await audit(env, orgId, "job.result_event_failed", "recon_job", jobId, withActor(identity, {
        workflowId,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  }
  const storedBody = await finalizeJobResult(env, orgId, identity, jobId, body, workflowId || undefined);
  return Response.json({ id: jobId, status: String(storedBody.status ?? body.status), workflowId }, { headers: jsonHeaders });
}

async function finalizeJobResult(
  env: Env,
  orgId: string,
  identity: AccessIdentity,
  jobId: number,
  body: Record<string, unknown>,
  workflowId?: string,
): Promise<Record<string, unknown>> {
  const resultBody = body as {
    status: string;
    artifactPrefix?: string;
    artifacts?: unknown[];
    ledgerTotals?: unknown;
    summary?: unknown;
    findings?: unknown;
    moduleStatuses?: unknown[];
    agentSummary?: string;
  };
  const analysis = await summarizeJobResult(env, orgId, jobId, resultBody);
  const previousResult = await loadPreviousJobResult(env, orgId, jobId);
  const drift = computeRunDrift(previousResult, body);
  const phishingAnalysis = await analyzeSubdomainPhishingRisk(env, orgId, jobId, body);
  const enhancedArtifacts = await writeEnhancedReportArtifacts(env, jobId, body, drift, phishingAnalysis);
  const storedBody = {
    ...body,
    workflowId,
    workflowStatus: "completed",
    drift,
    subdomainInventory: subdomainInventory(body.findings),
    subdomainPhishingAnalysis: phishingAnalysis.analysis,
    agentSummary: body.agentSummary ?? analysis.summary,
    agentSummaryStatus: analysis.status,
    agentSummaryMeta: analysis.meta,
    artifacts: [...(Array.isArray(body.artifacts) ? body.artifacts : []), ...enhancedArtifacts],
  };
  await env.DB.prepare(
    "UPDATE recon_jobs SET status = ?, result_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
  )
    .bind(typeof body.status === "string" ? body.status : "completed", JSON.stringify(storedBody), jobId)
    .run();
  await env.DB.prepare(
    "INSERT INTO run_summaries (org_id, recon_job_id, asset_id, artifact_prefix, summary_json, agent_summary) SELECT org_id, id, asset_id, ?, ?, ? FROM recon_jobs WHERE id = ?",
  )
    .bind(
      body.artifactPrefix ?? null,
      JSON.stringify({
        summary: body.summary ?? {},
        findings: body.findings ?? {},
        moduleStatuses: body.moduleStatuses ?? [],
        ledgerTotals: body.ledgerTotals ?? {},
        artifacts: storedBody.artifacts,
        drift,
        subdomainPhishingAnalysis: phishingAnalysis.analysis,
      }),
      storedBody.agentSummary ?? null,
      jobId,
    )
    .run();
  if (analysis.meta) {
    await audit(env, orgId, "agent.run_summary.generated", "recon_job", jobId, analysis.meta);
  }
  await audit(env, orgId, "agent.subdomain_phishing_analysis.generated", "recon_job", jobId, phishingAnalysis.meta);
  await audit(env, orgId, "job.result_recorded", "recon_job", jobId, withActor(identity, storedBody));
  return storedBody;
}

async function loadPreviousJobResult(
  env: Env,
  orgId: string,
  jobId: number,
): Promise<Record<string, unknown> | null> {
  const row = await env.DB.prepare(
    `SELECT previous.id, previous.result_json
     FROM recon_jobs current
     JOIN recon_jobs previous ON previous.asset_id = current.asset_id
     WHERE current.org_id = ? AND current.id = ?
       AND previous.org_id = current.org_id
       AND previous.id != current.id
       AND previous.status = 'completed'
       AND previous.result_json IS NOT NULL
     ORDER BY previous.created_at DESC
     LIMIT 1`,
  )
    .bind(orgId, jobId)
    .first<{ id: number; result_json: string }>();
  if (!row) {
    return null;
  }
  return { ...parseJsonRecord(row.result_json), jobId: row.id };
}

async function analyzeSubdomainPhishingRisk(
  env: Env,
  orgId: string,
  jobId: number,
  body: Record<string, unknown>,
): Promise<{ analysis: Record<string, unknown>; meta: Record<string, unknown> }> {
  if (body.status !== "completed") {
    return {
      analysis: {},
      meta: { jobId, status: "skipped", reason: "job_not_completed" },
    };
  }
  try {
    const result = await runReconModel(env, buildPhishingAnalysisMessages(orgId, jobId, body), {
      agent: "ReconAgent",
      action: "subdomain_phishing_analysis",
      jobId: String(jobId),
    });
    return {
      analysis: sanitizeSubdomainPhishingAnalysis(parseModelJsonObject(result.content), body, { orgId, jobId }),
      meta: {
        jobId,
        status: "generated_sanitized",
        model: result.model,
        provider: result.provider,
        gatewayUsed: result.gatewayUsed,
      },
    };
  } catch (error) {
    return {
      analysis: {
        overview: "Subdomain phishing-target analysis unavailable.",
        notableTargets: [],
        monitoringRecommendations: [],
        safetyNote: "No phishing instructions were generated.",
      },
      meta: {
        jobId,
        status: "unavailable",
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

async function writeEnhancedReportArtifacts(
  env: Env,
  jobId: number,
  body: Record<string, unknown>,
  drift: Record<string, unknown>,
  phishingAnalysis: { analysis: Record<string, unknown> },
): Promise<Array<{ key: string; contentType: string; bytes: number }>> {
  if (body.status !== "completed") {
    return [];
  }
  const artifactPrefix = typeof body.artifactPrefix === "string" && body.artifactPrefix
    ? body.artifactPrefix.replace(/^runs\//, "")
    : `job-${jobId}`;
  const domain = typeof body.domain === "string"
    ? body.domain
    : typeof body.artifactPrefix === "string"
      ? body.artifactPrefix.split("/")[0]
      : `job-${jobId}`;
  const reports = buildEnhancedReports({
    domain,
    company: typeof body.company === "string" ? body.company : null,
    summary: body.summary,
    drift,
    phishingAnalysis: phishingAnalysis.analysis,
    subdomainInventory: subdomainInventory(body.findings),
    artifacts: Array.isArray(body.artifacts) ? body.artifacts : [],
  });
  const baseKey = `runs/${artifactPrefix}/artifacts`;
  const mdKey = `${baseKey}/agent_enhanced_report.md`;
  const htmlKey = `${baseKey}/agent_enhanced_report.html`;
  await env.ARTIFACTS.put(mdKey, reports.markdown, { httpMetadata: { contentType: "text/markdown; charset=utf-8" } });
  await env.ARTIFACTS.put(htmlKey, reports.html, { httpMetadata: { contentType: "text/html; charset=utf-8" } });
  return [
    { key: mdKey, contentType: "text/markdown; charset=utf-8", bytes: byteLength(reports.markdown) },
    { key: htmlKey, contentType: "text/html; charset=utf-8", bytes: byteLength(reports.html) },
  ];
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isArtifactRecord(value: unknown): value is { key: string; contentType?: string } {
  return typeof value === "object" && value !== null && "key" in value && typeof (value as { key?: unknown }).key === "string";
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

function workflowIdForPlan(planId: number): string {
  return `recon-plan-${planId}`;
}

async function startReconWorkflow(
  env: Env,
  orgId: string,
  planId: number,
  workflowId: string,
  identity: AccessIdentity,
): Promise<void> {
  try {
    await env.RECON_RUN_WORKFLOW.create({
      id: workflowId,
      params: {
        orgId,
        planId,
        workflowId,
        requestedBy: identityAuditPayload(identity),
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.toLowerCase().includes("already")) {
      throw error;
    }
  }
  await audit(env, orgId, "workflow.created", "recon_plan", planId, withActor(identity, { workflowId }));
}

async function sendWorkflowEvent(
  env: Env,
  planId: number,
  type: string,
  payload: unknown,
): Promise<void> {
  const workflowId = workflowIdForPlan(planId);
  try {
    const instance = await env.RECON_RUN_WORKFLOW.get(workflowId);
    await instance.sendEvent({ type, payload });
  } catch {
    // Older/manual plans may not have a workflow instance. Keep the REST path compatible.
  }
}

async function updateJobWorkflowStatus(
  env: Env,
  orgId: string,
  jobId: number,
  workflowStatus: string,
  workflowId: string,
): Promise<void> {
  const row = await env.DB.prepare("SELECT result_json FROM recon_jobs WHERE org_id = ? AND id = ?")
    .bind(orgId, jobId)
    .first<{ result_json: string | null }>();
  const result = parseJsonRecord(row?.result_json ?? "");
  await env.DB.prepare("UPDATE recon_jobs SET result_json = ?, updated_at = CURRENT_TIMESTAMP WHERE org_id = ? AND id = ?")
    .bind(JSON.stringify({ ...result, workflowId, workflowStatus }), orgId, jobId)
    .run();
}

function workflowIdentity(): AccessIdentity {
  return {
    type: "service-token",
    email: "ReconRunWorkflow",
    jwtPresent: false,
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
    :root { color-scheme: light; --ink: #172026; --muted: #5c6975; --line: #d8dee4; --panel: #f6f8f9; --accent: #0f766e; --danger: #9f1239; --good: #15803d; --warn: #a16207; }
    * { box-sizing: border-box; }
    body { font-family: Arial, sans-serif; margin: 0; color: var(--ink); background: #fff; }
    main { max-width: 1120px; margin: 0 auto; padding: 32px; }
    h1 { margin: 0 0 10px; font-size: 42px; line-height: 1.1; }
    h2 { margin: 34px 0 12px; font-size: 22px; }
    p { color: var(--muted); }
    code { background: var(--panel); padding: 2px 4px; }
    form { display: grid; gap: 12px; }
    label { font-weight: 700; }
    input, textarea, select { width: 100%; padding: 11px 12px; font: inherit; border: 1px solid var(--line); background: #fff; }
    textarea { min-height: 90px; }
    button { width: fit-content; padding: 10px 14px; font: inherit; cursor: pointer; border: 1px solid #0d5f59; background: var(--accent); color: #fff; }
    button.secondary { border-color: var(--line); background: #fff; color: var(--ink); }
    button:disabled { opacity: 0.65; cursor: wait; }
    .grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 0.8fr); gap: 24px; align-items: start; }
    .panel { border: 1px solid var(--line); padding: 18px; border-radius: 6px; }
    .status { margin-top: 12px; min-height: 24px; color: var(--muted); }
    .jobs, .approvals { display: grid; gap: 12px; }
    .job, .approval { border: 1px solid var(--line); border-radius: 6px; padding: 14px; }
    .job header, .approval header { display: flex; justify-content: space-between; gap: 12px; align-items: start; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 999px; background: var(--panel); font-size: 13px; }
    .badge.completed { background: #dcfce7; color: #14532d; }
    .badge.queued { background: #fef9c3; color: #713f12; }
    .badge.running, .badge.processing_result { background: #dbeafe; color: #1e3a8a; }
    .badge.pending { background: #ffedd5; color: #7c2d12; }
    .badge.approved { background: #dcfce7; color: #14532d; }
    .badge.rejected { background: #ffe4e6; color: var(--danger); }
    .badge.failed { background: #ffe4e6; color: var(--danger); }
    .score-row, .ledger-row, .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    .score-card, .ledger-card { border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; background: #fff; min-width: 140px; }
    .score-card strong, .ledger-card strong { display: block; font-size: 18px; color: var(--ink); }
    .score-card span, .ledger-card span { display: block; color: var(--muted); font-size: 12px; }
    .meta { color: var(--muted); font-size: 14px; margin-top: 4px; }
    .hint { color: var(--muted); font-size: 13px; margin-top: -6px; }
    .warning { color: var(--warn); }
    details { margin-top: 12px; }
    summary { cursor: pointer; color: var(--ink); font-weight: 700; }
    pre { max-height: 360px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; background: var(--panel); padding: 14px; }
    a { color: #0f5f99; }
    ul { padding-left: 20px; }
    @media (max-width: 820px) { main { padding: 22px; } .grid { grid-template-columns: 1fr; } h1 { font-size: 32px; } }
  </style>
</head>
<body>
  <main>
    <h1>OSINT Recon Agent Control Plane</h1>
    <p>Start safe passive recon immediately, or request approval for higher-fidelity recon. The Python executor performs deterministic checks; the LLM only explains completed results.</p>

    <div class="grid">
      <section class="panel">
        <h2>Start Recon</h2>
        <form id="start-form">
          <label for="domain">Domain</label>
          <input id="domain" name="domain" placeholder="example.com" autocomplete="off" required />
          <label for="company">Organization Name</label>
          <input id="company" name="company" placeholder="Example Inc." autocomplete="organization" required />
          <label for="recon-level">Recon Level</label>
          <select id="recon-level" name="reconLevel">
            <option value="safe-passive">Safe passive - no approval</option>
            <option value="passive-full-dns">Passive + full DNS - approval required</option>
            <option value="low-noise">Low-noise web checks - approval required</option>
            <option value="low-noise-full-dns">Low-noise + full DNS - approval required</option>
            <option value="third-party-intel">Third-party intel - approval required</option>
          </select>
          <div id="level-hint" class="hint">No target HTTP, minimal DNS, passive public sources only.</div>
          <button id="start-button" type="submit">Start recon</button>
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
      <h2>Approval Queue</h2>
      <p>Elevated recon levels pause here until an operator approves or rejects them.</p>
      <button id="refresh-approvals" class="secondary" type="button">Refresh approvals</button>
      <div id="approvals" class="approvals" aria-live="polite"></div>
    </section>

    <section>
      <h2>Recent Jobs</h2>
      <button id="refresh-jobs" class="secondary" type="button">Refresh</button>
      <div id="jobs" class="jobs" aria-live="polite"></div>
    </section>
  </main>
  <script>
    const orgHeaders = { "content-type": "application/json", "X-Org-Id": "default" };
    const reconLevelDescriptions = {
      "safe-passive": "No target HTTP, minimal DNS, passive public sources only.",
      "passive-full-dns": "Broader target DNS checks. Requires approval before queueing.",
      "low-noise": "Capped in-scope HEAD/GET checks with minimal DNS. Requires approval.",
      "low-noise-full-dns": "Capped web checks plus broader DNS. Requires approval.",
      "third-party-intel": "Uses approved passive third-party intel providers. Requires approval and executor API keys."
    };

    function setText(id, text) {
      document.getElementById(id).textContent = text;
    }

    function statusClass(status) {
      return "badge " + (
        status === "completed" ||
        status === "failed" ||
        status === "queued" ||
        status === "running" ||
        status === "processing_result" ||
        status === "pending" ||
        status === "approved" ||
        status === "rejected" ? status : ""
      );
    }

    function scoreBand(score) {
      if (typeof score !== "number") return "not available";
      if (score >= 90) return "strong";
      if (score >= 70) return "review";
      return "needs attention";
    }

    function addCard(container, label, value, note) {
      const card = document.createElement("div");
      card.className = label.includes("score") ? "score-card" : "ledger-card";
      const strong = document.createElement("strong");
      strong.textContent = value;
      const span = document.createElement("span");
      span.textContent = note || label;
      card.append(strong, span);
      container.append(card);
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
      const planMeta = document.createElement("div");
      planMeta.className = "meta";
      planMeta.textContent = "Mode: " + (job.mode || "passive") + " · DNS: " + (job.dnsPolicy || "minimal") + (job.enableThirdPartyIntel ? " · third-party intel" : "") + (job.workflowStatus ? " · workflow: " + job.workflowStatus : "");
      title.append(strong, meta, planMeta);
      const badge = document.createElement("span");
      badge.className = statusClass(job.status);
      badge.textContent = job.status || "unknown";
      header.append(title, badge);
      article.append(header);

      if (job.summary && Object.keys(job.summary).length) {
        const scores = document.createElement("div");
        scores.className = "score-row";
        const emailScore = job.summary.email_posture_score;
        const exposureScore = job.summary.exposure_score;
        addCard(scores, "email score", emailScore ?? "n/a", "Email score, higher is better · " + scoreBand(emailScore));
        addCard(scores, "exposure score", exposureScore ?? "n/a", "Exposure score, higher is better · " + scoreBand(exposureScore));
        article.append(scores);
      }

      if (job.ledgerTotals && Object.keys(job.ledgerTotals).length) {
        const ledger = document.createElement("div");
        ledger.className = "ledger-row";
        const counts = job.ledgerTotals.counts || {};
        addCard(ledger, "Target HTTP", counts.target_http || 0, "Target HTTP requests");
        addCard(ledger, "Target DNS", counts.target_dns || 0, "Target DNS queries");
        addCard(ledger, "Third-party source calls", counts.third_party_http || 0, "Passive source HTTP calls");
        article.append(ledger);
      }

      if (job.agentSummary) {
        const details = document.createElement("details");
        details.open = job.status === "completed";
        const label = document.createElement("summary");
        label.textContent = "SOC analyst notes";
        const summary = document.createElement("pre");
        summary.textContent = job.agentSummary;
        details.append(label, summary);
        article.append(details);
      }

      if (job.subdomainPhishingAnalysis && Object.keys(job.subdomainPhishingAnalysis).length) {
        const details = document.createElement("details");
        const label = document.createElement("summary");
        label.textContent = "Subdomain phishing-target analysis";
        const summary = document.createElement("pre");
        summary.textContent = JSON.stringify(job.subdomainPhishingAnalysis, null, 2);
        details.append(label, summary);
        article.append(details);
      }

      if (job.drift && Object.keys(job.drift).length) {
        const details = document.createElement("details");
        const label = document.createElement("summary");
        label.textContent = "Drift";
        const summary = document.createElement("pre");
        summary.textContent = JSON.stringify(job.drift, null, 2);
        details.append(label, summary);
        article.append(details);
      }

      if (Array.isArray(job.artifacts) && job.artifacts.length) {
        const details = document.createElement("details");
        const label = document.createElement("summary");
        label.textContent = "Artifacts (" + job.artifacts.length + ")";
        const list = document.createElement("ul");
        job.artifacts.forEach((artifact, index) => {
          const item = document.createElement("li");
          if (artifact.key) {
            const link = document.createElement("a");
            link.href = "/api/jobs/" + job.id + "/artifacts/" + index;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = artifact.key;
            item.append(link);
          } else {
            item.textContent = JSON.stringify(artifact);
          }
          list.append(item);
        });
        details.append(label, list);
        article.append(details);
      }

      if (job.error) {
        const error = document.createElement("div");
        error.className = "meta";
        error.textContent = "Error: " + job.error;
        article.append(error);
      }
      const actions = document.createElement("div");
      actions.className = "actions";
      const rerun = document.createElement("button");
      rerun.className = "secondary";
      rerun.type = "button";
      rerun.textContent = "Run again";
      rerun.addEventListener("click", async () => {
        rerun.disabled = true;
        rerun.textContent = "Queueing...";
        try {
          const response = await fetch("/api/jobs/" + job.id + "/rerun", { method: "POST", headers: orgHeaders });
          const payload = await response.json();
          if (!response.ok) throw new Error(payload.error || "rerun_failed");
          if (payload.approvalRequired) {
            alert("Approval request " + payload.approval.id + " created before rerun queueing.");
          }
          await loadApprovals();
          await loadJobs();
        } catch (error) {
          rerun.textContent = "Failed";
          alert("Run again failed: " + (error.message || String(error)));
        } finally {
          rerun.disabled = false;
          rerun.textContent = "Run again";
        }
      });
      actions.append(rerun);
      article.append(actions);
      return article;
    }

    function renderApproval(approval) {
      const article = document.createElement("article");
      article.className = "approval";
      const header = document.createElement("header");
      const title = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = approval.domain || "unknown domain";
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = "Approval " + approval.id + " · Plan " + approval.reconPlanId + " · " + (approval.company || "No organization") + " · " + (approval.createdAt || "");
      const plan = document.createElement("div");
      plan.className = "meta";
      plan.textContent = "Mode: " + approval.requestedMode + " · DNS: " + approval.requestedDnsPolicy + (approval.enableThirdPartyIntel ? " · third-party intel" : "");
      title.append(strong, meta, plan);
      const badge = document.createElement("span");
      badge.className = statusClass(approval.status);
      badge.textContent = approval.status || "unknown";
      header.append(title, badge);
      article.append(header);

      const reason = document.createElement("p");
      reason.className = "warning";
      reason.textContent = approval.reason || "Approval required for elevated recon.";
      article.append(reason);

      const sources = document.createElement("div");
      sources.className = "meta";
      sources.textContent = "Expected sources: " + (Array.isArray(approval.expectedSources) ? approval.expectedSources.join(", ") : "n/a");
      article.append(sources);

      if (approval.status === "pending") {
        const actions = document.createElement("div");
        actions.className = "actions";
        const approve = document.createElement("button");
        approve.type = "button";
        approve.textContent = "Approve and queue";
        approve.addEventListener("click", async () => {
          approve.disabled = true;
          approve.textContent = "Approving...";
          try {
            const approvalResponse = await fetch("/api/approvals/" + approval.id + "/approve", {
              method: "POST",
              headers: orgHeaders,
              body: JSON.stringify({ note: "Approved from dashboard." })
            });
            const approvalPayload = await approvalResponse.json();
            if (!approvalResponse.ok) throw new Error(approvalPayload.error || "approval_failed");
            await loadApprovals();
            await loadJobs();
          } catch (error) {
            alert("Approval failed: " + (error.message || String(error)));
          } finally {
            approve.disabled = false;
            approve.textContent = "Approve and queue";
          }
        });

        const reject = document.createElement("button");
        reject.className = "secondary";
        reject.type = "button";
        reject.textContent = "Reject";
        reject.addEventListener("click", async () => {
          reject.disabled = true;
          reject.textContent = "Rejecting...";
          try {
            const response = await fetch("/api/approvals/" + approval.id + "/reject", {
              method: "POST",
              headers: orgHeaders,
              body: JSON.stringify({ note: "Rejected from dashboard." })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || "reject_failed");
            await loadApprovals();
          } catch (error) {
            alert("Reject failed: " + (error.message || String(error)));
          } finally {
            reject.disabled = false;
            reject.textContent = "Reject";
          }
        });
        actions.append(approve, reject);
        article.append(actions);
      }
      return article;
    }

    async function loadApprovals() {
      const container = document.getElementById("approvals");
      container.textContent = "Loading approvals...";
      const response = await fetch("/api/approvals", { headers: { "X-Org-Id": "default" } });
      const approvals = await response.json();
      container.textContent = "";
      if (!Array.isArray(approvals) || approvals.length === 0) {
        container.textContent = "No approval requests.";
        return;
      }
      const pending = approvals.filter((approval) => approval.status === "pending");
      const visible = pending.length ? pending : approvals.slice(0, 5);
      for (const approval of visible) {
        container.append(renderApproval(approval));
      }
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
      setText("start-status", "Creating asset and recon plan...");
      try {
        const response = await fetch("/api/recon/start", {
          method: "POST",
          headers: orgHeaders,
          body: JSON.stringify({
            domain: document.getElementById("domain").value,
            company: document.getElementById("company").value,
            reconLevel: document.getElementById("recon-level").value,
          }),
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error || "request_failed");
        }
        if (payload.approvalRequired) {
          setText("start-status", "Approval request " + payload.approval.id + " created for " + payload.asset.domain + ".");
          await loadApprovals();
        } else {
          setText("start-status", "Started workflow " + payload.workflowId + " for " + payload.asset.domain + ".");
        }
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

    document.getElementById("recon-level").addEventListener("change", (event) => {
      setText("level-hint", reconLevelDescriptions[event.target.value] || reconLevelDescriptions["safe-passive"]);
    });
    document.getElementById("refresh-approvals").addEventListener("click", loadApprovals);
    document.getElementById("refresh-jobs").addEventListener("click", loadJobs);
    loadApprovals();
    loadJobs();
    setInterval(() => {
      loadApprovals();
      loadJobs();
    }, 15000);
  </script>
</body>
</html>`;
}
