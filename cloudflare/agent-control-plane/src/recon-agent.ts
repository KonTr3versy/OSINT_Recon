import { Agent } from "agents";
import { proposeReconPlan } from "./policy";
import type { AgentState, AssetRecord, Env, ReconJobPayload } from "./types";

export class ReconAgent extends Agent<Env, AgentState> {
  initialState: AgentState = {
    messages: [],
  };

  async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname.endsWith("/chat")) {
      const body = (await request.json()) as { message?: string };
      return Response.json(await this.chat(body.message ?? ""));
    }
    if (request.method === "POST" && url.pathname.endsWith("/schedule")) {
      const body = (await request.json()) as { assetId: number; cron?: string };
      const id = await this.schedule(body.cron ?? "0 9 * * 1", "scheduledRecon", {
        assetId: body.assetId,
      });
      return Response.json({ scheduled: true, id });
    }
    return Response.json({ ok: true, state: this.state });
  }

  async scheduledRecon(payload: { assetId: number }) {
    const asset = await this.loadAsset(payload.assetId);
    if (!asset) {
      await this.audit("unknown", "agent.schedule.asset_missing", "asset", payload.assetId, {});
      return;
    }
    const proposal = proposeReconPlan(asset);
    const planId = await this.persistPlan(asset.org_id, proposal);
    if (proposal.requiresApproval) {
      await this.requestApproval(asset.org_id, planId, proposal.rationale);
      return;
    }
    await this.queueReconJob(asset, planId, proposal);
  }

  private async chat(message: string) {
    const system = [
      "You are OSINT_Recon's defensive recon coordinator.",
      "You may plan, explain, summarize, and ask for approval.",
      "You must never perform target recon directly.",
      "Deterministic Python workers execute approved DNS/HTTP/third-party tools.",
    ].join(" ");
    const messages = [
      { role: "system", content: system },
      ...this.state.messages.map((item) => ({ role: item.role, content: item.content })),
      { role: "user", content: message },
    ];
    const response = await this.env.AI.run("@cf/meta/llama-3.1-8b-instruct", { messages });
    const content = String((response as { response?: string }).response ?? "");
    this.setState({
      ...this.state,
      messages: [
        ...this.state.messages,
        { role: "user" as const, content: message, ts: new Date().toISOString() },
        { role: "assistant" as const, content, ts: new Date().toISOString() },
      ].slice(-40),
    });
    return { response: content };
  }

  private async loadAsset(assetId: number): Promise<AssetRecord | null> {
    const result = await this.env.DB.prepare("SELECT * FROM assets WHERE id = ?").bind(assetId).first<AssetRecord>();
    return result ?? null;
  }

  private async persistPlan(orgId: string, proposal: ReturnType<typeof proposeReconPlan>): Promise<number> {
    const result = await this.env.DB.prepare(
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
    if (!result) {
      throw new Error("Failed to persist recon plan");
    }
    await this.audit(orgId, "agent.plan.proposed", "recon_plan", result.id, proposal);
    return result.id;
  }

  private async requestApproval(orgId: string, planId: number, reason: string) {
    await this.env.DB.prepare(
      "INSERT INTO approval_requests (org_id, recon_plan_id, status, reason) VALUES (?, ?, 'pending', ?)",
    )
      .bind(orgId, planId, reason)
      .run();
    await this.audit(orgId, "agent.approval.requested", "recon_plan", planId, { reason });
  }

  private async queueReconJob(
    asset: AssetRecord,
    planId: number,
    proposal: ReturnType<typeof proposeReconPlan>,
  ): Promise<number> {
    const payload: Omit<ReconJobPayload, "cloudflareJobId"> = {
      orgId: asset.org_id,
      assetId: asset.id,
      reconPlanId: planId,
      domain: asset.domain,
      company: asset.company,
      mode: proposal.requestedMode,
      dnsPolicy: proposal.requestedDnsPolicy,
      enableThirdPartyIntel: proposal.enableThirdPartyIntel,
      budgets: proposal.budgets,
    };
    const inserted = await this.env.DB.prepare(
      "INSERT INTO recon_jobs (org_id, asset_id, recon_plan_id, status, payload_json) VALUES (?, ?, ?, 'queued', ?) RETURNING id",
    )
      .bind(asset.org_id, asset.id, planId, JSON.stringify(payload))
      .first<{ id: number }>();
    if (!inserted) {
      throw new Error("Failed to create recon job");
    }
    const queuePayload = { ...payload, cloudflareJobId: inserted.id };
    await this.env.RECON_JOBS.send(queuePayload);
    this.setState({ ...this.state, lastPlan: proposal, lastJobId: inserted.id });
    await this.audit(asset.org_id, "agent.job.queued", "recon_job", inserted.id, queuePayload);
    return inserted.id;
  }

  private async audit(orgId: string, action: string, targetType: string, targetId: number | null, payload: unknown) {
    await this.env.DB.prepare(
      "INSERT INTO audit_events (org_id, action, target_type, target_id, payload_json) VALUES (?, ?, ?, ?, ?)",
    )
      .bind(orgId, action, targetType, targetId, JSON.stringify(payload ?? {}))
      .run();
  }
}
