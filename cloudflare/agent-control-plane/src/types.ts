export type ReconMode = "passive" | "low-noise";
export type DnsPolicy = "none" | "minimal" | "full";
export type ApprovalStatus = "approved" | "pending" | "rejected";
export type ReconLevel =
  | "safe-passive"
  | "passive-full-dns"
  | "low-noise"
  | "low-noise-full-dns"
  | "third-party-intel";

export interface Env {
  AI: Ai;
  DB: D1Database;
  ARTIFACTS: R2Bucket;
  RECON_JOBS: Queue<ReconJobPayload>;
  RECON_RUN_WORKFLOW: Workflow<ReconWorkflowParams>;
  OSINT_AGENT: DurableObjectNamespace;
  ACCESS_REQUIRED?: string;
  CF_ACCESS_AUD?: string;
  CONTROL_PLANE_TOKEN?: string;
  AI_MODEL?: string;
  AI_GATEWAY_URL?: string;
  AI_GATEWAY_TOKEN?: string;
}

export interface ReconWorkflowParams {
  orgId: string;
  planId: number;
  workflowId: string;
  requestedBy?: Record<string, unknown>;
}

export interface AssetRecord {
  id: number;
  org_id: string;
  domain: string;
  company: string | null;
  allowed_mode: ReconMode;
  dns_policy_ceiling: DnsPolicy;
  third_party_intel_allowed: number;
  default_schedule: string;
}

export interface ReconPlanProposal {
  assetId: number;
  requestedMode: ReconMode;
  requestedDnsPolicy: DnsPolicy;
  enableThirdPartyIntel: boolean;
  budgets: Record<string, number>;
  expectedSources: string[];
  requiresApproval: boolean;
  rationale: string;
}

export interface ReconJobPayload {
  cloudflareJobId: number;
  orgId: string;
  assetId: number;
  reconPlanId: number;
  domain: string;
  company?: string | null;
  mode: ReconMode;
  dnsPolicy: DnsPolicy;
  enableThirdPartyIntel: boolean;
  budgets: Record<string, number>;
  workflowId?: string;
}

export interface AgentState {
  messages: Array<{ role: "user" | "assistant" | "system"; content: string; ts: string }>;
  lastPlan?: ReconPlanProposal;
  lastJobId?: number;
}
