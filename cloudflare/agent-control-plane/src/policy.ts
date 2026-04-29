import type { AssetRecord, DnsPolicy, ReconMode, ReconPlanProposal } from "./types";

const MODE_RANK: Record<ReconMode, number> = {
  passive: 0,
  "low-noise": 1,
};

const DNS_RANK: Record<DnsPolicy, number> = {
  none: 0,
  minimal: 1,
  full: 2,
};

export const DEFAULT_BUDGETS = {
  max_target_http_requests_total: 12,
  max_target_http_per_host: 3,
  max_target_http_per_minute: 12,
  max_target_dns_queries: 25,
};

export function proposeReconPlan(
  asset: AssetRecord,
  requestedMode: ReconMode = "passive",
  requestedDnsPolicy: DnsPolicy = "minimal",
  enableThirdPartyIntel = false,
  budgets: Record<string, number> = {},
): ReconPlanProposal {
  const resolvedBudgets = { ...DEFAULT_BUDGETS, ...budgets };
  const requiresApproval =
    requestedMode === "low-noise" ||
    requestedDnsPolicy === "full" ||
    enableThirdPartyIntel ||
    MODE_RANK[requestedMode] > MODE_RANK[asset.allowed_mode] ||
    DNS_RANK[requestedDnsPolicy] > DNS_RANK[asset.dns_policy_ceiling] ||
    (enableThirdPartyIntel && asset.third_party_intel_allowed !== 1);

  const expectedSources = [
    "dns_mail_profile",
    "passive_subdomains",
    "passive_users",
    "web_signals",
  ];
  if (enableThirdPartyIntel) {
    expectedSources.push("third_party_intel");
  }
  if (requestedMode === "low-noise") {
    expectedSources.push("doc_signals");
  }

  return {
    assetId: asset.id,
    requestedMode,
    requestedDnsPolicy,
    enableThirdPartyIntel,
    budgets: resolvedBudgets,
    expectedSources,
    requiresApproval,
    rationale:
      "Cloudflare agent proposed a scheduled recon run. Approval is required for low-noise target contact, full DNS, or third-party intel.",
  };
}

export function canQueuePlan(requiresApproval: boolean, approvalStatus: string): boolean {
  return !requiresApproval || approvalStatus === "approved";
}
