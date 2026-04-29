import { describe, expect, it } from "vitest";
import { canQueuePlan, proposeReconPlan } from "../src/policy";
import type { AssetRecord } from "../src/types";

const asset: AssetRecord = {
  id: 1,
  org_id: "default",
  domain: "example.com",
  company: "Example",
  allowed_mode: "passive",
  dns_policy_ceiling: "minimal",
  third_party_intel_allowed: 0,
  default_schedule: "0 9 * * 1",
};

describe("Cloudflare recon policy", () => {
  it("allows passive/minimal plans without approval", () => {
    const plan = proposeReconPlan(asset);

    expect(plan.requiresApproval).toBe(false);
    expect(plan.expectedSources).toContain("dns_mail_profile");
  });

  it("requires approval for low-noise or full DNS plans", () => {
    expect(proposeReconPlan(asset, "low-noise").requiresApproval).toBe(true);
    expect(proposeReconPlan(asset, "passive", "full").requiresApproval).toBe(true);
  });

  it("does not queue approval-gated plans before approval", () => {
    expect(canQueuePlan(true, "pending")).toBe(false);
    expect(canQueuePlan(true, "approved")).toBe(true);
    expect(canQueuePlan(false, "approved")).toBe(true);
  });
});
