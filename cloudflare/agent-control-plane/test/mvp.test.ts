import { describe, expect, it, vi } from "vitest";
import {
  buildAnalystMessages,
  buildEnhancedReports,
  buildPhishingAnalysisMessages,
  computeRunDrift,
  jobSummary,
  normalizeDomain,
  parseModelJsonObject,
  resolveReconLevel,
  sanitizeSubdomainPhishingAnalysis,
  subdomainList,
  summarizeJobResult,
} from "../src/mvp";
import type { Env } from "../src/types";

describe("MVP one-click recon helpers", () => {
  it("normalizes domains entered by an operator", () => {
    expect(normalizeDomain("https://Example.COM/path")).toBe("example.com");
    expect(normalizeDomain("*.Login.Example.COM")).toBe("login.example.com");
  });

  it("maps dashboard recon levels to deterministic executor settings", () => {
    expect(resolveReconLevel("safe-passive")).toMatchObject({
      mode: "passive",
      dnsPolicy: "minimal",
      enableThirdPartyIntel: false,
    });
    expect(resolveReconLevel("low-noise-full-dns")).toMatchObject({
      mode: "low-noise",
      dnsPolicy: "full",
      enableThirdPartyIntel: false,
    });
    expect(resolveReconLevel("third-party-intel")).toMatchObject({
      mode: "passive",
      dnsPolicy: "minimal",
      enableThirdPartyIntel: true,
    });
    expect(resolveReconLevel("unknown")).toMatchObject({ id: "safe-passive" });
  });

  it("projects stored job results into dashboard-friendly JSON", () => {
    const summary = jobSummary({
      id: 4,
      org_id: "default",
      asset_id: 2,
      recon_plan_id: 3,
      status: "completed",
      domain: "example.com",
      company: "Example",
      created_at: "2026-01-01",
      updated_at: "2026-01-01",
      payload_json: JSON.stringify({ mode: "passive", dnsPolicy: "minimal" }),
      result_json: JSON.stringify({
        artifactPrefix: "example.com/20260101_000000",
        artifacts: [{ key: "runs/example.com/report.html" }],
        summary: { email_posture_score: 90 },
        findings: { prioritized_backlog: [{ title: "Enforce DMARC" }] },
        moduleStatuses: [{ module: "dns_mail_profile", status: "ok" }],
        ledgerTotals: { counts: { target_http: 0 } },
        drift: { newRun: true },
        subdomainPhishingAnalysis: { overview: "Login portal is attractive." },
        agentSummary: "Looks good.",
      }),
    });

    expect(summary.status).toBe("completed");
    expect(summary.mode).toBe("passive");
    expect(summary.dnsPolicy).toBe("minimal");
    expect(summary.enableThirdPartyIntel).toBe(false);
    expect(summary.artifactPrefix).toBe("example.com/20260101_000000");
    expect(summary.artifacts).toEqual([{ key: "runs/example.com/report.html" }]);
    expect(summary.findings).toEqual({ prioritized_backlog: [{ title: "Enforce DMARC" }] });
    expect(summary.moduleStatuses).toEqual([{ module: "dns_mail_profile", status: "ok" }]);
    expect(summary.ledgerTotals).toEqual({ counts: { target_http: 0 } });
    expect(summary.drift).toEqual({ newRun: true });
    expect(summary.subdomainPhishingAnalysis).toEqual({ overview: "Login portal is attractive." });
    expect(summary.agentSummary).toBe("Looks good.");
  });

  it("extracts subdomains and computes artifact-level drift", () => {
    const previous = {
      jobId: 1,
      summary: { email_posture_score: 100, exposure_score: 100 },
      findings: {
        prioritized_backlog: [{ title: "Old finding" }],
        subdomain_inventory: { subdomains: ["old.example.com", "login.example.com"] },
      },
      moduleStatuses: [{ module: "dns_mail_profile", status: "ok" }],
      ledgerTotals: { counts: { target_dns: 3 } },
    };
    const current = {
      summary: { email_posture_score: 85, exposure_score: 100 },
      findings: {
        prioritized_backlog: [{ title: "New finding" }],
        subdomain_inventory: { subdomains: ["login.example.com", "vpn.example.com"] },
      },
      moduleStatuses: [{ module: "dns_mail_profile", status: "error" }],
      ledgerTotals: { counts: { target_dns: 5 } },
    };

    const drift = computeRunDrift(previous, current);

    expect(subdomainList(current.findings)).toEqual(["login.example.com", "vpn.example.com"]);
    expect(drift.scoreChanges).toEqual({ email_posture_score: -15 });
    expect(drift.newFindings).toEqual(["New finding"]);
    expect(drift.remediatedFindings).toEqual(["Old finding"]);
    expect(drift.subdomainChanges).toMatchObject({ added: ["vpn.example.com"], removed: ["old.example.com"] });
    expect(drift.ledgerCountChanges).toEqual({ target_dns: 2 });
  });

  it("builds a defensive phishing analysis prompt with explicit prohibitions", () => {
    const messages = buildPhishingAnalysisMessages("default", 10, {
      findings: { subdomain_inventory: { subdomains: ["login.example.com"] } },
    });

    expect(messages[0].content).toContain("defensive phishing-risk analyst");
    expect(messages[0].content).toContain("Do not generate phishing copy");
    expect(messages[0].content).toContain("lookalike domains");
    expect(messages[0].content).toContain("credential collection steps");
    expect(JSON.parse(messages[1].content).subdomainInventory.subdomains).toEqual(["login.example.com"]);
  });

  it("parses model JSON and builds enhanced reports", () => {
    const parsed = parseModelJsonObject('```json\n{"overview":"ok","notableTargets":[]}\n```');
    const report = buildEnhancedReports({
      domain: "example.com",
      phishingAnalysis: parsed,
      drift: { newRun: true },
      subdomainInventory: { subdomains: ["login.example.com"] },
    });

    expect(parsed.overview).toBe("ok");
    expect(report.markdown).toContain("Agent-Enhanced OSINT Report");
    expect(report.markdown).toContain("login.example.com");
    expect(report.html).toContain("Agent-Enhanced OSINT Report");
  });

  it("filters invented phishing-analysis hostnames and falls back to observed evidence", () => {
    const raw = parseModelJsonObject(`Here is the classification:
{
  "overview": "vpn.default.org is risky",
  "notableTargets": [
    {"subdomain":"vpn.default.org","category":"VPN/remote access","rationale":"invented","evidenceRef":"target_dns"},
    {"subdomain":"login.example.com","category":"identity/login","rationale":"observed login role","evidenceRef":"target_dns"}
  ],
  "monitoringRecommendations": ["Review observed authentication endpoints."]
}`);
    const sanitized = sanitizeSubdomainPhishingAnalysis(
      raw,
      { findings: { subdomain_inventory: { subdomains: ["login.example.com", "vpn.example.com"] } } },
      { orgId: "default", jobId: 99 },
    );

    expect(JSON.stringify(sanitized)).not.toContain("vpn.default.org");
    expect(sanitized.overview).toContain("2 discovered subdomains");
    expect(sanitized.notableTargets).toEqual([
      expect.objectContaining({
        subdomain: "login.example.com",
        category: "identity/login",
        evidenceRef: "findings.evidence.passive_subdomains.subdomains",
      }),
    ]);
    expect(sanitized.evidenceScope).toMatchObject({ modelTargetsFiltered: 1, fallbackUsed: false });
  });

  it("builds score-aware SOC analyst messages with ledger semantics", () => {
    const messages = buildAnalystMessages("default", 12, {
      summary: { email_posture_score: 100, exposure_score: 100 },
      ledgerTotals: { counts: { target_http: 0, target_dns: 6, third_party_http: 13 } },
      findings: {
        scoring_rubric: {
          email_posture: { applied_rules: [] },
          exposure: { applied_rules: [{ id: "exposure.test", label: "Example", deduction: 5 }] },
        },
        prioritized_backlog: [{ title: "Review SPF", priority: "Medium" }],
        evidence: { dns_mail_profile: { spf_raw: "v=spf1 -all" } },
      },
      moduleStatuses: [{ module: "passive_subdomains", status: "ok" }],
    });

    expect(messages[0].content).toContain("Higher posture scores are better");
    expect(messages[0].content).toContain("third_party_http");
    expect(messages[0].content).toContain("not target exposure");
    const payload = JSON.parse(messages[1].content);
    expect(payload.scoreInterpretation).toContain("Higher scores are better");
    expect(payload.appliedScoringRules[0].category).toBe("exposure");
    expect(payload.prioritizedBacklog[0].title).toBe("Review SPF");
    expect(payload.ledgerSemantics.third_party_http).toContain("not target exposure");
  });

  it("generates an analyst summary without executing recon", async () => {
    const env = {
      AI_MODEL: "@cf/test/model",
      AI: { run: vi.fn(async () => ({ response: "Prioritize DMARC enforcement." })) },
    } as unknown as Env;

    const result = await summarizeJobResult(env, "default", 9, {
      status: "completed",
      summary: { email_posture_score: 85 },
      ledgerTotals: { counts: { target_http: 0 } },
      artifacts: [{ key: "runs/example/summary.md" }],
    });

    expect(result.status).toBe("generated");
    expect(result.summary).toContain("DMARC");
    expect(env.AI.run).toHaveBeenCalledOnce();
  });

  it("keeps completed deterministic results when the analyst model fails", async () => {
    const env = {
      AI_MODEL: "@cf/test/model",
      AI: { run: vi.fn(async () => {
        throw new Error("model unavailable");
      }) },
    } as unknown as Env;

    const result = await summarizeJobResult(env, "default", 9, {
      status: "completed",
      summary: { email_posture_score: 85 },
    });

    expect(result.status).toBe("unavailable");
    expect(result.summary).toBe("AI summary unavailable.");
    expect(result.meta?.error).toContain("model unavailable");
  });
});
