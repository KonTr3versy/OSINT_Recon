import { describe, expect, it, vi } from "vitest";
import { buildAnalystMessages, jobSummary, normalizeDomain, summarizeJobResult } from "../src/mvp";
import type { Env } from "../src/types";

describe("MVP one-click recon helpers", () => {
  it("normalizes domains entered by an operator", () => {
    expect(normalizeDomain("https://Example.COM/path")).toBe("example.com");
    expect(normalizeDomain("*.Login.Example.COM")).toBe("login.example.com");
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
        agentSummary: "Looks good.",
      }),
    });

    expect(summary.status).toBe("completed");
    expect(summary.artifactPrefix).toBe("example.com/20260101_000000");
    expect(summary.artifacts).toEqual([{ key: "runs/example.com/report.html" }]);
    expect(summary.findings).toEqual({ prioritized_backlog: [{ title: "Enforce DMARC" }] });
    expect(summary.moduleStatuses).toEqual([{ module: "dns_mail_profile", status: "ok" }]);
    expect(summary.ledgerTotals).toEqual({ counts: { target_http: 0 } });
    expect(summary.agentSummary).toBe("Looks good.");
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
