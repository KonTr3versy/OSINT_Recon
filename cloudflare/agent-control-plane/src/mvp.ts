import { runReconModel } from "./ai";
import type { Env } from "./types";

export function normalizeDomain(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/^\*\./, "");
}

export function jobSummary(row: Record<string, unknown>): Record<string, unknown> {
  const result = parseJsonRecord(row.result_json);
  const payload = parseJsonRecord(row.payload_json);
  return {
    id: numberValue(row.id),
    orgId: stringValue(row.org_id),
    assetId: numberValue(row.asset_id),
    reconPlanId: numberValue(row.recon_plan_id),
    status: stringValue(row.status),
    domain: stringValue(row.domain) || stringValue(payload.domain),
    company: stringValue(row.company) || stringValue(payload.company),
    mode: stringValue(payload.mode),
    dnsPolicy: stringValue(payload.dnsPolicy),
    createdAt: stringValue(row.created_at),
    updatedAt: stringValue(row.updated_at),
    artifactPrefix: stringValue(result.artifactPrefix),
    artifacts: Array.isArray(result.artifacts) ? result.artifacts : [],
    summary: isRecord(result.summary) ? result.summary : {},
    findings: isRecord(result.findings) ? result.findings : {},
    moduleStatuses: Array.isArray(result.moduleStatuses) ? result.moduleStatuses : [],
    ledgerTotals: isRecord(result.ledgerTotals) ? result.ledgerTotals : {},
    agentSummary: stringValue(result.agentSummary),
    agentSummaryStatus: stringValue(result.agentSummaryStatus),
    error: stringValue(result.error),
  };
}

export async function summarizeJobResult(
  env: Env,
  orgId: string,
  jobId: number,
  body: {
    status: string;
    artifactPrefix?: string;
    artifacts?: unknown[];
    ledgerTotals?: unknown;
    summary?: unknown;
    findings?: unknown;
    moduleStatuses?: unknown[];
    agentSummary?: string;
  },
): Promise<{ status: "generated" | "provided" | "unavailable" | "skipped"; summary?: string; meta?: Record<string, unknown> }> {
  if (body.agentSummary) {
    return { status: "provided", summary: body.agentSummary };
  }
  if (body.status !== "completed") {
    return { status: "skipped" };
  }
  try {
    const result = await runReconModel(env, buildAnalystMessages(orgId, jobId, body), {
      agent: "ReconAgent",
      action: "summarize_run",
      jobId: String(jobId),
    });
    return {
      status: "generated",
      summary: result.content,
      meta: {
        model: result.model,
        provider: result.provider,
        gatewayUsed: result.gatewayUsed,
        jobId,
      },
    };
  } catch (error) {
    return {
      status: "unavailable",
      summary: "AI summary unavailable.",
      meta: {
        jobId,
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

export function buildAnalystMessages(
  orgId: string,
  jobId: number,
  body: {
    artifactPrefix?: string;
    artifacts?: unknown[];
    ledgerTotals?: unknown;
    summary?: unknown;
    findings?: unknown;
    moduleStatuses?: unknown[];
  },
): Array<{ role: string; content: string }> {
  return [
    {
      role: "system",
      content: [
        "You are OSINT_Recon's defensive SOC analyst.",
        "Write concise SOC analyst notes for remediation using only the deterministic results provided.",
        "Higher posture scores are better: 100 means no score deductions for that category; lower scores mean more remediation need.",
        "`target_http` counts target-origin HTTP requests; `target_http=0` means no target HTTP occurred.",
        "`target_dns` counts DNS queries for the target domain under policy.",
        "`third_party_http` counts passive data-source calls such as CT, GitHub, or other allowed providers; it is not target exposure.",
        "Do not claim high risk, unauthorized activity, sensitive exposure, or attacks unless applied scoring rules or backlog evidence support it.",
        "Do not suggest phishing, exploitation, brute force, crawling, credential collection, or new network activity.",
        "Use sections: Overview, Evidence-backed observations, Remediation priorities, Module caveats, Safety/noise notes.",
      ].join(" "),
    },
    {
      role: "user",
      content: JSON.stringify({
        jobId,
        orgId,
        scoreInterpretation: "Higher scores are better; 100 means no score-impacting findings in that category.",
        summary: body.summary ?? {},
        appliedScoringRules: appliedScoringRules(body.findings),
        prioritizedBacklog: prioritizedBacklog(body.findings),
        evidence: evidenceSnapshot(body.findings),
        moduleStatuses: body.moduleStatuses ?? [],
        ledgerTotals: body.ledgerTotals ?? {},
        ledgerSemantics: {
          target_http: "Target-origin HTTP requests. Zero means no target HTTP occurred.",
          target_dns: "Target DNS queries allowed by DNS policy.",
          third_party_http: "Passive source/provider HTTP calls, not target exposure.",
        },
        artifactPrefix: body.artifactPrefix ?? null,
        artifacts: body.artifacts ?? [],
      }),
    },
  ];
}

function appliedScoringRules(findings: unknown): unknown[] {
  if (!isRecord(findings) || !isRecord(findings.scoring_rubric)) {
    return [];
  }
  const rules: unknown[] = [];
  for (const [category, rubric] of Object.entries(findings.scoring_rubric)) {
    if (!isRecord(rubric) || !Array.isArray(rubric.applied_rules)) {
      continue;
    }
    for (const rule of rubric.applied_rules) {
      rules.push({ category, ...(isRecord(rule) ? rule : { rule }) });
    }
  }
  return rules;
}

function prioritizedBacklog(findings: unknown): unknown[] {
  if (!isRecord(findings) || !Array.isArray(findings.prioritized_backlog)) {
    return [];
  }
  return findings.prioritized_backlog.slice(0, 10);
}

function evidenceSnapshot(findings: unknown): unknown {
  if (!isRecord(findings) || !isRecord(findings.evidence)) {
    return {};
  }
  return findings.evidence;
}

export function parseJsonRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "string" || !value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function numberValue(value: unknown): number {
  return typeof value === "number" ? value : Number(value);
}
