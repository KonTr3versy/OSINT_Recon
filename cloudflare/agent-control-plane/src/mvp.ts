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
    const result = await runReconModel(
      env,
      [
        {
          role: "system",
          content: [
            "You are OSINT_Recon's defensive analyst.",
            "Summarize deterministic recon results for remediation.",
            "Do not suggest phishing, exploitation, brute force, crawling, credential collection, or new network activity.",
            "Include high-level posture, top findings, evidence references, remediation priorities, and a safety note.",
          ].join(" "),
        },
        {
          role: "user",
          content: JSON.stringify({
            jobId,
            orgId,
            summary: body.summary ?? {},
            ledgerTotals: body.ledgerTotals ?? {},
            artifactPrefix: body.artifactPrefix ?? null,
            artifacts: body.artifacts ?? [],
          }),
        },
      ],
      { agent: "ReconAgent", action: "summarize_run", jobId: String(jobId) },
    );
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
