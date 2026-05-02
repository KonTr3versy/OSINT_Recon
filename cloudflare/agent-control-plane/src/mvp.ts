import { runReconModel } from "./ai";
import type { DnsPolicy, Env, ReconLevel, ReconMode } from "./types";

export interface ReconLevelConfig {
  id: ReconLevel;
  label: string;
  description: string;
  mode: ReconMode;
  dnsPolicy: DnsPolicy;
  enableThirdPartyIntel: boolean;
  budgets: Record<string, number>;
}

export const RECON_LEVELS: Record<ReconLevel, ReconLevelConfig> = {
  "safe-passive": {
    id: "safe-passive",
    label: "Safe passive",
    description: "No target HTTP, minimal DNS, passive public sources only.",
    mode: "passive",
    dnsPolicy: "minimal",
    enableThirdPartyIntel: false,
    budgets: {},
  },
  "passive-full-dns": {
    id: "passive-full-dns",
    label: "Passive + full DNS",
    description: "No target HTTP, broader target DNS checks, approval required.",
    mode: "passive",
    dnsPolicy: "full",
    enableThirdPartyIntel: false,
    budgets: {},
  },
  "low-noise": {
    id: "low-noise",
    label: "Low-noise web",
    description: "Capped in-scope HEAD/GET checks with minimal DNS, approval required.",
    mode: "low-noise",
    dnsPolicy: "minimal",
    enableThirdPartyIntel: false,
    budgets: {},
  },
  "low-noise-full-dns": {
    id: "low-noise-full-dns",
    label: "Low-noise + full DNS",
    description: "Capped in-scope web checks plus broader DNS, approval required.",
    mode: "low-noise",
    dnsPolicy: "full",
    enableThirdPartyIntel: false,
    budgets: {},
  },
  "low-noise-verified-surface": {
    id: "low-noise-verified-surface",
    label: "Low-noise verified surface",
    description: "Approval-gated external-surface verification with full DNS, HEAD-only HTTP metadata, and well-known checks.",
    mode: "low-noise",
    dnsPolicy: "full",
    enableThirdPartyIntel: false,
    budgets: {
      max_target_http_requests_total: 30,
      max_target_http_per_host: 2,
      max_target_http_per_minute: 10,
      max_target_dns_queries: 100,
    },
  },
  "third-party-intel": {
    id: "third-party-intel",
    label: "Third-party intel",
    description: "Passive/minimal run with approved external intel providers, approval required.",
    mode: "passive",
    dnsPolicy: "minimal",
    enableThirdPartyIntel: true,
    budgets: {},
  },
};

export function resolveReconLevel(value: unknown): ReconLevelConfig {
  if (typeof value === "string" && value in RECON_LEVELS) {
    return RECON_LEVELS[value as ReconLevel];
  }
  return RECON_LEVELS["safe-passive"];
}

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
    enableThirdPartyIntel: Boolean(payload.enableThirdPartyIntel),
    workflowId: stringValue(result.workflowId) || stringValue(payload.workflowId),
    workflowStatus: stringValue(result.workflowStatus),
    reconLevel: stringValue(result.reconLevel) || stringValue(payload.reconLevel),
    createdAt: stringValue(row.created_at),
    updatedAt: stringValue(row.updated_at),
    artifactPrefix: stringValue(result.artifactPrefix),
    artifacts: Array.isArray(result.artifacts) ? result.artifacts : [],
    summary: isRecord(result.summary) ? result.summary : {},
    findings: isRecord(result.findings) ? result.findings : {},
    moduleStatuses: Array.isArray(result.moduleStatuses) ? result.moduleStatuses : [],
    ledgerTotals: isRecord(result.ledgerTotals) ? result.ledgerTotals : {},
    drift: isRecord(result.drift) ? result.drift : {},
    subdomainInventory: isRecord(result.subdomainInventory) ? result.subdomainInventory : subdomainInventory(result.findings),
    subdomainPhishingAnalysis: isRecord(result.subdomainPhishingAnalysis) ? result.subdomainPhishingAnalysis : {},
    verifiedSurface: isRecord(result.verifiedSurface) ? result.verifiedSurface : {},
    wellKnownMetadata: isRecord(result.wellKnownMetadata) ? result.wellKnownMetadata : {},
    technologyFingerprints: isRecord(result.technologyFingerprints) ? result.technologyFingerprints : {},
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
        subdomainInventory: subdomainInventory(body.findings),
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

export function subdomainInventory(findings: unknown): Record<string, unknown> {
  if (!isRecord(findings)) {
    return {};
  }
  if (isRecord(findings.subdomain_inventory)) {
    return findings.subdomain_inventory;
  }
  if (isRecord(findings.evidence) && isRecord(findings.evidence.passive_subdomains)) {
    return findings.evidence.passive_subdomains;
  }
  return {};
}

export function subdomainList(findings: unknown): string[] {
  const inventory = subdomainInventory(findings);
  const subdomains = inventory.subdomains;
  if (!Array.isArray(subdomains)) {
    return [];
  }
  return [...new Set(subdomains.map((item) => stringValue(item)).filter(Boolean))].sort();
}

export function computeRunDrift(
  previousResult: Record<string, unknown> | null,
  current: {
    summary?: unknown;
    findings?: unknown;
    moduleStatuses?: unknown[];
    ledgerTotals?: unknown;
  },
): Record<string, unknown> {
  if (!previousResult || Object.keys(previousResult).length === 0) {
    return { newRun: true, previousJobId: null };
  }
  const previousFindings = previousResult.findings;
  const currentFindings = current.findings;
  return {
    newRun: false,
    previousJobId: previousResult.jobId ?? null,
    scoreChanges: compareScores(previousResult.summary, current.summary),
    newFindings: diffStrings(backlogTitles(previousFindings), backlogTitles(currentFindings)).added,
    remediatedFindings: diffStrings(backlogTitles(previousFindings), backlogTitles(currentFindings)).removed,
    moduleStatusChanges: compareModuleStatuses(previousResult.moduleStatuses, current.moduleStatuses),
    ledgerCountChanges: compareCounts(previousResult.ledgerTotals, current.ledgerTotals),
    subdomainChanges: diffStrings(subdomainList(previousFindings), subdomainList(currentFindings)),
  };
}

export function buildPhishingAnalysisMessages(
  orgId: string,
  jobId: number,
  body: {
    summary?: unknown;
    findings?: unknown;
    moduleStatuses?: unknown[];
    ledgerTotals?: unknown;
  },
): Array<{ role: string; content: string }> {
  return [
    {
      role: "system",
      content: [
        "You are OSINT_Recon's defensive phishing-risk analyst.",
        "Classify discovered subdomains by defensive attractiveness to threat actors.",
        "Use only evidence provided by deterministic recon artifacts.",
        "Only analyze exact hostnames listed in `subdomainInventory.subdomains`; never invent, infer, or substitute hostnames.",
        "If no subdomains are listed, return an empty `notableTargets` array.",
        "Allowed categories: identity/login, VPN/remote access, mail, payroll/HR, admin, dev/test, customer portal, brand/payment, low-signal.",
        "For each notable subdomain, provide category, rationale, evidenceRef, and defensive recommendations.",
        "Do not generate phishing copy, lure text, lookalike domains, payloads, credential collection steps, social engineering instructions, or attack steps.",
        "Return strict JSON with keys: overview, notableTargets, monitoringRecommendations, safetyNote.",
      ].join(" "),
    },
    {
      role: "user",
      content: JSON.stringify({
        orgId,
        jobId,
        summary: body.summary ?? {},
        subdomainInventory: subdomainInventory(body.findings),
        moduleStatuses: body.moduleStatuses ?? [],
        ledgerTotals: body.ledgerTotals ?? {},
      }),
    },
  ];
}

export function sanitizeSubdomainPhishingAnalysis(
  rawAnalysis: unknown,
  body: { findings?: unknown },
  context: { orgId: string; jobId: number },
): Record<string, unknown> {
  const subdomains = subdomainList(body.findings);
  const allowed = new Set(subdomains);
  const raw = isRecord(rawAnalysis) ? rawAnalysis : {};
  const rawTargets = Array.isArray(raw.notableTargets) ? raw.notableTargets : [];
  const sanitizedTargets = rawTargets
    .filter(isRecord)
    .map((target) => sanitizePhishingTarget(target, allowed))
    .filter(isRecord);
  const deterministicTargets = subdomains
    .map((subdomain) => deterministicPhishingTarget(subdomain))
    .filter((target) => target.category !== "low-signal");
  const notableTargets = sanitizedTargets.length ? sanitizedTargets : deterministicTargets;
  const rawRecommendations = Array.isArray(raw.monitoringRecommendations)
    ? raw.monitoringRecommendations.map((item) => stringValue(item)).filter(Boolean).slice(0, 8)
    : [];

  return {
    overview: subdomains.length
      ? `Classified ${subdomains.length} discovered subdomain${subdomains.length === 1 ? "" : "s"} from deterministic passive evidence. ${notableTargets.length} stood out for defensive monitoring based on hostname role indicators.`
      : "No discovered subdomains were available for phishing-target analysis.",
    orgId: context.orgId,
    jobId: context.jobId,
    notableTargets,
    monitoringRecommendations: rawRecommendations.length ? rawRecommendations : defaultMonitoringRecommendations(notableTargets),
    safetyNote: "Defensive classification only. This analysis uses observed subdomains and does not include lure text, lookalike domains, payloads, credential collection, or attack instructions.",
    evidenceScope: {
      source: "findings.evidence.passive_subdomains.subdomains",
      subdomainCount: subdomains.length,
      modelTargetsFiltered: rawTargets.length - sanitizedTargets.length,
      fallbackUsed: sanitizedTargets.length === 0 && deterministicTargets.length > 0,
    },
  };
}

export function parseModelJsonObject(content: string): Record<string, unknown> {
  const trimmed = content.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)?.[1]?.trim();
  const embedded = trimmed.match(/\{[\s\S]*\}/)?.[0]?.trim();
  const candidate = fenced || embedded || trimmed;
  try {
    const parsed = JSON.parse(candidate) as unknown;
    return isRecord(parsed) ? parsed : { overview: content };
  } catch {
    return { overview: content };
  }
}

export function buildEnhancedReports(input: {
  domain: string;
  company?: string | null;
  summary?: unknown;
  drift?: unknown;
  phishingAnalysis?: unknown;
  subdomainInventory?: unknown;
  artifacts?: unknown[];
}): { markdown: string; html: string } {
  const title = `# Agent-Enhanced OSINT Report`;
  const subdomains = Array.isArray((input.subdomainInventory as { subdomains?: unknown[] } | undefined)?.subdomains)
    ? ((input.subdomainInventory as { subdomains?: unknown[] }).subdomains ?? []).map((item) => stringValue(item))
    : [];
  const phishing = isRecord(input.phishingAnalysis) ? input.phishingAnalysis : {};
  const drift = isRecord(input.drift) ? input.drift : {};
  const markdown = [
    title,
    "",
    `Domain: ${input.domain}`,
    `Organization: ${input.company || "n/a"}`,
    "",
    "## Defensive Phishing-Target Analysis",
    "",
    stringValue(phishing.overview) || "No AI analysis was generated.",
    "",
    "## Notable Targets",
    "",
    renderMarkdownList(phishing.notableTargets),
    "",
    "## Monitoring Recommendations",
    "",
    renderMarkdownList(phishing.monitoringRecommendations),
    "",
    "## Drift",
    "",
    "```json",
    JSON.stringify(drift, null, 2),
    "```",
    "",
    "## Discovered Subdomains",
    "",
    ...(subdomains.length ? subdomains.map((item) => `- ${item}`) : ["- No subdomains discovered."]),
    "",
    "## Safety Note",
    "",
    stringValue(phishing.safetyNote) || "Analysis is defensive only and does not include phishing instructions.",
  ].join("\n");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Agent-Enhanced OSINT Report</title><style>body{font-family:Arial,sans-serif;line-height:1.45;max-width:1040px;margin:0 auto;padding:32px;color:#172026}pre{background:#f6f8f9;padding:12px;overflow:auto}li{margin:.25rem 0}h1,h2{line-height:1.2}</style></head><body>${markdownToSimpleHtml(markdown)}</body></html>`;
  return { markdown, html };
}

function sanitizePhishingTarget(target: Record<string, unknown>, allowed: Set<string>): Record<string, unknown> | null {
  const subdomain = stringValue(target.subdomain).toLowerCase();
  if (!allowed.has(subdomain)) {
    return null;
  }
  const deterministic = deterministicPhishingTarget(subdomain);
  const category = allowedPhishingCategories.has(stringValue(target.category))
    ? stringValue(target.category)
    : deterministic.category;
  const recommendations = Array.isArray(target.defensiveRecommendations)
    ? target.defensiveRecommendations.map((item) => stringValue(item)).filter(Boolean).slice(0, 4)
    : deterministic.defensiveRecommendations;
  return {
    subdomain,
    category,
    rationale: stringValue(target.rationale) || deterministic.rationale,
    evidenceRef: "findings.evidence.passive_subdomains.subdomains",
    defensiveRecommendations: recommendations.length ? recommendations : deterministic.defensiveRecommendations,
  };
}

const allowedPhishingCategories = new Set([
  "identity/login",
  "VPN/remote access",
  "mail",
  "payroll/HR",
  "admin",
  "dev/test",
  "customer portal",
  "brand/payment",
  "low-signal",
]);

function deterministicPhishingTarget(subdomain: string): {
  subdomain: string;
  category: string;
  rationale: string;
  evidenceRef: string;
  defensiveRecommendations: string[];
} {
  const labels = subdomain.split(".");
  const joined = labels.join(" ");
  const category = classifySubdomainRole(joined);
  return {
    subdomain,
    category,
    rationale: rationaleForCategory(category, subdomain),
    evidenceRef: "findings.evidence.passive_subdomains.subdomains",
    defensiveRecommendations: recommendationsForCategory(category),
  };
}

function classifySubdomainRole(text: string): string {
  if (/\b(vpn|remote|ra|citrix|rdp|globalprotect|anyconnect|forti|ssl-vpn|sslvpn|zpa|ztna)\b/i.test(text)) {
    return "VPN/remote access";
  }
  if (/\b(login|sso|idp|identity|auth|okta|adfs|signin|account|accounts)\b/i.test(text)) {
    return "identity/login";
  }
  if (/\b(mail|smtp|imap|pop|owa|webmail|mx|autodiscover|exchange)\b/i.test(text)) {
    return "mail";
  }
  if (/\b(hr|payroll|benefits|workday|people|employee|employees)\b/i.test(text)) {
    return "payroll/HR";
  }
  if (/\b(admin|manage|management|console|dashboard|panel|internal)\b/i.test(text)) {
    return "admin";
  }
  if (/\b(dev|test|stage|staging|qa|uat|sandbox|preview|demo)\b/i.test(text)) {
    return "dev/test";
  }
  if (/\b(portal|customer|client|support|help|service|services)\b/i.test(text)) {
    return "customer portal";
  }
  if (/\b(pay|payment|billing|invoice|checkout|brand|www|shop|store)\b/i.test(text)) {
    return "brand/payment";
  }
  return "low-signal";
}

function rationaleForCategory(category: string, subdomain: string): string {
  switch (category) {
    case "VPN/remote access":
      return `${subdomain} appears to identify remote-access infrastructure, which is commonly monitored defensively because account takeover attempts often concentrate there.`;
    case "identity/login":
      return `${subdomain} appears related to authentication or identity workflows, making it important for brand monitoring and login anomaly review.`;
    case "mail":
      return `${subdomain} appears related to mail infrastructure, so it is relevant to email authentication, spoofing resistance, and mailbox access monitoring.`;
    case "payroll/HR":
      return `${subdomain} appears related to employee or HR workflows, which can be attractive for impersonation and access-pretext attempts.`;
    case "admin":
      return `${subdomain} appears to expose an administrative or management role signal and should be reviewed for visibility and access controls.`;
    case "dev/test":
      return `${subdomain} appears to identify non-production infrastructure, which should be monitored for stale exposure and weaker controls.`;
    case "customer portal":
      return `${subdomain} appears related to customer or support access and is useful for brand-abuse and account-abuse monitoring.`;
    case "brand/payment":
      return `${subdomain} appears related to public brand, commerce, or payment workflows and is useful for spoofing and abuse monitoring.`;
    default:
      return `${subdomain} does not strongly indicate a sensitive workflow from its hostname alone.`;
  }
}

function recommendationsForCategory(category: string): string[] {
  switch (category) {
    case "VPN/remote access":
      return ["Verify MFA coverage and conditional access.", "Monitor failed logins, impossible travel, and unusual source networks."];
    case "identity/login":
      return ["Monitor authentication anomalies and suspicious redirects.", "Keep brand and certificate transparency monitoring tuned for this hostname."];
    case "mail":
      return ["Review SPF, DKIM, and DMARC alignment.", "Monitor mailbox login anomalies and suspicious forwarding rules."];
    case "payroll/HR":
      return ["Review access controls and MFA coverage.", "Monitor for impersonation reports using this workflow name."];
    case "admin":
      return ["Confirm administrative access is restricted.", "Monitor for unexpected public exposure and login anomalies."];
    case "dev/test":
      return ["Confirm non-production systems do not expose sensitive data.", "Retire stale records and monitor certificate issuance."];
    case "customer portal":
      return ["Monitor account abuse and brand impersonation reports.", "Review login protections and customer support escalation paths."];
    case "brand/payment":
      return ["Monitor lookalike abuse through defensive brand-protection channels.", "Review payment and account-security telemetry for anomalies."];
    default:
      return ["Keep in passive inventory and monitor for ownership drift or unexpected certificate changes."];
  }
}

function defaultMonitoringRecommendations(targets: unknown[]): string[] {
  if (!targets.length) {
    return ["Keep passive subdomain inventory updated and compare changes between runs."];
  }
  return [
    "Prioritize monitoring for identity, remote-access, mail, admin, and HR-labeled hostnames.",
    "Compare new subdomains against expected business systems before taking remediation action.",
    "Use certificate transparency and DNS drift to detect unexpected additions.",
  ];
}

function renderMarkdownList(value: unknown): string {
  if (!Array.isArray(value) || value.length === 0) {
    return "- No notable items.";
  }
  return value.map((item) => `- ${typeof item === "string" ? item : JSON.stringify(item)}`).join("\n");
}

function markdownToSimpleHtml(markdown: string): string {
  return markdown
    .split("\n")
    .map((line) => {
      if (line.startsWith("# ")) return `<h1>${escapeHtml(line.slice(2))}</h1>`;
      if (line.startsWith("## ")) return `<h2>${escapeHtml(line.slice(3))}</h2>`;
      if (line.startsWith("- ")) return `<li>${escapeHtml(line.slice(2))}</li>`;
      if (line.startsWith("```")) return "";
      if (!line.trim()) return "";
      return `<p>${escapeHtml(line)}</p>`;
    })
    .join("\n");
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function backlogTitles(findings: unknown): string[] {
  if (!isRecord(findings) || !Array.isArray(findings.prioritized_backlog)) {
    return [];
  }
  return findings.prioritized_backlog.map((item) => isRecord(item) ? stringValue(item.title) : "").filter(Boolean).sort();
}

function compareScores(previous: unknown, current: unknown): Record<string, number> {
  const changes: Record<string, number> = {};
  if (!isRecord(previous) || !isRecord(current)) {
    return changes;
  }
  for (const key of ["email_posture_score", "exposure_score"]) {
    const oldScore = Number(previous[key]);
    const newScore = Number(current[key]);
    if (Number.isFinite(oldScore) && Number.isFinite(newScore) && oldScore !== newScore) {
      changes[key] = newScore - oldScore;
    }
  }
  return changes;
}

function compareModuleStatuses(previous: unknown, current: unknown): unknown[] {
  if (!Array.isArray(previous) || !Array.isArray(current)) {
    return [];
  }
  const previousMap = new Map(previous.filter(isRecord).map((item) => [stringValue(item.module), stringValue(item.status)]));
  return current
    .filter(isRecord)
    .map((item) => ({ module: stringValue(item.module), previous: previousMap.get(stringValue(item.module)) || "missing", current: stringValue(item.status) }))
    .filter((item) => item.previous !== item.current);
}

function compareCounts(previous: unknown, current: unknown): Record<string, number> {
  const previousCounts = isRecord(previous) && isRecord(previous.counts) ? previous.counts : {};
  const currentCounts = isRecord(current) && isRecord(current.counts) ? current.counts : {};
  const keys = new Set([...Object.keys(previousCounts), ...Object.keys(currentCounts)]);
  const changes: Record<string, number> = {};
  for (const key of keys) {
    const oldValue = Number(previousCounts[key] ?? 0);
    const newValue = Number(currentCounts[key] ?? 0);
    if (oldValue !== newValue) {
      changes[key] = newValue - oldValue;
    }
  }
  return changes;
}

function diffStrings(previous: string[], current: string[]): { added: string[]; removed: string[]; unchanged: string[] } {
  const previousSet = new Set(previous);
  const currentSet = new Set(current);
  return {
    added: current.filter((item) => !previousSet.has(item)),
    removed: previous.filter((item) => !currentSet.has(item)),
    unchanged: current.filter((item) => previousSet.has(item)),
  };
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
