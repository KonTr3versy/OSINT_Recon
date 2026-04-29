# osint-posture

Defensive OSINT posture assessment for a public-facing domain and email security. This tool is strictly for **remediation-focused recon**. It does **not** include phishing execution, lure generation, pretexting, credential harvesting, or instructions for social engineering.

## Install

Requirements: Python 3.11+

Using `uv`:

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

## How to run

Passive run (default, no target HTTP):

```bash
osint-posture run --domain example.com --out ./output
```

Low-noise run (strictly bounded target HTTP checks):

```bash
osint-posture run --domain example.com --mode low-noise --dns-policy minimal
```

Backward-compatible aliases (deprecated):

```bash
osint-posture run --domain example.com --mode enhanced
osint-posture run --domain example.com --mode active
```

Generate reports from an existing run:

```bash
osint-posture report --input ./output/example.com/<timestamp>
```

Validate findings JSON:

```bash
osint-posture validate --input ./output/example.com/<timestamp>/findings.json
```

Run the internal team platform API and dashboard:

```bash
osint-posture serve --host 127.0.0.1 --port 8000
```

Process one queued platform run:

```bash
osint-posture worker-once --out ./output
```

Execute one Cloudflare Queue job payload with the local Python recon worker:

```bash
osint-posture cloudflare-job --input ./job.json --out ./output
```

Run the continuous Cloudflare Queue worker with R2 artifact upload:

```bash
export CF_ACCOUNT_ID="<account-id>"
export CF_QUEUE_ID="<queue-id>"
export CF_QUEUES_TOKEN="<queues-read-write-token>"
export CF_CONTROL_PLANE_URL="https://<worker-name>.<subdomain>.workers.dev"
export CF_CONTROL_PLANE_TOKEN="<same-value-as-worker-secret>"
export CF_R2_BUCKET="osint-recon-artifacts"
export CF_R2_ACCESS_KEY_ID="<r2-access-key-id>"
export CF_R2_SECRET_ACCESS_KEY="<r2-secret-access-key>"

osint-posture cloudflare-worker --out ./output
```

For a one-shot local smoke test:

```bash
osint-posture cloudflare-worker --once --skip-r2 --out ./output
```

Reports generated:
- `artifacts/summary.md`
- `artifacts/remediation_backlog.csv`
- `artifacts/report.html`

Raw run artifacts:
- `raw/network_ledger.json` (auditable outbound network ledger)
- `raw/run_manifest.json` (sanitized config, budgets, and ledger totals)

## Noise Contract

- `--mode passive` (default): no target HTTP requests. Third-party OSINT calls allowed.
- `--mode low-noise`: allows only tiny, policy-enforced target HTTP checks (HEAD by default), with strict budgets.
- `--dns-policy none`: no DNS queries.
- `--dns-policy minimal` (default): only apex TXT/MX + `_dmarc` TXT.
- `--dns-policy full`: A/AAAA/NS/MX/TXT and DKIM safelist checks in low-noise mode.

HTTP and DNS activity is policy-enforced and logged to `raw/network_ledger.json`.

## Agentic team platform

The preferred agentic architecture uses Cloudflare as the stateful AI control plane and this Python package as the trusted recon executor.

Cloudflare control plane:
- `cloudflare/agent-control-plane` contains a Workers + Agents SDK app.
- The `ReconAgent` owns stateful planning, chat, scheduling, approval coordination, and LLM-backed explanations.
- D1 stores assets, recon plans, approval requests, queued job metadata, run summaries, and audit events.
- Cloudflare Queues hands approved recon jobs to the internal Python worker.
- R2 is the intended storage layer for generated reports, CSV backlogs, raw ledgers, and manifests.
- Cloudflare Access should protect deployed Worker routes. The Worker enforces Access headers by default and uses `CONTROL_PLANE_TOKEN` for Python result callbacks.
- Workers AI is the default inference runtime. Set `AI_GATEWAY_URL` to route Agent model calls through Cloudflare AI Gateway.

Python executor:
- `osint-posture cloudflare-job` accepts the Cloudflare queue payload shape and executes the existing deterministic pipeline.
- `osint-posture cloudflare-worker` pulls jobs from Cloudflare Queues, executes recon, uploads the run directory to R2, and posts the result back to the Cloudflare control plane.
- The LLM never performs target DNS, target HTTP, or paid third-party intel directly.
- Network activity still passes through `NetworkPolicy` and is recorded in `NetworkLedger`.

Run the Cloudflare control plane locally:

```bash
cd cloudflare/agent-control-plane
npm install
npm run db:migrate:local
npm run dev
```

Deploy Cloudflare resources:

```bash
npx wrangler d1 create osint-recon-control-plane
npx wrangler r2 bucket create osint-recon-artifacts
npx wrangler queues create osint-recon-jobs
npx wrangler queues consumer http add osint-recon-jobs
npx wrangler secret put CONTROL_PLANE_TOKEN
npm run db:migrate:remote
npm run deploy
```

The local FastAPI platform also wraps the deterministic recon pipeline in an approval-gated web control plane for internal development and fallback deployments.

V1 capabilities:
- Manual asset inventory with allowed mode, DNS policy ceiling, third-party intel allowance, and default schedule.
- Local RBAC users seeded for development: `admin@example.com`, `analyst@example.com`, `approver@example.com`, and `viewer@example.com`. API requests can select a user with the `X-User-Email` header.
- Agent plan proposal for scheduled recon runs. Low-noise target contact, full DNS policy, and third-party intel require approval before execution.
- Queue-backed run execution through `worker-once`, with module status, findings, backlog items, artifacts, network ledger totals, and audit events persisted.
- A compact dashboard at `/` plus JSON APIs for assets, recon plans, approvals, runs, artifacts, and backlog.

Default persistence is SQLite at `./osint_platform.db` for local use. Set `OSINT_POSTURE_DATABASE_URL` to a PostgreSQL SQLAlchemy URL for internal server deployment.

## Data sources and limitations

- DNS: `dnspython` with explicit policy (`none` / `minimal` / `full`).
- Certificate Transparency: `crt.sh` JSON endpoint for passive subdomain discovery.
- Passive user discovery: GitHub user search API using company/domain query hints (third-party only; validate association).
- Optional third-party intel: Shodan and Censys only when explicitly enabled and API keys provided.
- Web signals: passive mode infers from DNS/subdomains only; low-noise mode performs a small bounded set of `HEAD` checks.
- Documents: low-noise heuristics with metadata-only checks.

Limitations:
- No brute-force or high-volume crawling.
- No exploitation, port scanning, or offensive workflows.
- Third-party intel is best-effort and may be rate-limited or skipped if not configured.

## Defensive intent

This tool is designed solely for defensive assessment and remediation. It does not support phishing, social engineering, or offensive action. Output is meant to help improve organizational security posture.
