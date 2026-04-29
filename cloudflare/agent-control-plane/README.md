# OSINT Recon Cloudflare Agent Control Plane

This Worker makes Cloudflare a core part of the application:

- `ReconAgent` is a stateful Cloudflare Agent for chat, planning, scheduling, and approval coordination.
- D1 stores assets, recon plans, approvals, job metadata, run summaries, and audit events.
- Cloudflare Queues hands approved jobs to the internal Python `osint_posture` worker.
- R2 is reserved for generated reports and raw artifacts.
- Workers AI gives the agent an LLM for planning and explanation while the Python worker remains the only recon executor.

## Local Setup

```bash
cd cloudflare/agent-control-plane
npm install
npm run db:migrate:local
npm run dev
```

The Worker runs locally at `http://localhost:8787`.

## First Calls

Create an asset:

```bash
curl -X POST http://localhost:8787/api/assets \
  -H 'content-type: application/json' \
  -H 'X-Org-Id: default' \
  -d '{"domain":"example.com","company":"Example"}'
```

Create a passive/minimal recon plan:

```bash
curl -X POST http://localhost:8787/api/recon-plans \
  -H 'content-type: application/json' \
  -H 'X-Org-Id: default' \
  -d '{"assetId":1}'
```

Queue an approved plan:

```bash
curl -X POST http://localhost:8787/api/recon-plans/1/queue \
  -H 'X-Org-Id: default'
```

Chat with the stateful org agent:

```bash
curl -X POST http://localhost:8787/api/agents/default/chat \
  -H 'content-type: application/json' \
  -d '{"message":"What should we run this week?"}'
```

Schedule the agent to create recurring passive recon work:

```bash
curl -X POST http://localhost:8787/api/agents/default/schedule \
  -H 'content-type: application/json' \
  -d '{"assetId":1,"cron":"0 9 * * 1"}'
```

## Deploy Setup

Create Cloudflare resources, then update `wrangler.toml` with your real D1 database id:

```bash
npx wrangler d1 create osint-recon-control-plane
npx wrangler r2 bucket create osint-recon-artifacts
npx wrangler queues create osint-recon-jobs
npx wrangler queues consumer http add osint-recon-jobs
npm run db:migrate:remote
npm run deploy
```

The internal Python worker should consume `ReconJobPayload` messages from the `osint-recon-jobs` queue and report results back to:

```text
POST /api/jobs/{cloudflareJobId}/result
```

## Python Queue Worker

The Python package includes a pull consumer for the Cloudflare queue:

```bash
export CF_ACCOUNT_ID="<account-id>"
export CF_QUEUE_ID="<queue-id>"
export CF_QUEUES_TOKEN="<queues-read-write-token>"
export CF_CONTROL_PLANE_URL="https://<worker-name>.<subdomain>.workers.dev"
export CF_R2_BUCKET="osint-recon-artifacts"
export CF_R2_ACCESS_KEY_ID="<r2-access-key-id>"
export CF_R2_SECRET_ACCESS_KEY="<r2-secret-access-key>"

osint-posture cloudflare-worker --out ./output
```

Use `--once` to process a single batch and exit. Use `--skip-r2` for local smoke tests where you want to verify queue pull, recon execution, and result callbacks without uploading artifacts.

Required Cloudflare setup:
- Enable HTTP pull for `osint-recon-jobs`.
- Create a Cloudflare API token with Account Queues read/write permissions for `CF_QUEUES_TOKEN`.
- Create R2 S3 credentials with object read/write permissions for `CF_R2_ACCESS_KEY_ID` and `CF_R2_SECRET_ACCESS_KEY`.

## Safety Boundary

The Cloudflare Agent can plan, summarize, request approval, schedule work, and enqueue approved jobs. It does not perform target DNS, target HTTP, or paid third-party intel directly. Those actions remain inside the Python `osint_posture` pipeline with its existing `NetworkPolicy` and `NetworkLedger`.
