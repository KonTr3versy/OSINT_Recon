# OSINT_Recon Agent Operating Guide

## Mission

OSINT_Recon is a defensive, remediation-focused recon platform. It must never generate phishing, credential harvesting, social engineering, exploitation, brute-force, or offensive workflows.

## Architecture

- `osint_posture/`: Python recon executor and local/internal platform APIs.
- `osint_posture/modules/`: deterministic recon modules.
- `osint_posture/utils/network.py`: non-bypassable network policy and ledger controls.
- `osint_posture/platform/`: FastAPI platform, Cloudflare queue bridge, R2 uploader, and Python executor worker.
- `cloudflare/agent-control-plane/`: Cloudflare Workers/Agents SDK control plane.
- `tests/`: Python regression and platform tests.

## Safety Boundary

- The LLM plans, explains, summarizes, asks for approval, and queues approved work.
- The LLM does not perform target DNS, target HTTP, third-party intel queries, or artifact mutation directly.
- The Python `osint_posture` pipeline is the only recon executor.
- All target network activity must pass through `NetworkPolicy`.
- All outbound network activity must be recorded in `NetworkLedger`.

## Cloudflare Deployment Model

- Cloudflare Access protects the Worker route.
- Workers AI is the default model runtime.
- AI Gateway can be configured with `AI_GATEWAY_URL` and `AI_GATEWAY_TOKEN`.
- D1 stores assets, plans, approvals, jobs, run summaries, and audit events.
- R2 stores generated run artifacts.
- Cloudflare Queues hands approved jobs to the private Python executor.
- The Python executor posts results back with `CONTROL_PLANE_TOKEN`.

## Common Commands

Python:

```bash
PYTHONPATH=. uv run pytest
uv run osint-posture run --domain example.com --out ./output
uv run osint-posture cloudflare-worker --once --skip-r2 --out ./output
```

Cloudflare:

```bash
cd cloudflare/agent-control-plane
npm install
npm run typecheck
npm test
npm run db:migrate:local
npm run dev
```

Deployment:

```bash
npx wrangler d1 create osint-recon-control-plane
npx wrangler r2 bucket create osint-recon-artifacts
npx wrangler queues create osint-recon-jobs
npx wrangler queues consumer http add osint-recon-jobs
npm run db:migrate:remote
npm run deploy
```

VPS executor:

```bash
./deploy/ubuntu/setup-executor.sh
sudo bash -lc 'set -a; source /etc/osint-recon-worker.env; set +a; cd /opt/osint-recon; exec runuser -u osintrecon -- env HOME=/var/lib/osint-recon /usr/local/bin/uv run osint-posture cloudflare-worker --once --skip-r2 --out /var/lib/osint-recon/output'
sudo systemctl status osint-recon-worker
sudo journalctl -u osint-recon-worker -f
```

## Required Secrets

- `CONTROL_PLANE_TOKEN`: shared callback token for Python worker result posts.
- `AI_GATEWAY_TOKEN`: optional token if using an authenticated AI Gateway endpoint.
- Python executor environment:
  - `CF_ACCOUNT_ID`
  - `CF_QUEUE_ID`
  - `CF_QUEUES_TOKEN`
  - `CF_CONTROL_PLANE_URL`
  - `CF_R2_BUCKET`
  - `CF_R2_ACCESS_KEY_ID`
  - `CF_R2_SECRET_ACCESS_KEY`
  - `CF_CONTROL_PLANE_TOKEN`

## Change Rules

- Preserve CLI compatibility unless explicitly changing a public interface.
- Prefer adding tests for policy, approval, queue, and artifact behavior.
- Do not loosen network policy defaults.
- Do not add target-touching behavior to Cloudflare Workers or LLM prompts.
- Keep generated artifacts, local DBs, `.wrangler/`, and `node_modules/` out of git.
