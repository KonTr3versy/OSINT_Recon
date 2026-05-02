# VPS Executor Deployment

This deploys the private Python executor for the Cloudflare control plane. The VPS stays outbound-only: it polls Cloudflare Queues, runs the deterministic `osint_posture` pipeline, uploads artifacts to R2, and posts results back to the Worker with `CF_CONTROL_PLANE_TOKEN`.

## 1. Bootstrap Ubuntu

Use Ubuntu 24.04 LTS, SSH key auth, and no public application ports. From the VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/KonTr3versy/OSINT_Recon/main/deploy/ubuntu/setup-executor.sh -o setup-executor.sh
chmod +x setup-executor.sh
./setup-executor.sh
```

For a branch or fork:

```bash
REPO_URL="https://github.com/KonTr3versy/OSINT_Recon.git" ./setup-executor.sh
```

## 2. Configure Secrets

Edit the root-owned environment file:

```bash
sudo nano /etc/osint-recon-worker.env
```

Required values:

```bash
CF_ACCOUNT_ID=d5a52343c81813cf8a6517d53a8964fc
CF_QUEUE_ID=213aef4a44c64819b3f64e7157e3d2c4
CF_CONTROL_PLANE_URL=https://osint-recon-agent-control-plane.mack4965.workers.dev
CF_CONTROL_PLANE_TOKEN=<same value as Worker CONTROL_PLANE_TOKEN secret>
CF_ACCESS_CLIENT_ID=<Cloudflare Access service token client id>
CF_ACCESS_CLIENT_SECRET=<Cloudflare Access service token client secret>
CF_QUEUES_TOKEN=<Cloudflare Queues read/write API token>
CF_R2_BUCKET=osint-recon-artifacts
CF_R2_ACCESS_KEY_ID=<R2 S3 access key id>
CF_R2_SECRET_ACCESS_KEY=<R2 S3 secret access key>
CF_ORG_ID=default
```

Keep the file owned by root and unreadable by normal users:

```bash
sudo chown root:root /etc/osint-recon-worker.env
sudo chmod 600 /etc/osint-recon-worker.env
```

## 3. Install Optional Recon Tools

The `low-noise-verified-surface` tier can use optional passive adapters for `subfinder` and `amass`. Install or refresh those tools with:

```bash
sudo /opt/osint-recon/deploy/ubuntu/install-recon-tools.sh
```

If `amass` cannot be installed, the executor still runs and records the adapter as skipped. `subfinder` should be present for the best passive subdomain enrichment.

## 4. Smoke Test Queue and Callback

Queue a passive/minimal plan from the Worker dashboard console, then run:

```bash
sudo bash -lc '
  set -a
  source /etc/osint-recon-worker.env
  set +a
  cd /opt/osint-recon
  exec runuser -u osintrecon -- env HOME=/var/lib/osint-recon /usr/local/bin/uv run osint-posture cloudflare-worker --once --skip-r2 --out /var/lib/osint-recon/output
'
```

Expected result:

```json
{
  "processed": 1,
  "succeeded": 1,
  "failed": 0
}
```

## 5. Smoke Test R2 Upload

Queue another passive/minimal plan, then run without `--skip-r2`:

```bash
sudo bash -lc '
  set -a
  source /etc/osint-recon-worker.env
  set +a
  cd /opt/osint-recon
  exec runuser -u osintrecon -- env HOME=/var/lib/osint-recon /usr/local/bin/uv run osint-posture cloudflare-worker --once --out /var/lib/osint-recon/output
'
```

Confirm R2 contains objects under `runs/`, and D1 has a completed `recon_jobs` row plus a `run_summaries` row.

## 6. Install systemd Service

```bash
sudo cp /opt/osint-recon/deploy/systemd/osint-recon-worker.service /etc/systemd/system/osint-recon-worker.service
sudo systemctl daemon-reload
sudo systemctl enable osint-recon-worker
sudo systemctl start osint-recon-worker
```

Check status and logs:

```bash
sudo systemctl status osint-recon-worker
sudo journalctl -u osint-recon-worker -f
```

Restart test:

```bash
sudo systemctl restart osint-recon-worker
sudo systemctl status osint-recon-worker
```

## Rollback

Stop the executor without touching Cloudflare state:

```bash
sudo systemctl disable --now osint-recon-worker
```

Jobs already queued remain in Cloudflare Queues until processed or expired by queue policy. To revert the VPS code:

```bash
cd /opt/osint-recon
sudo -u osintrecon env HOME=/var/lib/osint-recon git fetch --all --prune
sudo -u osintrecon env HOME=/var/lib/osint-recon git checkout main
sudo -u osintrecon env HOME=/var/lib/osint-recon git pull --ff-only
sudo -u osintrecon env HOME=/var/lib/osint-recon /usr/local/bin/uv sync
sudo systemctl restart osint-recon-worker
```
