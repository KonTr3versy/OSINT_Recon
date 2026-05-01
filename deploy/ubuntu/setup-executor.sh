#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/KonTr3versy/OSINT_Recon.git}"
APP_DIR="${APP_DIR:-/opt/osint-recon}"
DATA_DIR="${DATA_DIR:-/var/lib/osint-recon/output}"
ENV_FILE="${ENV_FILE:-/etc/osint-recon-worker.env}"
RUN_USER="${RUN_USER:-osintrecon}"

echo "[1/8] Updating apt packages"
sudo apt-get update

echo "[2/8] Installing system dependencies"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential \
  ca-certificates \
  curl \
  dnsutils \
  git \
  jq \
  python3 \
  python3-pip \
  python3-venv \
  unzip

echo "[3/8] Installing uv"
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
  echo "uv was installed but is not on PATH. Run: source \$HOME/.local/bin/env" >&2
  exit 1
fi
sudo install -m 0755 "$(command -v uv)" /usr/local/bin/uv
if command -v uvx >/dev/null 2>&1; then
  sudo install -m 0755 "$(command -v uvx)" /usr/local/bin/uvx
fi

echo "[4/8] Creating service user and directories"
if ! id "$RUN_USER" >/dev/null 2>&1; then
  sudo useradd --system --home /var/lib/osint-recon --shell /usr/sbin/nologin "$RUN_USER"
fi
sudo mkdir -p "$APP_DIR" "$DATA_DIR"
sudo chown -R "$RUN_USER:$RUN_USER" "$APP_DIR" /var/lib/osint-recon

echo "[5/8] Cloning or updating repo"
if [ ! -d "$APP_DIR/.git" ]; then
  sudo -u "$RUN_USER" env HOME=/var/lib/osint-recon git clone "$REPO_URL" "$APP_DIR"
else
  sudo -u "$RUN_USER" env HOME=/var/lib/osint-recon git -C "$APP_DIR" fetch --all --prune
  sudo -u "$RUN_USER" env HOME=/var/lib/osint-recon git -C "$APP_DIR" pull --ff-only
fi

echo "[6/8] Installing Python project dependencies"
cd "$APP_DIR"
sudo -u "$RUN_USER" env HOME=/var/lib/osint-recon /usr/local/bin/uv sync

echo "[7/8] Creating env template if missing"
if [ ! -f "$ENV_FILE" ]; then
  sudo tee "$ENV_FILE" >/dev/null <<'EOF'
CF_ACCOUNT_ID=d5a52343c81813cf8a6517d53a8964fc
CF_QUEUE_ID=213aef4a44c64819b3f64e7157e3d2c4
CF_CONTROL_PLANE_URL=https://osint-recon-agent-control-plane.mack4965.workers.dev
CF_CONTROL_PLANE_TOKEN=replace-me
CF_ACCESS_CLIENT_ID=replace-me
CF_ACCESS_CLIENT_SECRET=replace-me
CF_QUEUES_TOKEN=replace-me
CF_R2_BUCKET=osint-recon-artifacts
CF_R2_ACCESS_KEY_ID=replace-me
CF_R2_SECRET_ACCESS_KEY=replace-me
CF_ORG_ID=default
EOF
  sudo chmod 600 "$ENV_FILE"
  sudo chown root:root "$ENV_FILE"
fi

echo "[8/8] Verifying install"
sudo -u "$RUN_USER" env HOME=/var/lib/osint-recon /usr/local/bin/uv run osint-posture --help >/dev/null
python3 --version
/usr/local/bin/uv --version

echo
echo "Setup complete."
echo "Edit secrets: sudo nano $ENV_FILE"
echo "Smoke test:"
echo "  sudo bash -lc 'set -a; source $ENV_FILE; set +a; cd $APP_DIR; exec runuser -u $RUN_USER -- env HOME=/var/lib/osint-recon /usr/local/bin/uv run osint-posture cloudflare-worker --once --skip-r2 --out $DATA_DIR'"
