#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
GO_BIN="${GO_BIN:-/usr/local/bin/go}"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

echo "[1/5] Installing base packages"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates \
  curl \
  dnsutils \
  git \
  golang-go \
  jq

mkdir -p "$INSTALL_DIR"

install_go_tool() {
  local name="$1"
  local module="$2"
  local tmp
  tmp="$(mktemp -d)"
  echo "Installing $name from $module"
  if GOBIN="$tmp" "$GO_BIN" install "$module"; then
    install -m 0755 "$tmp/$name" "$INSTALL_DIR/$name"
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

echo "[2/5] Installing subfinder passive adapter"
install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[3/5] Installing amass passive adapter"
if ! install_go_tool amass github.com/owasp-amass/amass/v5/cmd/amass@latest; then
  echo "amass v5 install failed; trying amass v4"
  if ! install_go_tool amass github.com/owasp-amass/amass/v4/.../amass@latest; then
    echo "Go install for amass failed; trying apt package if available"
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y amass; then
      echo "WARNING: amass could not be installed. The executor will skip the amass adapter." >&2
    fi
  fi
fi

echo "[4/5] Verifying tools"
if command -v subfinder >/dev/null 2>&1; then
  subfinder -version || true
else
  echo "ERROR: subfinder is not on PATH" >&2
  exit 1
fi

if command -v amass >/dev/null 2>&1; then
  amass -version || true
else
  echo "WARNING: amass is not on PATH; optional adapter will be skipped" >&2
fi

echo "[5/5] Checking executor service user can see tools"
if id osintrecon >/dev/null 2>&1; then
  runuser -u osintrecon -- env PATH="$INSTALL_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" subfinder -version >/dev/null || {
    echo "ERROR: osintrecon cannot execute subfinder" >&2
    exit 1
  }
  if command -v amass >/dev/null 2>&1; then
    runuser -u osintrecon -- env PATH="$INSTALL_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" amass -version >/dev/null || true
  fi
fi

echo
echo "Recon tool installation complete."
echo "The low-noise verified-surface executor will use:"
echo "  $(command -v subfinder)"
if command -v amass >/dev/null 2>&1; then
  echo "  $(command -v amass)"
else
  echo "  amass: not installed; adapter will be skipped"
fi
