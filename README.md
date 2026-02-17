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

## Data sources and limitations

- DNS: `dnspython` with explicit policy (`none` / `minimal` / `full`).
- Certificate Transparency: `crt.sh` JSON endpoint for passive subdomain discovery.
- Optional third-party intel: Shodan and Censys only when explicitly enabled and API keys provided.
- Web signals: passive mode infers from DNS/subdomains only; low-noise mode performs a small bounded set of `HEAD` checks.
- Documents: low-noise heuristics with metadata-only checks.

Limitations:
- No brute-force or high-volume crawling.
- No exploitation, port scanning, or offensive workflows.
- Third-party intel is best-effort and may be rate-limited or skipped if not configured.

## Defensive intent

This tool is designed solely for defensive assessment and remediation. It does not support phishing, social engineering, or offensive action. Output is meant to help improve organizational security posture.
