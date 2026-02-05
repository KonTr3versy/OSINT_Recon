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

Passive run (default):

```bash
osint-posture run --domain example.com --out ./output
```

Enhanced run (safe, limited requests):

```bash
osint-posture run --domain example.com --mode enhanced --max-requests-per-minute 60
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

## Data sources and limitations

- DNS: `A/AAAA`, `NS`, `MX`, `TXT` using `dnspython`.
- Certificate Transparency: `crt.sh` JSON endpoint for passive subdomain discovery.
- Optional third-party intel: Shodan and Censys only when explicitly enabled and API keys provided.
- Web signals: passive mode avoids crawling and only infers from DNS/subdomains. Enhanced mode makes a **small capped** set of `HEAD/GET` requests.
- Documents: lightweight heuristics with size checks and metadata-only extraction.

Limitations:
- No brute-force or high-volume crawling.
- DKIM selectors are only checked from a small safe list and only in enhanced mode.
- Third-party intel is best-effort and may be rate-limited or skipped if not configured.

## Defensive intent

This tool is designed solely for defensive assessment and remediation. It does not support phishing, social engineering, or offensive action. Output is meant to help improve organizational security posture.
