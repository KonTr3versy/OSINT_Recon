from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import typer

from .models.config import CacheMode, DnsPolicy, Mode
from .pipeline.service import create_run_config, execute_run
from .platform.cloudflare_bridge import CloudflareReconJob, execute_cloudflare_job
from .platform.db import Database, seed_defaults
from .platform.worker import process_next_run
from .reporting.csv_backlog import build_csv
from .reporting.html import build_html
from .reporting.markdown import build_summary

app = typer.Typer(add_completion=False)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "time": datetime.utcnow().isoformat(),
        }
        return json.dumps(payload)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])


def parse_mode_alias(raw_mode: str) -> Mode:
    mode = raw_mode.strip().lower()
    if mode == "enhanced":
        typer.echo("[deprecation] --mode enhanced is deprecated; use --mode low-noise", err=True)
        return Mode.low_noise
    if mode == "active":
        typer.echo("[deprecation] --mode active is deprecated; use --mode low-noise", err=True)
        return Mode.low_noise
    return Mode(mode)


@app.command()
def run(
    domain: str = typer.Option(..., "--domain"),
    company: str | None = typer.Option(None, "--company"),
    out: str = typer.Option("./output", "--out"),
    mode: str = typer.Option(
        Mode.passive.value,
        "--mode",
        help="passive (default): no target HTTP; low-noise: tiny capped target HEAD checks. Aliases: enhanced, active (deprecated).",
    ),
    dns_policy: DnsPolicy = typer.Option(
        DnsPolicy.minimal,
        "--dns-policy",
        help="none: no DNS; minimal: apex TXT+MX and _dmarc TXT; full: A/AAAA/NS/MX/TXT plus DKIM safelist in low-noise.",
    ),
    cache: CacheMode = typer.Option(CacheMode.sqlite, "--cache"),
    max_requests_per_minute: int = typer.Option(60, "--max-requests-per-minute"),
    max_target_http_requests_total: int = typer.Option(12, "--max-target-http-requests-total"),
    max_target_http_per_host: int = typer.Option(3, "--max-target-http-per-host"),
    max_target_http_per_minute: int = typer.Option(12, "--max-target-http-per-minute"),
    max_bytes_per_response: int = typer.Option(262_144, "--max-bytes-per-response"),
    max_target_dns_queries: int = typer.Option(25, "--max-target-dns-queries"),
    enable_third_party_intel: bool = typer.Option(False, "--enable-third-party-intel"),
    shodan_key: str | None = typer.Option(None, "--shodan-key"),
    censys_id: str | None = typer.Option(None, "--censys-id"),
    censys_secret: str | None = typer.Option(None, "--censys-secret"),
) -> None:
    """Run a posture assessment for a domain."""
    setup_logging()
    resolved_mode = parse_mode_alias(mode)
    config = create_run_config(
        domain=domain,
        company=company,
        out_dir=out,
        mode=resolved_mode,
        dns_policy=dns_policy,
        cache=cache,
        max_requests_per_minute=max_requests_per_minute,
        max_target_http_requests_total=max_target_http_requests_total,
        max_target_http_per_host=max_target_http_per_host,
        max_target_http_per_minute=max_target_http_per_minute,
        max_bytes_per_response=max_bytes_per_response,
        max_target_dns_queries=max_target_dns_queries,
        enable_third_party_intel=enable_third_party_intel,
        shodan_key=shodan_key,
        censys_id=censys_id,
        censys_secret=censys_secret,
    )
    result = execute_run(config)
    typer.echo(json.dumps(result, indent=2, default=str))


@app.command()
def report(input: str = typer.Option(..., "--input")) -> None:
    """Generate report artifacts from an existing run directory."""
    setup_logging()
    path = Path(input)
    findings_path = path / "findings.json"
    if not findings_path.exists():
        typer.echo("findings.json not found", err=True)
        raise typer.Exit(1)
    findings = json.loads(findings_path.read_text(encoding="utf-8"))

    summary_md = build_summary(findings)
    backlog_csv = build_csv(findings)
    report_html = build_html(findings)

    artifacts = path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "summary.md").write_text(summary_md, encoding="utf-8")
    (artifacts / "remediation_backlog.csv").write_text(backlog_csv, encoding="utf-8")
    (artifacts / "report.html").write_text(report_html, encoding="utf-8")

    typer.echo("reports generated")


@app.command()
def validate(input: str = typer.Option(..., "--input")) -> None:
    """Validate findings.json structure."""
    setup_logging()
    try:
        data = json.loads(Path(input).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        typer.echo(f"invalid JSON: {exc}", err=True)
        raise typer.Exit(1)

    required = ["summary", "scoring_rubric", "prioritized_backlog"]
    missing = [field for field in required if field not in data]
    if missing:
        typer.echo(f"missing fields: {', '.join(missing)}", err=True)
        raise typer.Exit(1)

    typer.echo("valid")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Run the internal web API and dashboard."""
    import uvicorn

    from .platform.app import create_app

    uvicorn.run(create_app(), host=host, port=port, reload=False)


@app.command("worker-once")
def worker_once(
    database_url: str | None = typer.Option(None, "--database-url"),
    out: str = typer.Option("./output", "--out"),
) -> None:
    """Process one queued platform run."""
    database = Database(database_url)
    database.create_all()
    with database.session() as session:
        seed_defaults(session)
        run = process_next_run(session, out_dir=out)
        if run is None:
            typer.echo("no queued runs")
        else:
            typer.echo(f"processed run {run.id}: {run.status}")


@app.command("cloudflare-job")
def cloudflare_job(
    input: str = typer.Option("-", "--input", help="Cloudflare queue job JSON file, or '-' for stdin."),
    out: str = typer.Option("./output", "--out"),
) -> None:
    """Execute one Cloudflare recon job payload with the local Python pipeline."""
    raw = sys.stdin.read() if input == "-" else Path(input).read_text(encoding="utf-8")
    job = CloudflareReconJob.model_validate_json(raw)
    result = execute_cloudflare_job(job, out_dir=out)
    typer.echo(json.dumps(result, indent=2, default=str))
