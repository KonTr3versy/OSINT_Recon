from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ..models.config import CacheMode, DnsPolicy, Mode, RunConfig
from ..reporting.csv_backlog import build_csv
from ..reporting.html import build_html
from ..reporting.markdown import build_summary
from .runner import run_pipeline_sync


def create_run_config(
    *,
    domain: str,
    company: str | None = None,
    out_dir: str = "./output",
    mode: Mode = Mode.passive,
    dns_policy: DnsPolicy = DnsPolicy.minimal,
    cache: CacheMode = CacheMode.sqlite,
    max_requests_per_minute: int = 60,
    max_target_http_requests_total: int = 12,
    max_target_http_per_host: int = 3,
    max_target_http_per_minute: int = 12,
    max_bytes_per_response: int = 262_144,
    max_target_dns_queries: int = 25,
    enable_third_party_intel: bool = False,
    shodan_key: str | None = None,
    censys_id: str | None = None,
    censys_secret: str | None = None,
) -> RunConfig:
    return RunConfig(
        domain=domain,
        company=company,
        mode=mode,
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
        out_dir=out_dir,
        run_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
    )


def execute_run(config: RunConfig) -> dict:
    return run_pipeline_sync(config)


def generate_reports(findings: dict) -> dict[str, str]:
    return {
        "summary_md": build_summary(findings),
        "remediation_backlog_csv": build_csv(findings),
        "report_html": build_html(findings),
    }


def load_run_artifacts(run_path: str | Path) -> dict[str, str | dict]:
    path = Path(run_path)
    artifacts = path / "artifacts"
    raw = path / "raw"
    loaded: dict[str, str | dict] = {}
    for name, fp in {
        "findings": path / "findings.json",
        "summary_md": artifacts / "summary.md",
        "remediation_backlog_csv": artifacts / "remediation_backlog.csv",
        "report_html": artifacts / "report.html",
        "network_ledger": raw / "network_ledger.json",
        "run_manifest": raw / "run_manifest.json",
    }.items():
        if not fp.exists():
            continue
        text = fp.read_text(encoding="utf-8")
        loaded[name] = json.loads(text) if fp.suffix == ".json" else text
    return loaded

