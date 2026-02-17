from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..models.config import ModuleResult, RunConfig
from ..modules import (
    dns_mail_profile,
    doc_signals,
    passive_subdomains,
    passive_users,
    scope_init,
    synthesis,
    third_party_intel,
    web_signals,
)
from ..pipeline.context import RunContext
from ..reporting.csv_backlog import build_csv
from ..reporting.html import build_html
from ..reporting.markdown import build_summary
from ..utils.cache import build_cache
from ..utils.dns import DnsClient
from ..utils.http import HttpClient
from ..utils.network import NetworkLedger, NetworkPolicy
from ..utils.rate_limit import AsyncRateLimiter

logger = logging.getLogger(__name__)


def _write_json(path: str, data: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _git_sha() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return None


def _wrap_module(name: str, func, *args, **kwargs) -> ModuleResult:
    started = datetime.utcnow()
    try:
        data = func(*args, **kwargs)
        status = "ok"
        warnings = []
        errors = []
        payload = data.model_dump() if hasattr(data, "model_dump") else data
    except Exception as exc:
        status = "error"
        warnings = []
        errors = [str(exc)]
        payload = {}
    finished = datetime.utcnow()
    return ModuleResult(
        module=name,
        status=status,
        data=payload,
        warnings=warnings,
        errors=errors,
        started_at=started,
        finished_at=finished,
    )


async def _wrap_module_async(name: str, coro) -> ModuleResult:
    started = datetime.utcnow()
    try:
        data = await coro
        status = "ok"
        warnings = []
        errors = []
        payload = data.model_dump() if hasattr(data, "model_dump") else data
    except Exception as exc:
        status = "error"
        warnings = []
        errors = [str(exc)]
        payload = {}
    finished = datetime.utcnow()
    return ModuleResult(
        module=name,
        status=status,
        data=payload,
        warnings=warnings,
        errors=errors,
        started_at=started,
        finished_at=finished,
    )


def _build_manifest(context: RunContext) -> dict:
    redacted = context.config.model_dump()
    for secret in ("shodan_key", "censys_id", "censys_secret"):
        if redacted.get(secret):
            redacted[secret] = "***"
    return {
        "tool_version": __version__,
        "git_sha": _git_sha(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config": redacted,
        "budgets": context.policy.budgets(),
        "ledger_totals": context.ledger.totals(),
    }


async def run_pipeline(config: RunConfig) -> dict:
    run_path = config.run_path
    raw_path = f"{run_path}/raw"
    artifacts_path = f"{run_path}/artifacts"

    Path(raw_path).mkdir(parents=True, exist_ok=True)
    Path(artifacts_path).mkdir(parents=True, exist_ok=True)

    ledger = NetworkLedger()
    policy = NetworkPolicy.from_config(config)
    cache = build_cache(config.cache.value, run_path)
    limiter = AsyncRateLimiter(config.max_requests_per_minute)
    http = HttpClient(timeout_seconds=config.timeout_seconds, retries=config.retries, rate_limiter=limiter, policy=policy, ledger=ledger)
    dns_client = DnsClient(policy=policy, ledger=ledger)
    context = RunContext(config=config, policy=policy, ledger=ledger, http_client=http, dns_client=dns_client, cache=cache)

    modules: list[ModuleResult] = []
    findings: dict = {}
    try:
        scope_result = _wrap_module("scope_init", scope_init.run, config.domain, config.model_dump())
        modules.append(scope_result)
        _write_json(f"{raw_path}/scope_init.json", scope_result.data)

        dns_result = _wrap_module("dns_mail_profile", dns_mail_profile.run, config.domain, config.mode, context.dns_client)
        modules.append(dns_result)
        _write_json(f"{raw_path}/dns_mail_profile.json", dns_result.data)

        subdomains_result = await _wrap_module_async("passive_subdomains", passive_subdomains.run(config.domain, context.http_client, context.cache))
        modules.append(subdomains_result)
        _write_json(f"{raw_path}/passive_subdomains.json", subdomains_result.data)

        users_result = await _wrap_module_async(
            "passive_users",
            passive_users.run(config.domain, config.company, context.http_client, config.max_pages),
        )
        modules.append(users_result)
        _write_json(f"{raw_path}/passive_users.json", users_result.data)

        third_party_result = await _wrap_module_async(
            "third_party_intel",
            third_party_intel.run(
                config.domain,
                config.enable_third_party_intel,
                config.shodan_key,
                config.censys_id,
                config.censys_secret,
                context.http_client,
            ),
        )
        modules.append(third_party_result)
        _write_json(f"{raw_path}/third_party_intel.json", third_party_result.data)

        web_result = await _wrap_module_async(
            "web_signals",
            web_signals.run(config.domain, subdomains_result.data.get("subdomains", []), config.mode.value, context.http_client, config.max_pages),
        )
        modules.append(web_result)
        _write_json(f"{raw_path}/web_signals.json", web_result.data)

        doc_result = await _wrap_module_async(
            "doc_signals",
            doc_signals.run(config.domain, subdomains_result.data.get("subdomains", []), context.http_client, config.max_pages, config.mode.value),
        )
        modules.append(doc_result)
        _write_json(f"{raw_path}/doc_signals.json", doc_result.data)

        results_map = {m.module: m.data for m in modules}
        synth_payload = synthesis.run(results_map).model_dump()
        _write_json(f"{raw_path}/synthesis.json", synth_payload)

        summary_md = build_summary(synth_payload)
        totals = context.ledger.totals().get("counts", {})
        summary_md += (
            "\n\n## Noise Contract Summary\n"
            f"- mode: {config.mode.value}\n"
            f"- dns_policy: {config.dns_policy.value}\n"
            f"- third_party_http calls: {totals.get('third_party_http', 0)}\n"
            f"- target_dns queries: {totals.get('target_dns', 0)}\n"
            f"- target_http calls: {totals.get('target_http', 0)}\n"
            "- budgets_exceeded: false (policy blocks attempts)\n"
        )
        backlog_csv = build_csv(synth_payload)
        report_html = build_html(synth_payload)

        with open(f"{artifacts_path}/summary.md", "w", encoding="utf-8") as f:
            f.write(summary_md)
        with open(f"{artifacts_path}/remediation_backlog.csv", "w", encoding="utf-8") as f:
            f.write(backlog_csv)
        with open(f"{artifacts_path}/report.html", "w", encoding="utf-8") as f:
            f.write(report_html)

        findings = {**synth_payload, "summary": synth_payload.get("summary", {})}
        _write_json(f"{run_path}/findings.json", findings)

        return {
            "config": config.model_dump(),
            "modules": [m.model_dump() for m in modules],
            "synthesis": synth_payload,
            "run_path": run_path,
        }
    finally:
        await http.close()
        _write_json(f"{raw_path}/network_ledger.json", context.ledger.to_dict())
        _write_json(f"{raw_path}/run_manifest.json", _build_manifest(context))


def run_pipeline_sync(config: RunConfig) -> dict:
    return asyncio.run(run_pipeline(config))
