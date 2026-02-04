from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

from ..models.config import ModuleResult, RunConfig
from ..modules import (
    dns_mail_profile,
    doc_signals,
    passive_subdomains,
    scope_init,
    synthesis,
    third_party_intel,
    web_signals,
)
from ..reporting.csv_backlog import build_csv
from ..reporting.markdown import build_summary
from ..utils.cache import build_cache
from ..utils.http import HttpClient
from ..utils.rate_limit import AsyncRateLimiter

logger = logging.getLogger(__name__)


def _write_json(path: str, data: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _wrap_module(name: str, func, *args, **kwargs) -> ModuleResult:
    started = datetime.utcnow()
    try:
        data = func(*args, **kwargs)
        status = "ok"
        warnings = []
        errors = []
        if hasattr(data, "model_dump"):
            payload = data.model_dump()
        else:
            payload = data
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
        if hasattr(data, "model_dump"):
            payload = data.model_dump()
        else:
            payload = data
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


async def run_pipeline(config: RunConfig) -> dict:
    run_path = config.run_path
    raw_path = f"{run_path}/raw"
    artifacts_path = f"{run_path}/artifacts"

    Path(raw_path).mkdir(parents=True, exist_ok=True)
    Path(artifacts_path).mkdir(parents=True, exist_ok=True)

    cache = build_cache(config.cache.value, run_path)
    limiter = AsyncRateLimiter(config.max_requests_per_minute)
    http = HttpClient(timeout_seconds=config.timeout_seconds, retries=config.retries, rate_limiter=limiter)

    modules: list[ModuleResult] = []

    scope_result = _wrap_module(
        "scope_init",
        scope_init.run,
        config.domain,
        config.model_dump(),
    )
    modules.append(scope_result)
    _write_json(f"{raw_path}/scope_init.json", scope_result.data)

    dns_result = _wrap_module(
        "dns_mail_profile",
        dns_mail_profile.run,
        config.domain,
        config.mode.value == "enhanced",
    )
    modules.append(dns_result)
    _write_json(f"{raw_path}/dns_mail_profile.json", dns_result.data)

    subdomains_result = await _wrap_module_async(
        "passive_subdomains",
        passive_subdomains.run(config.domain, http, cache),
    )
    modules.append(subdomains_result)
    _write_json(f"{raw_path}/passive_subdomains.json", subdomains_result.data)

    third_party_result = await _wrap_module_async(
        "third_party_intel",
        third_party_intel.run(
            config.domain,
            config.enable_third_party_intel,
            config.shodan_key,
            config.censys_id,
            config.censys_secret,
            http,
        ),
    )
    modules.append(third_party_result)
    _write_json(f"{raw_path}/third_party_intel.json", third_party_result.data)

    web_result = await _wrap_module_async(
        "web_signals",
        web_signals.run(
            config.domain,
            subdomains_result.data.get("subdomains", []),
            config.mode.value,
            http,
            config.max_pages,
        ),
    )
    modules.append(web_result)
    _write_json(f"{raw_path}/web_signals.json", web_result.data)

    doc_result = await _wrap_module_async(
        "doc_signals",
        doc_signals.run(
            config.domain,
            subdomains_result.data.get("subdomains", []),
            http,
            config.max_pages,
        ),
    )
    modules.append(doc_result)
    _write_json(f"{raw_path}/doc_signals.json", doc_result.data)

    results_map = {m.module: m.data for m in modules}
    synth = synthesis.run(results_map)
    synth_payload = synth.model_dump()

    _write_json(f"{raw_path}/synthesis.json", synth_payload)

    summary_md = build_summary(synth_payload)
    backlog_csv = build_csv(synth_payload)

    with open(f"{artifacts_path}/summary.md", "w", encoding="utf-8") as f:
        f.write(summary_md)
    with open(f"{artifacts_path}/remediation_backlog.csv", "w", encoding="utf-8") as f:
        f.write(backlog_csv)

    findings = {
        **synth_payload,
        "summary": synth_payload.get("summary", {}),
    }
    _write_json(f"{run_path}/findings.json", findings)

    return {
        "config": config.model_dump(),
        "modules": [m.model_dump() for m in modules],
        "synthesis": synth_payload,
        "run_path": run_path,
    }


def run_pipeline_sync(config: RunConfig) -> dict:
    return asyncio.run(run_pipeline(config))
