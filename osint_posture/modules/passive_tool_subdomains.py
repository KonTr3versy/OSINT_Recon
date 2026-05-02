from __future__ import annotations

import asyncio
import shutil

from ..utils.normalize import dedupe_subdomains, is_valid_subdomain, normalize_subdomain

TOOL_TIMEOUT_SECONDS = 45
MAX_TOOL_LINES = 5_000


async def _run_tool(source: str, command: list[str]) -> tuple[list[str], str | None]:
    if not shutil.which(command[0]):
        return [], f"{source} skipped: {command[0]} is not installed"
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TOOL_TIMEOUT_SECONDS)
    except TimeoutError:
        return [], f"{source} timed out after {TOOL_TIMEOUT_SECONDS}s"
    except Exception as exc:
        return [], f"{source} failed: {exc}"

    if proc.returncode not in (0, None):
        detail = stderr.decode("utf-8", errors="replace").strip()[:300]
        return [], f"{source} failed: {detail or f'exit {proc.returncode}'}"

    names = stdout.decode("utf-8", errors="replace").splitlines()[:MAX_TOOL_LINES]
    return names, None


def _scope_filter(domain: str, names: list[str]) -> tuple[list[str], int]:
    scoped: list[str] = []
    rejected = 0
    for raw in names:
        value = normalize_subdomain(raw)
        if not value or not is_valid_subdomain(value):
            rejected += 1
            continue
        if value != domain and not value.endswith(f".{domain}"):
            rejected += 1
            continue
        scoped.append(value)
    return dedupe_subdomains(scoped), rejected


async def run(domain: str, mode: str, dns_policy: str, enabled: bool = False) -> dict:
    if not enabled or mode != "low-noise" or dns_policy != "full":
        return {
            "status": "skipped",
            "reason": "passive tool adapters run only for approved low-noise/full-DNS recon",
            "subdomains": [],
            "attribution": {"sources": [], "warnings": []},
        }

    commands = {
        "subfinder": ["subfinder", "-silent", "-passive", "-d", domain],
        "amass": ["amass", "enum", "-passive", "-norecursive", "-noalts", "-d", domain],
    }
    all_names: list[str] = []
    warnings: list[str] = []
    per_source_counts: dict[str, int] = {}
    rejected_by_scope = 0

    for source, command in commands.items():
        names, error = await _run_tool(source, command)
        if error:
            warnings.append(error)
            per_source_counts[source] = 0
            continue
        scoped, rejected = _scope_filter(domain, names)
        per_source_counts[source] = len(scoped)
        rejected_by_scope += rejected
        all_names.extend(scoped)

    return {
        "status": "ok" if all_names else "skipped",
        "subdomains": dedupe_subdomains(all_names),
        "attribution": {
            "sources": list(commands.keys()),
            "per_source_counts": per_source_counts,
            "warnings": warnings,
        },
        "rejected_by_scope": rejected_by_scope,
        "allowlisted_commands": list(commands.values()),
    }
