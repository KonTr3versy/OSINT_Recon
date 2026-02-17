from __future__ import annotations

import json
from typing import Optional

from ..models.results import PassiveSubdomainsResult
from ..utils.cache import CacheBase
from ..utils.http import HttpClient
from ..utils.normalize import dedupe_subdomains, is_valid_subdomain, normalize_subdomain


async def _from_crtsh(domain: str, http: HttpClient) -> tuple[list[str], str | None]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = await http.get(url)
        data = json.loads(resp.text)
    except Exception as exc:
        return [], f"crt.sh failed: {exc}"

    names: list[str] = []
    for entry in data:
        name_val = entry.get("name_value", "")
        for part in str(name_val).split("\n"):
            names.append(part)
    return names, None


async def _from_certspotter(domain: str, http: HttpClient) -> tuple[list[str], str | None]:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        resp = await http.get(url)
        data = resp.json()
    except Exception as exc:
        return [], f"certspotter failed: {exc}"

    names: list[str] = []
    for entry in data if isinstance(data, list) else []:
        for dns_name in entry.get("dns_names", []):
            names.append(str(dns_name))
    return names, None


async def _from_bufferover(domain: str, http: HttpClient) -> tuple[list[str], str | None]:
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        resp = await http.get(url)
        data = resp.json()
    except Exception as exc:
        return [], f"bufferover failed: {exc}"

    names: list[str] = []
    for item in data.get("FDNS_A", []) if isinstance(data, dict) else []:
        host = str(item).split(",")[-1].strip()
        names.append(host)
    for item in data.get("RDNS", []) if isinstance(data, dict) else []:
        host = str(item).split(",")[-1].strip()
        names.append(host)
    return names, None


async def _from_urlscan(domain: str, http: HttpClient) -> tuple[list[str], str | None]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    try:
        resp = await http.get(url)
        data = resp.json()
    except Exception as exc:
        return [], f"urlscan failed: {exc}"

    names: list[str] = []
    for item in data.get("results", []) if isinstance(data, dict) else []:
        page = item.get("page", {})
        domain_seen = page.get("domain")
        if domain_seen:
            names.append(str(domain_seen))
        ptr = page.get("ptr")
        if ptr:
            names.append(str(ptr))
    return names, None


def _clean_candidates(names: list[str]) -> tuple[list[str], int, int]:
    removed_wildcards = 0
    invalid_entries = 0
    cleaned: list[str] = []
    for raw in names:
        if raw.strip().startswith("*."):
            removed_wildcards += 1
        value = normalize_subdomain(raw)
        if not value:
            invalid_entries += 1
            continue
        if not is_valid_subdomain(value):
            invalid_entries += 1
            continue
        cleaned.append(value)
    return cleaned, removed_wildcards, invalid_entries


async def run(domain: str, http: HttpClient, cache: Optional[CacheBase] = None) -> PassiveSubdomainsResult:
    cache_key = f"passive_subdomains:{domain}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return PassiveSubdomainsResult(**cached)

    source_fetchers = {
        "crt.sh": _from_crtsh,
        "certspotter": _from_certspotter,
        "bufferover": _from_bufferover,
        "urlscan": _from_urlscan,
    }

    all_names: list[str] = []
    warnings: list[str] = []
    per_source_counts: dict[str, int] = {}
    for source, fetcher in source_fetchers.items():
        names, error = await fetcher(domain, http)
        if error:
            warnings.append(error)
            per_source_counts[source] = 0
            continue
        per_source_counts[source] = len(names)
        all_names.extend(names)

    cleaned, removed_wildcards, invalid_entries = _clean_candidates(all_names)
    subdomains = dedupe_subdomains(cleaned)

    result = PassiveSubdomainsResult(
        subdomains=subdomains,
        attribution={
            "sources": list(source_fetchers.keys()),
            "per_source_counts": per_source_counts,
            "warnings": warnings,
            "note": "Passive third-party aggregation; validate ownership and recency before action.",
        },
        removed_wildcards=removed_wildcards,
        invalid_entries=invalid_entries,
        total_seen=len(all_names),
    )

    if cache:
        cache.set(cache_key, result.model_dump())

    return result
