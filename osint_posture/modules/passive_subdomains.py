from __future__ import annotations

import json
from typing import Optional

from ..models.results import PassiveSubdomainsResult
from ..utils.cache import CacheBase
from ..utils.http import HttpClient
from ..utils.normalize import dedupe_subdomains, is_valid_subdomain, normalize_subdomain


async def run(domain: str, http: HttpClient, cache: Optional[CacheBase] = None) -> PassiveSubdomainsResult:
    cache_key = f"crtsh:{domain}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return PassiveSubdomainsResult(**cached)

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = await http.get(url)
    data = []
    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError:
        data = []

    names = []
    for entry in data:
        name_val = entry.get("name_value", "")
        for part in name_val.split("\n"):
            names.append(part)

    total_seen = len(names)
    removed_wildcards = 0
    invalid_entries = 0
    cleaned = []
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

    subdomains = dedupe_subdomains(cleaned)

    result = PassiveSubdomainsResult(
        subdomains=subdomains,
        attribution={"source": "crt.sh", "url": url},
        removed_wildcards=removed_wildcards,
        invalid_entries=invalid_entries,
        total_seen=total_seen,
    )

    if cache:
        cache.set(cache_key, result.model_dump())

    return result
