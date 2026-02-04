from __future__ import annotations

import json
from typing import Optional

from ..models.results import PassiveSubdomainsResult
from ..utils.cache import CacheBase
from ..utils.http import HttpClient
from ..utils.normalize import dedupe_subdomains


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

    subdomains = dedupe_subdomains(names)

    result = PassiveSubdomainsResult(
        subdomains=subdomains,
        attribution={"source": "crt.sh", "url": url},
    )

    if cache:
        cache.set(cache_key, result.model_dump())

    return result
