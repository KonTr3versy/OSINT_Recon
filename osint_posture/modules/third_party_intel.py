from __future__ import annotations

import base64
from typing import Optional

from ..models.results import ThirdPartyIntelResult
from ..utils.http import HttpClient


async def _shodan(host: str, key: str, http: HttpClient) -> list[dict]:
    url = f"https://api.shodan.io/dns/domain/{host}?key={key}"
    resp = await http.get(url)
    data = resp.json()
    services = []
    for item in data.get("data", []):
        services.append(
            {
                "host": item.get("subdomain", "") + "." + host,
                "ports": item.get("ports", []),
                "product": None,
                "last_seen": None,
                "source": "shodan",
            }
        )
    return services


async def _censys(host: str, censys_id: str, censys_secret: str, http: HttpClient) -> list[dict]:
    url = "https://search.censys.io/api/v2/hosts/search"
    token = base64.b64encode(f"{censys_id}:{censys_secret}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}
    query = {"q": f"services.tls.certificates.leaf_data.names: {host}", "per_page": 5}
    resp = await http.post(url, json=query, headers=headers)
    data = resp.json()
    services = []
    for hit in data.get("result", {}).get("hits", []):
        services.append(
            {
                "host": hit.get("ip"),
                "ports": [s.get("port") for s in hit.get("services", [])],
                "product": None,
                "last_seen": hit.get("last_updated_at"),
                "source": "censys",
            }
        )
    return services


async def run(
    domain: str,
    enable: bool,
    shodan_key: Optional[str],
    censys_id: Optional[str],
    censys_secret: Optional[str],
    http: HttpClient,
) -> ThirdPartyIntelResult:
    if not enable:
        return ThirdPartyIntelResult(status="skipped")

    services: list[dict] = []
    risk_flags: list[str] = []
    recommendations: list[str] = []

    if shodan_key:
        try:
            services.extend(await _shodan(domain, shodan_key, http))
        except Exception:
            risk_flags.append("Shodan lookup failed.")
    if censys_id and censys_secret:
        try:
            services.extend(await _censys(domain, censys_id, censys_secret, http))
        except Exception:
            risk_flags.append("Censys lookup failed.")

    if not services:
        recommendations.append("No third-party exposed services identified or lookups skipped.")

    return ThirdPartyIntelResult(
        status="ok",
        services=services,
        risk_flags=risk_flags,
        recommendations=recommendations,
    )
