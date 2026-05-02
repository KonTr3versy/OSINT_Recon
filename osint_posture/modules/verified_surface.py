from __future__ import annotations

from ..modules.web_signals import _check_security_headers
from ..utils.http import HttpClient
from ..utils.normalize import sanitize_headers


async def run(
    domain: str,
    resolution: dict,
    mode: str,
    dns_policy: str,
    http: HttpClient,
    max_hosts: int,
    enabled: bool = False,
) -> dict:
    if not enabled or mode != "low-noise" or dns_policy != "full":
        return {
            "status": "skipped",
            "reason": "verified surface requires approved low-noise/full-DNS recon",
            "hosts": [],
            "security_headers": [],
        }

    resolved = resolution.get("resolved", []) if isinstance(resolution, dict) else []
    hosts = []
    for item in resolved:
        if isinstance(item, dict) and item.get("host"):
            hosts.append(str(item["host"]))
    if domain not in hosts:
        hosts.insert(0, domain)
    if f"www.{domain}" not in hosts:
        hosts.insert(1, f"www.{domain}")
    hosts = list(dict.fromkeys(hosts))[:max_hosts]

    observations: list[dict] = []
    security_headers: list[dict] = []
    warnings: list[str] = []
    for host in hosts:
        url = f"https://{host}"
        try:
            response = await http.head(url)
            raw_headers = dict(response.headers)
            observations.append(
                {
                    "host": host,
                    "url": url,
                    "method": "HEAD",
                    "status": response.status_code,
                    "headers": sanitize_headers(raw_headers),
                }
            )
            security_headers.append(_check_security_headers(url, raw_headers))
        except Exception as exc:
            warnings.append(f"{host}: {exc}")

    return {
        "status": "ok",
        "hosts": observations,
        "security_headers": security_headers,
        "warnings": warnings,
        "truncated": len(hosts) >= max_hosts,
    }
