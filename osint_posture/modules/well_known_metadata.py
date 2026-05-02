from __future__ import annotations

from ..utils.http import HttpClient
from ..utils.normalize import sanitize_headers

WELL_KNOWN_PATHS = ["/.well-known/security.txt", "/security.txt", "/.well-known/change-password"]


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
            "reason": "well-known metadata checks require approved low-noise/full-DNS recon",
            "checks": [],
        }

    resolved = resolution.get("resolved", []) if isinstance(resolution, dict) else []
    hosts = [domain, f"www.{domain}"]
    for item in resolved:
        if isinstance(item, dict) and item.get("host"):
            hosts.append(str(item["host"]))
    hosts = list(dict.fromkeys(hosts))[:max_hosts]

    checks: list[dict] = []
    for host in hosts:
        for path in WELL_KNOWN_PATHS:
            url = f"https://{host}{path}"
            try:
                response = await http.head(url)
                checks.append(
                    {
                        "host": host,
                        "url": url,
                        "method": "HEAD",
                        "status": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "content_length": response.headers.get("content-length", ""),
                        "headers": sanitize_headers(dict(response.headers)),
                    }
                )
            except Exception as exc:
                checks.append({"host": host, "url": url, "method": "HEAD", "status": "error", "error": str(exc)})

    return {
        "status": "ok",
        "checks": checks,
        "paths": WELL_KNOWN_PATHS,
        "hosts_checked": hosts,
    }
