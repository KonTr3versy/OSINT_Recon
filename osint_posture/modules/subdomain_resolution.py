from __future__ import annotations

from ..utils.dns import DnsClient
from ..utils.normalize import dedupe_subdomains

RECORD_TYPES = ("A", "AAAA", "CNAME")


def run(
    domain: str,
    subdomains: list[str],
    mode: str,
    dns_policy: str,
    dns: DnsClient,
    max_queries: int,
    enabled: bool = False,
) -> dict:
    if not enabled or mode != "low-noise" or dns_policy != "full":
        return {
            "status": "skipped",
            "reason": "subdomain resolution requires approved low-noise/full-DNS recon",
            "resolved": [],
            "unresolved": [],
        }

    candidates = dedupe_subdomains([domain, f"www.{domain}", *subdomains])
    max_hosts = max(1, max_queries // len(RECORD_TYPES))
    resolved: list[dict] = []
    unresolved: list[str] = []

    for host in candidates[:max_hosts]:
        records: dict[str, list[str]] = {}
        for record_type in RECORD_TYPES:
            values = dns.resolve_records(host, record_type)
            if values:
                records[record_type] = values
        if records:
            resolved.append({"host": host, "records": records})
        else:
            unresolved.append(host)

    return {
        "status": "ok",
        "resolved": resolved,
        "unresolved": unresolved,
        "truncated": len(candidates) > max_hosts,
        "candidate_count": len(candidates),
        "max_hosts": max_hosts,
    }
