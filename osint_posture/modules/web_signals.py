from __future__ import annotations

from typing import Iterable

from ..models.results import WebSignalsResult
from ..utils.http import HttpClient
from ..utils.normalize import sanitize_headers

COMMON_PORTALS = ["www", "login", "portal", "sso", "id", "account"]


def infer_tech_hints(subdomains: Iterable[str]) -> list[str]:
    hints = []
    for name in subdomains:
        if name.startswith("login.") or name.startswith("sso."):
            hints.append("SSO or identity portal detected via subdomain naming.")
        if "mail" in name:
            hints.append("Mail-related subdomain detected.")
    return sorted(set(hints))


async def run(domain: str, subdomains: list[str], mode: str, http: HttpClient, max_pages: int) -> WebSignalsResult:
    portal_candidates = [f"{p}.{domain}" for p in COMMON_PORTALS]
    portal_candidates.extend([s for s in subdomains if s.count(".") <= 3])
    portal_candidates = list(dict.fromkeys(portal_candidates))

    technology_hints = infer_tech_hints(subdomains)
    headers_samples = []

    if mode == "enhanced":
        targets = portal_candidates[:max_pages]
        for host in targets:
            url = f"https://{host}"
            try:
                resp = await http.head(url)
                headers_samples.append(
                    {
                        "url": url,
                        "status": resp.status_code,
                        "headers": sanitize_headers(dict(resp.headers)),
                    }
                )
            except Exception:
                continue

    return WebSignalsResult(
        portal_candidates=portal_candidates[:max_pages],
        technology_hints=technology_hints,
        headers_samples=headers_samples,
    )
