from __future__ import annotations

from typing import Iterable

from ..models.results import WebSignalsResult
from ..utils.http import HttpClient
from ..utils.normalize import sanitize_headers

COMMON_PORTALS = ["www", "login", "portal", "sso", "id", "account"]

EXPECTED_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]


def infer_tech_hints(subdomains: Iterable[str]) -> list[str]:
    hints = []
    for name in subdomains:
        if name.startswith("login.") or name.startswith("sso."):
            hints.append("SSO or identity portal detected via subdomain naming.")
        if "mail" in name:
            hints.append("Mail-related subdomain detected.")
    return sorted(set(hints))


def _check_security_headers(url: str, headers: dict) -> dict:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = []
    present = []
    for hdr in EXPECTED_SECURITY_HEADERS:
        if hdr in lower_headers:
            present.append(hdr)
        else:
            missing.append(hdr)
    return {
        "url": url,
        "missing": missing,
        "present": present,
    }


async def run(
    domain: str, subdomains: list[str], mode: str, http: HttpClient, max_pages: int
) -> WebSignalsResult:
    portal_candidates = [f"{p}.{domain}" for p in COMMON_PORTALS]
    portal_candidates.extend([s for s in subdomains if s.count(".") <= 3])
    portal_candidates = list(dict.fromkeys(portal_candidates))

    technology_hints = infer_tech_hints(subdomains)
    headers_samples = []
    security_headers = []

    if mode == "active":
        targets = portal_candidates[:max_pages]
        for host in targets:
            url = f"https://{host}"
            try:
                resp = await http.head(url)
                raw_headers = dict(resp.headers)
                headers_samples.append(
                    {
                        "url": url,
                        "status": resp.status_code,
                        "headers": sanitize_headers(raw_headers),
                    }
                )
                security_headers.append(_check_security_headers(url, raw_headers))
            except Exception:
                continue

    return WebSignalsResult(
        portal_candidates=portal_candidates[:max_pages],
        technology_hints=technology_hints,
        headers_samples=headers_samples,
        security_headers=security_headers,
    )
