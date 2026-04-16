from __future__ import annotations

import dns.resolver

from ..models.config import DnsPolicy
from ..models.results import TakeoverSignalsResult
from ..utils.dns import DnsClient

# Fingerprint database: third-party services known to be susceptible to subdomain takeover.
# Based on https://github.com/EdOverflow/can-i-take-over-xyz
# nxdomain_likely=True means the service returns NXDOMAIN for unclaimed resources,
# making takeover straightforward to confirm.
FINGERPRINTS: list[dict] = [
    {"service": "GitHub Pages", "cname_suffix": ".github.io", "nxdomain_likely": True},
    {"service": "Heroku", "cname_suffix": ".herokuapp.com", "nxdomain_likely": True},
    {"service": "Amazon S3", "cname_suffix": ".s3.amazonaws.com", "nxdomain_likely": True},
    {"service": "Amazon S3 Website (us-east-1)", "cname_suffix": ".s3-website-us-east-1.amazonaws.com", "nxdomain_likely": True},
    {"service": "Amazon S3 Website (us-west-2)", "cname_suffix": ".s3-website-us-west-2.amazonaws.com", "nxdomain_likely": True},
    {"service": "Fastly", "cname_suffix": ".fastly.net", "nxdomain_likely": True},
    {"service": "Ghost", "cname_suffix": ".ghost.io", "nxdomain_likely": True},
    {"service": "Azure Websites", "cname_suffix": ".azurewebsites.net", "nxdomain_likely": True},
    {"service": "Azure CloudApp", "cname_suffix": ".cloudapp.net", "nxdomain_likely": True},
    {"service": "Azure Traffic Manager", "cname_suffix": ".trafficmanager.net", "nxdomain_likely": True},
    {"service": "Netlify", "cname_suffix": ".netlify.app", "nxdomain_likely": True},
    {"service": "Surge.sh", "cname_suffix": ".surge.sh", "nxdomain_likely": True},
    {"service": "Vercel", "cname_suffix": ".vercel.app", "nxdomain_likely": True},
    {"service": "ReadTheDocs", "cname_suffix": ".readthedocs.io", "nxdomain_likely": True},
    {"service": "Cargo", "cname_suffix": ".cargo.site", "nxdomain_likely": True},
    {"service": "Bitbucket Pages", "cname_suffix": ".bitbucket.io", "nxdomain_likely": True},
    {"service": "Fly.io", "cname_suffix": ".fly.dev", "nxdomain_likely": True},
    {"service": "Tumblr", "cname_suffix": ".tumblr.com", "nxdomain_likely": True},
    {"service": "Shopify", "cname_suffix": ".myshopify.com", "nxdomain_likely": False},
    {"service": "WordPress.com", "cname_suffix": ".wordpress.com", "nxdomain_likely": False},
    {"service": "Zendesk", "cname_suffix": ".zendesk.com", "nxdomain_likely": False},
    {"service": "Webflow", "cname_suffix": ".webflow.io", "nxdomain_likely": False},
    {"service": "Intercom", "cname_suffix": ".intercom.help", "nxdomain_likely": False},
    {"service": "HelpScout Docs", "cname_suffix": ".helpscoutdocs.com", "nxdomain_likely": False},
    {"service": "Helpjuice", "cname_suffix": ".helpjuice.com", "nxdomain_likely": False},
]

# Maximum subdomains to inspect — keeps CNAME lookups within the DNS budget.
_MAX_SUBDOMAINS_TO_CHECK = 20


def _match_fingerprint(cname_target: str) -> dict | None:
    """Return the first fingerprint whose cname_suffix matches the target, or None."""
    t = cname_target.lower().rstrip(".")
    for fp in FINGERPRINTS:
        if t.endswith(fp["cname_suffix"]):
            return fp
    return None


def _resolves_nxdomain(host: str) -> bool:
    """Return True when host has no A/AAAA record (NXDOMAIN), False otherwise."""
    for rtype in ("A", "AAAA"):
        try:
            dns.resolver.resolve(host.rstrip("."), rtype)
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            # NoAnswer, Timeout, etc. — not a confirmed NXDOMAIN.
            pass
    return False


def run(
    domain: str,
    subdomains: list[str],
    dns_client: DnsClient,
    dns_policy: DnsPolicy,
) -> TakeoverSignalsResult:
    """Check discovered subdomains for dangling CNAME records (takeover candidates).

    Requires dns_policy=full so that CNAME queries for subdomains are permitted.
    Inspection is capped at _MAX_SUBDOMAINS_TO_CHECK to stay within the DNS budget.
    """
    if dns_policy != DnsPolicy.full:
        return TakeoverSignalsResult(
            status="skipped",
            skipped_reason=f"dns_policy={dns_policy.value}; subdomain takeover checks require dns_policy=full",
        )

    candidates: list[dict] = []
    warnings: list[str] = []
    checked = 0
    to_check = subdomains[:_MAX_SUBDOMAINS_TO_CHECK]

    for sub in to_check:
        cname_records = dns_client.resolve_records(sub, "CNAME")
        if not cname_records:
            continue

        cname_target = cname_records[0].rstrip(".")
        checked += 1

        fp = _match_fingerprint(cname_target)
        if fp is None:
            continue

        is_nxdomain = _resolves_nxdomain(cname_target)

        if is_nxdomain:
            confidence = "high"
            priority = "High"
        elif fp["nxdomain_likely"]:
            # CNAME points to a service known to produce NXDOMAIN for unclaimed resources,
            # but the target currently resolves — still warrants investigation.
            confidence = "medium"
            priority = "Medium"
        else:
            confidence = "low"
            priority = "Medium"

        candidates.append(
            {
                "subdomain": sub,
                "cname_target": cname_target,
                "service": fp["service"],
                "nxdomain": is_nxdomain,
                "confidence": confidence,
                "priority": priority,
            }
        )

    if len(subdomains) > _MAX_SUBDOMAINS_TO_CHECK:
        warnings.append(
            f"Only checked first {_MAX_SUBDOMAINS_TO_CHECK} of {len(subdomains)} subdomains "
            "to stay within DNS budget; re-run with a smaller scope for full coverage."
        )

    return TakeoverSignalsResult(
        status="ok",
        candidates=candidates,
        checked=checked,
        warnings=warnings,
    )
