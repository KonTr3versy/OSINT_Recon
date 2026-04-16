from __future__ import annotations

from unittest.mock import patch

import dns.resolver
import pytest

from osint_posture.models.config import DnsPolicy
from osint_posture.modules.takeover_signals import (
    FINGERPRINTS,
    _match_fingerprint,
    _resolves_nxdomain,
    run,
)


class _MockDnsClient:
    """Minimal DnsClient stand-in that returns preconfigured CNAME mappings."""

    def __init__(self, cname_map: dict[str, list[str]] | None = None) -> None:
        self.cname_map = cname_map or {}

    def resolve_records(self, domain: str, record_type: str) -> list[str]:
        if record_type == "CNAME":
            return self.cname_map.get(domain, [])
        return []


# ---------------------------------------------------------------------------
# Fingerprint matching
# ---------------------------------------------------------------------------

def test_match_fingerprint_github():
    fp = _match_fingerprint("myproject.github.io")
    assert fp is not None
    assert fp["service"] == "GitHub Pages"


def test_match_fingerprint_azure():
    fp = _match_fingerprint("myapp.azurewebsites.net.")
    assert fp is not None
    assert "Azure" in fp["service"]


def test_match_fingerprint_no_match():
    fp = _match_fingerprint("mysite.example.com")
    assert fp is None


def test_match_fingerprint_case_insensitive():
    fp = _match_fingerprint("MyApp.Netlify.App")
    assert fp is not None
    assert fp["service"] == "Netlify"


def test_fingerprints_list_not_empty():
    assert len(FINGERPRINTS) > 10


# ---------------------------------------------------------------------------
# NXDOMAIN helper
# ---------------------------------------------------------------------------

def test_resolves_nxdomain_true_when_nxdomain():
    with patch("osint_posture.modules.takeover_signals.dns.resolver.resolve",
               side_effect=dns.resolver.NXDOMAIN):
        assert _resolves_nxdomain("nonexistent.github.io") is True


def test_resolves_nxdomain_false_when_resolves():
    mock_answer = object()  # non-empty stand-in
    with patch("osint_posture.modules.takeover_signals.dns.resolver.resolve",
               return_value=mock_answer):
        assert _resolves_nxdomain("exists.github.io") is False


def test_resolves_nxdomain_false_on_timeout():
    with patch("osint_posture.modules.takeover_signals.dns.resolver.resolve",
               side_effect=dns.resolver.Timeout):
        assert _resolves_nxdomain("slow.github.io") is False


# ---------------------------------------------------------------------------
# Module run()
# ---------------------------------------------------------------------------

def test_skipped_when_minimal_policy():
    client = _MockDnsClient()
    result = run("example.com", ["sub.example.com"], client, DnsPolicy.minimal)
    assert result.status == "skipped"
    assert result.skipped_reason is not None
    assert "full" in result.skipped_reason


def test_skipped_when_none_policy():
    client = _MockDnsClient()
    result = run("example.com", ["sub.example.com"], client, DnsPolicy.none)
    assert result.status == "skipped"


def test_nxdomain_candidate_detected():
    client = _MockDnsClient({"shop.example.com": ["myshop.github.io."]})
    with patch("osint_posture.modules.takeover_signals._resolves_nxdomain", return_value=True):
        result = run("example.com", ["shop.example.com"], client, DnsPolicy.full)

    assert result.status == "ok"
    assert len(result.candidates) == 1
    c = result.candidates[0]
    assert c["subdomain"] == "shop.example.com"
    assert c["cname_target"] == "myshop.github.io"
    assert c["service"] == "GitHub Pages"
    assert c["nxdomain"] is True
    assert c["confidence"] == "high"
    assert c["priority"] == "High"


def test_resolving_cname_is_medium_confidence():
    client = _MockDnsClient({"blog.example.com": ["myblog.github.io."]})
    with patch("osint_posture.modules.takeover_signals._resolves_nxdomain", return_value=False):
        result = run("example.com", ["blog.example.com"], client, DnsPolicy.full)

    assert result.status == "ok"
    assert len(result.candidates) == 1
    c = result.candidates[0]
    assert c["nxdomain"] is False
    assert c["confidence"] == "medium"
    assert c["priority"] == "Medium"


def test_no_cname_subdomains_produce_no_candidates():
    client = _MockDnsClient()  # no CNAME records for any subdomain
    result = run("example.com", ["www.example.com", "api.example.com"], client, DnsPolicy.full)
    assert result.status == "ok"
    assert result.candidates == []
    assert result.checked == 0


def test_cname_not_matching_fingerprint_ignored():
    client = _MockDnsClient({"www.example.com": ["loadbalancer.internal-cdn.net."]})
    with patch("osint_posture.modules.takeover_signals._resolves_nxdomain", return_value=True):
        result = run("example.com", ["www.example.com"], client, DnsPolicy.full)

    assert result.candidates == []
    assert result.checked == 1  # CNAME found, but no fingerprint match


def test_budget_warning_for_large_subdomain_list():
    client = _MockDnsClient()
    subs = [f"sub{i}.example.com" for i in range(25)]
    result = run("example.com", subs, client, DnsPolicy.full)
    assert any("budget" in w.lower() or "Only checked" in w for w in result.warnings)


def test_multiple_candidates_returned():
    client = _MockDnsClient(
        {
            "shop.example.com": ["myshop.github.io."],
            "app.example.com": ["myapp.azurewebsites.net."],
        }
    )
    with patch("osint_posture.modules.takeover_signals._resolves_nxdomain", return_value=True):
        result = run(
            "example.com",
            ["shop.example.com", "app.example.com"],
            client,
            DnsPolicy.full,
        )

    assert result.status == "ok"
    assert len(result.candidates) == 2
    services = {c["service"] for c in result.candidates}
    assert "GitHub Pages" in services
    assert any("Azure" in s for s in services)


def test_empty_subdomains_list():
    client = _MockDnsClient()
    result = run("example.com", [], client, DnsPolicy.full)
    assert result.status == "ok"
    assert result.candidates == []
    assert result.checked == 0
