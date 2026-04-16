from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from osint_posture.modules.tls_profile import parse_cert_dict, run
from osint_posture.models.results import TlsProfileResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cert(days_until_expiry: int = 365, issuer_cn: str = "Let's Encrypt", subject_cn: str = "example.com", sans: list[str] | None = None) -> dict:
    """Build a minimal ssl.getpeercert()-style dict."""
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=days_until_expiry)
    not_before = now - timedelta(days=30)

    def _fmt(dt: datetime) -> str:
        return dt.strftime("%b %d %H:%M:%S %Y GMT")

    subject_tuples = ((("commonName", subject_cn),),)
    issuer_tuples = ((("commonName", issuer_cn),),)
    san_list = [f"*.{subject_cn}", subject_cn] if sans is None else sans
    san_tuples = tuple(("DNS", s) for s in san_list)

    return {
        "notBefore": _fmt(not_before),
        "notAfter": _fmt(not_after),
        "subject": subject_tuples,
        "issuer": issuer_tuples,
        "subjectAltName": san_tuples,
    }


# ---------------------------------------------------------------------------
# parse_cert_dict unit tests (no network)
# ---------------------------------------------------------------------------

def test_parse_cert_dict_valid():
    raw = _make_cert(days_until_expiry=180, subject_cn="example.com", issuer_cn="Let's Encrypt")
    parsed = parse_cert_dict(raw)

    assert parsed["subject_cn"] == "example.com"
    assert parsed["issuer_cn"] == "Let's Encrypt"
    assert parsed["days_until_expiry"] is not None
    assert 170 < parsed["days_until_expiry"] <= 180
    assert parsed["is_self_signed"] is False
    assert parsed["has_wildcard"] is True  # "*.example.com" in default SANs


def test_parse_cert_dict_self_signed():
    raw = _make_cert(subject_cn="internal.example.com", issuer_cn="internal.example.com")
    parsed = parse_cert_dict(raw)
    assert parsed["is_self_signed"] is True


def test_parse_cert_dict_no_wildcard():
    raw = _make_cert(sans=["example.com", "www.example.com"])
    parsed = parse_cert_dict(raw)
    assert parsed["has_wildcard"] is False


def test_parse_cert_dict_wildcard():
    raw = _make_cert(sans=["*.example.com", "example.com"])
    parsed = parse_cert_dict(raw)
    assert parsed["has_wildcard"] is True


def test_parse_cert_dict_sans_lowercase():
    raw = _make_cert(sans=["API.Example.COM", "www.Example.com"])
    parsed = parse_cert_dict(raw)
    assert all(s == s.lower() for s in parsed["sans"])


def test_parse_cert_dict_expiry_near():
    raw = _make_cert(days_until_expiry=15)
    parsed = parse_cert_dict(raw)
    assert parsed["days_until_expiry"] <= 15


def test_parse_cert_dict_empty_san():
    raw = _make_cert(sans=[])
    parsed = parse_cert_dict(raw)
    assert parsed["sans"] == []
    assert parsed["has_wildcard"] is False


# ---------------------------------------------------------------------------
# run() — mode gating
# ---------------------------------------------------------------------------

def test_run_skipped_in_passive_mode():
    result = run("example.com", ["www.example.com"], mode="passive")
    assert result.status == "skipped"
    assert result.skipped_reason is not None
    assert "low-noise" in result.skipped_reason


# ---------------------------------------------------------------------------
# run() — full behaviour via _check_host_tls mock
# ---------------------------------------------------------------------------

def _make_host_result(host: str, days: int = 200, self_signed: bool = False, sans: list[str] | None = None, tls_ok: bool = True) -> dict:
    cert = {
        "subject_cn": host,
        "issuer_cn": host if self_signed else "Let's Encrypt",
        "days_until_expiry": days,
        "not_before": "2024-01-01T00:00:00+00:00",
        "not_after": "2025-01-01T00:00:00+00:00",
        "sans": sans or [host],
        "is_self_signed": self_signed,
        "has_wildcard": False,
    }
    return {"host": host, "error": None, "cert": cert, "tls_ok": tls_ok}


def test_run_valid_cert():
    with patch("osint_posture.modules.tls_profile._check_host_tls",
               side_effect=lambda host, **kw: _make_host_result(host)):
        result = run("example.com", ["www.example.com"], mode="low-noise")

    assert result.status == "ok"
    assert len(result.hosts) == 1
    assert result.hosts[0]["tls_ok"] is True


def test_run_self_signed_cert_captured():
    with patch("osint_posture.modules.tls_profile._check_host_tls",
               side_effect=lambda host, **kw: _make_host_result(host, self_signed=True, tls_ok=False)):
        result = run("example.com", ["portal.example.com"], mode="low-noise")

    assert result.status == "ok"
    assert result.hosts[0]["cert"]["is_self_signed"] is True


def test_run_san_extends_subdomains():
    san_list = ["api.example.com", "www.example.com", "cdn.example.com"]
    with patch("osint_posture.modules.tls_profile._check_host_tls",
               side_effect=lambda host, **kw: _make_host_result(host, sans=san_list)):
        result = run(
            "example.com",
            ["www.example.com"],  # only www known initially
            mode="low-noise",
        )

    # api and cdn are in scope but not in the input list → new subdomains
    assert "api.example.com" in result.new_subdomains_from_san
    assert "cdn.example.com" in result.new_subdomains_from_san
    assert "www.example.com" not in result.new_subdomains_from_san  # already known


def test_run_san_out_of_scope_ignored():
    san_list = ["api.other-domain.com", "www.example.com"]
    with patch("osint_posture.modules.tls_profile._check_host_tls",
               side_effect=lambda host, **kw: _make_host_result(host, sans=san_list)):
        result = run("example.com", ["www.example.com"], mode="low-noise")

    assert "api.other-domain.com" not in result.new_subdomains_from_san


def test_run_empty_candidates():
    result = run("example.com", [], mode="low-noise")
    assert result.status == "ok"
    assert result.hosts == []
    assert result.new_subdomains_from_san == []


def test_run_budget_warning_for_many_candidates():
    with patch("osint_posture.modules.tls_profile._check_host_tls",
               side_effect=lambda host, **kw: _make_host_result(host)):
        candidates = [f"sub{i}.example.com" for i in range(15)]
        result = run("example.com", candidates, mode="low-noise")

    assert any("budget" in w.lower() or "Only checked" in w for w in result.warnings)


def test_run_connection_error_captured():
    def _err(host, **kw):
        return {"host": host, "error": "connection refused", "cert": None, "tls_ok": False}

    with patch("osint_posture.modules.tls_profile._check_host_tls", side_effect=_err):
        result = run("example.com", ["www.example.com"], mode="low-noise")

    assert result.status == "ok"
    assert result.hosts[0]["error"] == "connection refused"
    assert result.hosts[0]["cert"] is None
