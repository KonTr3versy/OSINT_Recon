import asyncio

from osint_posture.cli import parse_mode_alias
from osint_posture.models.config import Mode
from osint_posture.modules.dns_mail_profile import check_dkim
from osint_posture.modules.doc_signals import run as doc_run
from osint_posture.modules.synthesis import build_backlog, score_exposure
from osint_posture.modules.web_signals import _check_security_headers, infer_tech_hints


def test_mode_enum_values():
    assert Mode.passive.value == "passive"
    assert Mode.low_noise.value == "low-noise"
    assert set(m.value for m in Mode) == {"passive", "low-noise"}


def test_mode_aliases_emit_deprecation(capsys):
    assert parse_mode_alias("enhanced") == Mode.low_noise
    assert parse_mode_alias("active") == Mode.low_noise
    err = capsys.readouterr().err
    assert "deprecated" in err


def test_dkim_low_noise_mode_sets_mode_field():
    dkim = check_dkim("nonexistent.invalid", mode=Mode.low_noise)
    assert dkim["mode"] == "low-noise"
    assert dkim["status"] == "checked"
    assert "Low-noise mode" in dkim["note"]


def test_dkim_passive_skips_selectors():
    dkim = check_dkim("example.com", mode=Mode.passive)
    assert dkim["mode"] == "passive"
    assert dkim["status"] == "unknown"
    assert dkim["selectors_checked"] == []
    assert dkim["found"] == []


def test_doc_signals_passive_returns_empty():
    result = asyncio.run(doc_run("example.com", [], _FakeHttp(), 10, mode="passive"))
    assert result.documents == []


def test_doc_signals_low_noise_calls_http():
    http = _FakeHttp()
    result = asyncio.run(doc_run("example.com", [], http, 10, mode="low-noise"))
    assert result.documents == []


def test_check_security_headers_all_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    result = _check_security_headers("https://example.com", headers)
    assert result["missing"] == []
    assert len(result["present"]) == 4


def test_check_security_headers_some_missing():
    headers = {"X-Frame-Options": "DENY"}
    result = _check_security_headers("https://example.com", headers)
    assert "x-frame-options" in result["present"]
    assert "strict-transport-security" in result["missing"]


def test_check_security_headers_none_present():
    result = _check_security_headers("https://example.com", {})
    assert len(result["missing"]) == 4
    assert result["present"] == []


def test_score_exposure_with_security_headers():
    security_headers = [
        {"url": "https://a.example.com", "missing": ["strict-transport-security"], "present": []},
        {"url": "https://b.example.com", "missing": ["strict-transport-security", "csp"], "present": []},
    ]
    score, notes, applied = score_exposure([], security_headers)
    assert score < 100
    assert any("security headers" in n.lower() for n in notes)


def test_build_backlog_includes_security_header_items():
    security_headers = [
        {
            "url": "https://example.com",
            "missing": ["strict-transport-security", "content-security-policy"],
            "present": ["x-frame-options"],
        },
    ]
    backlog = build_backlog(
        {"raw": "v=spf1 -all"}, {"raw": "v=DMARC1; p=reject", "policy": "reject"}, {}, security_headers
    )
    header_items = [b for b in backlog if "security headers" in b["title"].lower()]
    assert len(header_items) == 1


def test_infer_tech_hints():
    hints = infer_tech_hints(["login.example.com", "mail.example.com", "api.example.com"])
    assert any("SSO" in h for h in hints)
    assert any("Mail" in h for h in hints)


class _FakeHttp:
    async def head(self, url, **kwargs):
        raise ConnectionError("fake")
