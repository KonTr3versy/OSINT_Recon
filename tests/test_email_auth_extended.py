from __future__ import annotations

import pytest

from osint_posture.modules.dns_mail_profile import (
    _extract_mx_hostnames,
    check_bimi,
    check_dane,
    check_mta_sts,
    check_tls_rpt,
    run,
)
from osint_posture.models.config import DnsPolicy, Mode


# ---------------------------------------------------------------------------
# Minimal DNS client stub
# ---------------------------------------------------------------------------

class _MockDnsClient:
    """Returns preconfigured responses per (name, type) key."""

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None) -> None:
        self._records = records or {}
        # Minimal policy stub so effective_policy check works
        self.policy = _Policy(DnsPolicy.full)

    def resolve_records(self, domain: str, record_type: str) -> list[str]:
        return self._records.get((domain, record_type), [])


class _Policy:
    def __init__(self, dns_policy: DnsPolicy) -> None:
        self.dns_policy = dns_policy


# ---------------------------------------------------------------------------
# check_mta_sts
# ---------------------------------------------------------------------------

def test_mta_sts_present():
    client = _MockDnsClient({("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=20230501T000000"']})
    result = check_mta_sts("example.com", client)
    assert result["present"] is True
    assert result["raw"] is not None


def test_mta_sts_absent():
    client = _MockDnsClient()
    result = check_mta_sts("example.com", client)
    assert result["present"] is False
    assert result["raw"] is None


def test_mta_sts_note_mentions_policy_file():
    client = _MockDnsClient()
    result = check_mta_sts("example.com", client)
    assert "mta-sts.example.com" in result["note"]


# ---------------------------------------------------------------------------
# check_tls_rpt
# ---------------------------------------------------------------------------

def test_tls_rpt_present_with_rua():
    recs = ['"v=TLSRPTv1; rua=mailto:tls@example.com"']
    client = _MockDnsClient({("_smtp._tls.example.com", "TXT"): recs})
    result = check_tls_rpt("example.com", client)
    assert result["present"] is True
    assert result["rua"] == "mailto:tls@example.com"


def test_tls_rpt_absent():
    client = _MockDnsClient()
    result = check_tls_rpt("example.com", client)
    assert result["present"] is False
    assert result["rua"] is None


# ---------------------------------------------------------------------------
# check_bimi
# ---------------------------------------------------------------------------

def test_bimi_present_with_location():
    recs = ['"v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/cert.pem"']
    client = _MockDnsClient({("default._bimi.example.com", "TXT"): recs})
    result = check_bimi("example.com", client)
    assert result["present"] is True
    assert result["location"] == "https://example.com/bimi.svg"
    assert result["authority"] == "https://example.com/cert.pem"


def test_bimi_absent():
    client = _MockDnsClient()
    result = check_bimi("example.com", client)
    assert result["present"] is False
    assert result["location"] is None


# ---------------------------------------------------------------------------
# _extract_mx_hostnames
# ---------------------------------------------------------------------------

def test_extract_mx_hostnames_standard():
    recs = ["10 mail.example.com.", "20 mail2.example.com."]
    hosts = _extract_mx_hostnames(recs)
    assert hosts == ["mail.example.com", "mail2.example.com"]


def test_extract_mx_hostnames_empty():
    assert _extract_mx_hostnames([]) == []


# ---------------------------------------------------------------------------
# check_dane
# ---------------------------------------------------------------------------

def test_dane_present():
    client = _MockDnsClient({
        ("_25._tcp.mail.example.com", "TLSA"): ["3 1 1 abc123"],
    })
    result = check_dane(["mail.example.com"], client)
    assert result["present"] is True
    assert len(result["hosts_with_dane"]) == 1
    assert result["hosts_with_dane"][0]["host"] == "mail.example.com"


def test_dane_absent():
    client = _MockDnsClient()
    result = check_dane(["mail.example.com"], client)
    assert result["present"] is False
    assert result["hosts_with_dane"] == []


def test_dane_caps_at_five_mx_hosts():
    client = _MockDnsClient()
    many_hosts = [f"mx{i}.example.com" for i in range(10)]
    result = check_dane(many_hosts, client)
    assert len(result["hosts_checked"]) == 5


# ---------------------------------------------------------------------------
# run() — extended fields present under full policy
# ---------------------------------------------------------------------------

def test_run_includes_extended_fields_full_policy():
    client = _MockDnsClient({
        ("example.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=1"'],
        ("_smtp._tls.example.com", "TXT"): ['"v=TLSRPTv1; rua=mailto:tls@example.com"'],
    })
    result = run("example.com", mode=Mode.passive, dns_client=client)
    assert "mta_sts" in result.model_dump()
    assert result.mta_sts["present"] is True
    assert result.tls_rpt["present"] is True


def test_run_extended_fields_skipped_under_minimal_policy():
    client = _MockDnsClient()
    client.policy = _Policy(DnsPolicy.minimal)
    result = run("example.com", mode=Mode.passive, dns_client=client)
    assert result.mta_sts.get("status") == "skipped"
    assert result.tls_rpt.get("status") == "skipped"
    assert result.bimi.get("status") == "skipped"
    assert result.dane.get("status") == "skipped"


def test_run_risk_flag_mta_sts_missing():
    client = _MockDnsClient({
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
    })
    result = run("example.com", mode=Mode.passive, dns_client=client)
    assert any("MTA-STS" in f for f in result.risk_flags)


def test_run_risk_flag_tls_rpt_missing_with_mta_sts():
    client = _MockDnsClient({
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
        ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=1"'],
        # TLS-RPT absent
    })
    result = run("example.com", mode=Mode.passive, dns_client=client)
    assert any("TLS-RPT" in f for f in result.risk_flags)


# ---------------------------------------------------------------------------
# synthesis scoring integration
# ---------------------------------------------------------------------------

def test_synthesis_scores_mta_sts_missing():
    from osint_posture.modules.synthesis import score_email_posture

    spf = {"raw": "v=spf1 -all"}
    dmarc = {"raw": "v=DMARC1; p=reject", "policy": "reject"}
    dkim = {"status": "unknown"}
    mta_sts = {"present": False, "status": "checked"}
    tls_rpt = {"present": False, "status": "checked"}

    score, notes, applied = score_email_posture(spf, dmarc, dkim, mta_sts, tls_rpt)
    ids = [r["id"] for r in applied]
    assert "email.mta_sts.missing" in ids
    assert score < 100


def test_synthesis_scores_tls_rpt_missing_only_when_mta_sts_present():
    from osint_posture.modules.synthesis import score_email_posture

    spf = {"raw": "v=spf1 -all"}
    dmarc = {"raw": "v=DMARC1; p=reject", "policy": "reject"}
    dkim = {"status": "unknown"}
    mta_sts = {"present": True, "status": "checked"}
    tls_rpt = {"present": False, "status": "checked"}

    score, notes, applied = score_email_posture(spf, dmarc, dkim, mta_sts, tls_rpt)
    ids = [r["id"] for r in applied]
    assert "email.tls_rpt.missing_with_mta_sts" in ids


def test_synthesis_no_tls_rpt_penalty_without_mta_sts():
    from osint_posture.modules.synthesis import score_email_posture

    spf = {"raw": "v=spf1 -all"}
    dmarc = {"raw": "v=DMARC1; p=reject", "policy": "reject"}
    dkim = {"status": "unknown"}
    mta_sts = {"present": False, "status": "checked"}
    tls_rpt = {"present": False, "status": "checked"}

    _, _, applied = score_email_posture(spf, dmarc, dkim, mta_sts, tls_rpt)
    ids = [r["id"] for r in applied]
    # TLS-RPT penalty should NOT apply when MTA-STS is absent
    assert "email.tls_rpt.missing_with_mta_sts" not in ids
