from osint_posture.modules.dns_mail_profile import parse_dmarc


def test_dmarc_policy_none_warning():
    dmarc = parse_dmarc(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])
    assert dmarc["policy"] == "none"
    assert any("policy is none" in w for w in dmarc["warnings"])


def test_dmarc_invalid_policy_and_pct():
    dmarc = parse_dmarc(["v=DMARC1; p=invalid; pct=999; rua=mailto:dmarc@example.com"])
    assert dmarc["valid"] is False
    assert "p" in dmarc["invalid_tags"]
    assert "pct" in dmarc["invalid_tags"]


def test_dmarc_missing_rua_when_enforcing():
    dmarc = parse_dmarc(["v=DMARC1; p=reject"])
    assert any("rua" in w for w in dmarc["warnings"])
