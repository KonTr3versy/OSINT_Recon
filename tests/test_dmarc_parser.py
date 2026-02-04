from osint_posture.modules.dns_mail_profile import parse_dmarc


def test_dmarc_policy_none_warning():
    dmarc = parse_dmarc(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])
    assert dmarc["policy"] == "none"
    assert any("policy is none" in w for w in dmarc["warnings"])
