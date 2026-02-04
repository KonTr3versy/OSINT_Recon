from osint_posture.modules.dns_mail_profile import parse_spf


def test_spf_softfail_warning():
    spf = parse_spf(["v=spf1 include:_spf.example.com ~all"])
    assert spf["all"] == "~all"
    assert any("softfail" in w for w in spf["warnings"])


def test_spf_missing():
    spf = parse_spf(["some text"])
    assert spf["raw"] is None
    assert any("No SPF" in w for w in spf["warnings"])
