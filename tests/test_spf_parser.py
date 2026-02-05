from osint_posture.modules.dns_mail_profile import parse_spf


def test_spf_softfail_warning():
    spf = parse_spf(["v=spf1 include:_spf.example.com ~all"])
    assert spf["all"] == "~all"
    assert any("softfail" in w for w in spf["warnings"])


def test_spf_missing():
    spf = parse_spf(["some text"])
    assert spf["raw"] is None
    assert any("No SPF" in w for w in spf["warnings"])


def test_spf_redirect_exp_and_broad_ip():
    spf = parse_spf(["v=spf1 ip4:0.0.0.0/0 include:_spf.example.com redirect=example.com exp=explain.example.com -all"])
    assert spf["redirect"] == "example.com"
    assert spf["exp"] == "explain.example.com"
    assert spf["has_overly_broad_ip"] is True
    assert any("overly broad" in w for w in spf["warnings"])
