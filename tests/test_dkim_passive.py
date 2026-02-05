from osint_posture.modules.dns_mail_profile import check_dkim


def test_dkim_passive_note():
    dkim = check_dkim("example.com", enhanced=False)
    assert dkim["mode"] == "passive"
    assert "Passive mode" in dkim["note"]
