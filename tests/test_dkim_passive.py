from osint_posture.models.config import Mode
from osint_posture.modules.dns_mail_profile import check_dkim


def test_dkim_passive_note():
    dkim = check_dkim("example.com", mode=Mode.passive)
    assert dkim["mode"] == "passive"
    assert "Passive mode" in dkim["note"]
    assert dkim["status"] == "unknown"
    assert dkim["selectors_checked"] == []
