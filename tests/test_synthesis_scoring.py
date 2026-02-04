from osint_posture.modules.synthesis import run


def test_synthesis_scores_penalties():
    results = {
        "dns_mail_profile": {
            "spf": {"raw": None},
            "dmarc": {"raw": None, "policy": None},
            "dkim": {"status": "checked", "found": []},
        },
        "third_party_intel": {"services": [{"host": "1.2.3.4"}]},
    }
    synth = run(results)
    assert synth.summary["email_posture_score"] < 100
    assert synth.summary["exposure_score"] < 100
