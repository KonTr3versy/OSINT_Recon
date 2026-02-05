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
    assert "spf_raw" in synth.evidence["dns_mail_profile"]
    assert "rules" in synth.scoring_rubric["email_posture"]
    assert "applied_rules" in synth.scoring_rubric["email_posture"]
    assert any(
        rule["id"] == "email.spf.missing"
        for rule in synth.scoring_rubric["email_posture"]["applied_rules"]
    )
    assert synth.evidence["dns_mail_profile"]["provenance"]["source"] == "dns_mail_profile"
    assert synth.prioritized_backlog[0]["confidence"] in {"high", "medium", "low"}
    assert "evidence_ref" in synth.prioritized_backlog[0]
