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


def test_synthesis_with_security_headers():
    results = {
        "dns_mail_profile": {
            "spf": {"raw": "v=spf1 -all"},
            "dmarc": {"raw": "v=DMARC1; p=reject", "policy": "reject", "rua": "mailto:d@e.com"},
            "dkim": {"status": "unknown"},
        },
        "third_party_intel": {"services": []},
        "web_signals": {
            "security_headers": [
                {
                    "url": "https://www.example.com",
                    "missing": ["strict-transport-security", "content-security-policy"],
                    "present": ["x-frame-options", "x-content-type-options"],
                }
            ]
        },
    }
    synth = run(results)
    assert synth.summary["exposure_score"] < 100
    assert any(
        rule["id"] == "exposure.web.missing_security_headers"
        for rule in synth.scoring_rubric["exposure"]["applied_rules"]
    )
    assert "web_signals" in synth.evidence
    header_backlog = [b for b in synth.prioritized_backlog if "security headers" in b["title"].lower()]
    assert len(header_backlog) == 1
