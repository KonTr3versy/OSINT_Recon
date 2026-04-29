from osint_posture.reporting.csv_backlog import build_csv
from osint_posture.reporting.html import build_html
from osint_posture.reporting.markdown import build_summary


def test_reporting_outputs_basic_sections():
    findings = {
        "summary": {
            "email_posture_score": 80,
            "exposure_score": 90,
            "email_notes": ["No SPF record"],
            "exposure_notes": [],
        },
        "scoring_rubric": {
            "email_posture": {
                "applied_rules": [
                    {
                        "id": "email.spf.missing",
                        "label": "No SPF record",
                        "deduction": 25,
                        "evidence_ref": "evidence.dns_mail_profile.spf_raw",
                    }
                ]
            }
        },
        "prioritized_backlog": [
            {
                "priority": "Medium",
                "title": "Enable DKIM",
                "evidence": "No DKIM selector",
                "remediation": "Enable DKIM",
                "source": "dns_mail_profile",
                "confidence": "medium",
                "evidence_ref": "evidence.dns_mail_profile.dkim_selectors_checked",
            },
            {
                "priority": "High",
                "title": "Publish SPF",
                "evidence": "No SPF",
                "remediation": "Add SPF",
                "source": "dns_mail_profile",
                "confidence": "high",
                "evidence_ref": "evidence.dns_mail_profile.spf_raw",
            }
        ],
        "evidence": {
            "dns_mail_profile": {
                "spf_raw": "",
                "dmarc_raw": "v=DMARC1; p=quarantine",
                "dkim_selectors_checked": ["default"],
            },
            "third_party_intel": {"services": []},
            "passive_users": {"users": []},
            "web_signals": {"security_headers": []},
        },
    }
    md = build_summary(findings)
    csv_text = build_csv(findings)
    html = build_html(findings)
    assert "OSINT Posture Summary" in md
    assert "Executive Overview" in md
    assert "Scoring Rationale" in md
    assert "Evidence Snapshot" in md
    assert "Publish SPF" in md
    assert md.index("High | Publish SPF") < md.index("Medium | Enable DKIM")
    assert "priority,title,evidence,remediation,source,confidence,evidence_ref" in csv_text
    assert "OSINT Posture Report" in html
    assert "Executive Overview" in html
    assert "Scoring Rationale" in html
    assert "Evidence Snapshot" in html
    assert "dns_mail_profile" in html
