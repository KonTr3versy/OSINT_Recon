from osint_posture.reporting.csv_backlog import build_csv
from osint_posture.reporting.html import build_html
from osint_posture.reporting.markdown import build_summary


def test_reporting_outputs_basic_sections():
    findings = {
        "summary": {"email_posture_score": 80, "exposure_score": 90, "email_notes": []},
        "prioritized_backlog": [
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
    }
    md = build_summary(findings)
    csv_text = build_csv(findings)
    html = build_html(findings)
    assert "OSINT Posture Summary" in md
    assert "Publish SPF" in md
    assert "priority,title,evidence,remediation,source,confidence,evidence_ref" in csv_text
    assert "OSINT Posture Report" in html
    assert "dns_mail_profile" in html
