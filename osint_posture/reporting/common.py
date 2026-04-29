from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generated_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def score_band(score: Any) -> str:
    if not isinstance(score, int | float):
        return "Unknown"
    if score >= 90:
        return "Strong"
    if score >= 70:
        return "Moderate"
    if score >= 50:
        return "Needs attention"
    return "High risk"


def score_items(summary: dict) -> list[dict]:
    return [
        {
            "label": "Email posture",
            "score": summary.get("email_posture_score", "n/a"),
            "band": score_band(summary.get("email_posture_score")),
        },
        {
            "label": "Exposure",
            "score": summary.get("exposure_score", "n/a"),
            "band": score_band(summary.get("exposure_score")),
        },
    ]


def sorted_backlog(backlog: list[dict]) -> list[dict]:
    return sorted(
        backlog,
        key=lambda item: (
            PRIORITY_ORDER.get(str(item.get("priority", "")).lower(), 99),
            str(item.get("title", "")).lower(),
        ),
    )


def backlog_counts(backlog: list[dict]) -> dict[str, int]:
    counts = Counter(str(item.get("priority", "Unspecified")) for item in backlog)
    return dict(sorted(counts.items(), key=lambda item: PRIORITY_ORDER.get(item[0].lower(), 99)))


def applied_scoring_rules(scoring_rubric: dict) -> list[dict]:
    rows: list[dict] = []
    for category, detail in scoring_rubric.items():
        for rule in detail.get("applied_rules", []):
            rows.append(
                {
                    "category": category.replace("_", " ").title(),
                    "id": rule.get("id", ""),
                    "label": rule.get("label", ""),
                    "deduction": rule.get("deduction", ""),
                    "evidence_ref": rule.get("evidence_ref", ""),
                }
            )
    return rows


def evidence_snapshot(evidence: dict) -> list[dict]:
    dns = evidence.get("dns_mail_profile", {})
    third_party = evidence.get("third_party_intel", {})
    users = evidence.get("passive_users", {})
    web = evidence.get("web_signals", {})

    spf_status = "present" if dns.get("spf_raw") else "missing"
    dmarc_status = "present" if dns.get("dmarc_raw") else "missing"
    dkim_checked = len(dns.get("dkim_selectors_checked", []) or [])
    services = len(third_party.get("services", []) or [])
    passive_users = len(users.get("users", []) or [])
    header_samples = len(web.get("security_headers", []) or [])

    return [
        {"label": "SPF", "value": spf_status, "source": "dns_mail_profile"},
        {"label": "DMARC", "value": dmarc_status, "source": "dns_mail_profile"},
        {"label": "DKIM selectors checked", "value": dkim_checked, "source": "dns_mail_profile"},
        {"label": "Third-party services", "value": services, "source": "third_party_intel"},
        {"label": "Passive user candidates", "value": passive_users, "source": "passive_users"},
        {"label": "Security-header samples", "value": header_samples, "source": "web_signals"},
    ]

