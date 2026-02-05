from __future__ import annotations

from ..models.results import SynthesisModuleResult


def score_email_posture(spf: dict, dmarc: dict, dkim: dict) -> tuple[int, list[str]]:
    score = 100
    notes = []
    if spf.get("raw") is None:
        score -= 25
        notes.append("No SPF record")
    if dmarc.get("raw") is None:
        score -= 35
        notes.append("No DMARC record")
    if dmarc.get("policy") in ("none", None):
        score -= 15
        notes.append("DMARC policy is none")
    if dkim.get("status") == "checked" and not dkim.get("found"):
        score -= 10
        notes.append("No DKIM selectors found in safe list")
    return max(score, 0), notes


def score_exposure(services: list[dict]) -> tuple[int, list[str]]:
    score = 100
    notes = []
    if services:
        score -= min(30, 5 * len(services))
        notes.append("Third-party intel shows exposed services")
    return max(score, 0), notes


def build_backlog(spf: dict, dmarc: dict, dkim: dict) -> list[dict]:
    backlog = []
    if spf.get("raw") is None:
        backlog.append(
            {
                "title": "Publish SPF record",
                "priority": "High",
                "evidence": "No SPF TXT record found",
                "remediation": "Create SPF record with authorized senders and -all",
            }
        )
    if dmarc.get("raw") is None:
        backlog.append(
            {
                "title": "Publish DMARC record",
                "priority": "High",
                "evidence": "No DMARC record found",
                "remediation": "Create DMARC with quarantine or reject",
            }
        )
    if dmarc.get("policy") == "none":
        backlog.append(
            {
                "title": "Enforce DMARC",
                "priority": "Medium",
                "evidence": "DMARC policy set to none",
                "remediation": "Move to quarantine/reject once reports are stable",
            }
        )
    if dkim.get("status") == "checked" and not dkim.get("found"):
        backlog.append(
            {
                "title": "Enable DKIM signing",
                "priority": "Medium",
                "evidence": "No DKIM selectors detected in safe list",
                "remediation": "Enable DKIM on outbound mail system",
            }
        )
    return backlog


def run(results: dict) -> SynthesisModuleResult:
    dns = results.get("dns_mail_profile", {})
    third_party = results.get("third_party_intel", {})

    spf = dns.get("spf", {})
    dmarc = dns.get("dmarc", {})
    dkim = dns.get("dkim", {})
    services = third_party.get("services", [])

    email_score, email_notes = score_email_posture(spf, dmarc, dkim)
    exposure_score, exposure_notes = score_exposure(services)

    scoring_rubric = {
        "email_posture": {
            "max": 100,
            "deductions": [
                "No SPF (-25)",
                "No DMARC (-35)",
                "DMARC policy none (-15)",
                "No DKIM selectors found in safe list (-10)",
            ],
        },
        "exposure": {
            "max": 100,
            "deductions": ["Exposed services from third-party intel (-5 each, up to -30)"]
        },
    }

    prioritized = build_backlog(spf, dmarc, dkim)

    summary = {
        "email_posture_score": email_score,
        "exposure_score": exposure_score,
        "email_notes": email_notes,
        "exposure_notes": exposure_notes,
    }

    spf_raw = spf.get("raw") or ""
    dmarc_raw = dmarc.get("raw") or ""
    evidence = {
        "dns_mail_profile": {
            "spf_raw": spf_raw[:300],
            "dmarc_raw": dmarc_raw[:300],
            "dkim_selectors_checked": dkim.get("selectors_checked", []),
        },
        "third_party_intel": third_party,
    }

    return SynthesisModuleResult(
        summary=summary,
        scoring_rubric=scoring_rubric,
        prioritized_backlog=prioritized,
        evidence=evidence,
    )
