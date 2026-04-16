from __future__ import annotations

from datetime import datetime, timezone

from ..models.results import SynthesisModuleResult


def _score_from_rules(max_score: int, rules: list[dict]) -> tuple[int, list[str], list[dict]]:
    score = max_score
    notes: list[str] = []
    applied: list[dict] = []
    for rule in rules:
        if rule["triggered"]:
            score -= int(rule["deduction"])
            notes.append(rule["label"])
            applied.append(
                {
                    "id": rule["id"],
                    "label": rule["label"],
                    "deduction": rule["deduction"],
                    "evidence_ref": rule["evidence_ref"],
                }
            )
    return max(score, 0), notes, applied


def score_email_posture(spf: dict, dmarc: dict, dkim: dict) -> tuple[int, list[str], list[dict]]:
    rules = [
        {
            "id": "email.spf.missing",
            "label": "No SPF record",
            "deduction": 25,
            "triggered": spf.get("raw") is None,
            "evidence_ref": "evidence.dns_mail_profile.spf_raw",
        },
        {
            "id": "email.dmarc.missing",
            "label": "No DMARC record",
            "deduction": 35,
            "triggered": dmarc.get("raw") is None,
            "evidence_ref": "evidence.dns_mail_profile.dmarc_raw",
        },
        {
            "id": "email.dmarc.policy_none",
            "label": "DMARC policy is none",
            "deduction": 15,
            "triggered": dmarc.get("policy") in ("none", None),
            "evidence_ref": "evidence.dns_mail_profile.dmarc_raw",
        },
        {
            "id": "email.dkim.not_detected_safe_list",
            "label": "No DKIM selectors found in safe list",
            "deduction": 10,
            "triggered": dkim.get("status") == "checked" and not dkim.get("found"),
            "evidence_ref": "evidence.dns_mail_profile.dkim_selectors_checked",
        },
    ]
    return _score_from_rules(100, rules)


def score_exposure(
    services: list[dict],
    security_headers: list[dict] | None = None,
    takeover_candidates: list[dict] | None = None,
    tls_hosts: list[dict] | None = None,
) -> tuple[int, list[str], list[dict]]:
    service_count = len(services or [])
    exposure_deduction = min(30, 5 * service_count)

    sites_missing_headers = 0
    if security_headers:
        sites_missing_headers = sum(1 for sh in security_headers if sh.get("missing"))
    header_deduction = min(20, 5 * sites_missing_headers)

    nxdomain_count = sum(1 for c in (takeover_candidates or []) if c.get("nxdomain"))
    takeover_deduction = min(40, 20 * nxdomain_count)

    self_signed_count = sum(
        1 for h in (tls_hosts or []) if (h.get("cert") or {}).get("is_self_signed")
    )
    tls_self_signed_deduction = min(30, 15 * self_signed_count)

    expiring_count = sum(
        1
        for h in (tls_hosts or [])
        if (h.get("cert") or {}).get("days_until_expiry") is not None
        and (h.get("cert") or {})["days_until_expiry"] <= 30
    )
    tls_expiry_deduction = min(20, 10 * expiring_count)

    rules = [
        {
            "id": "exposure.third_party.services_detected",
            "label": "Third-party intel shows exposed services",
            "deduction": exposure_deduction,
            "triggered": service_count > 0,
            "evidence_ref": "evidence.third_party_intel.services",
        },
        {
            "id": "exposure.web.missing_security_headers",
            "label": "Web portals missing security headers",
            "deduction": header_deduction,
            "triggered": sites_missing_headers > 0,
            "evidence_ref": "evidence.web_signals.security_headers",
        },
        {
            "id": "exposure.takeover.nxdomain_candidates",
            "label": "Potential subdomain takeover (NXDOMAIN CNAME)",
            "deduction": takeover_deduction,
            "triggered": nxdomain_count > 0,
            "evidence_ref": "evidence.takeover_signals.candidates",
        },
        {
            "id": "exposure.tls.self_signed_cert",
            "label": "Self-signed TLS certificate on public portal",
            "deduction": tls_self_signed_deduction,
            "triggered": self_signed_count > 0,
            "evidence_ref": "evidence.tls_profile.hosts",
        },
        {
            "id": "exposure.tls.cert_expiring_soon",
            "label": "TLS certificate expiring within 30 days",
            "deduction": tls_expiry_deduction,
            "triggered": expiring_count > 0,
            "evidence_ref": "evidence.tls_profile.hosts",
        },
    ]
    return _score_from_rules(100, rules)


def build_backlog(
    spf: dict,
    dmarc: dict,
    dkim: dict,
    security_headers: list[dict] | None = None,
    takeover_candidates: list[dict] | None = None,
    tls_hosts: list[dict] | None = None,
) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    backlog = []
    if spf.get("raw") is None:
        backlog.append(
            {
                "title": "Publish SPF record",
                "priority": "High",
                "evidence": "No SPF TXT record found",
                "remediation": "Create SPF record with authorized senders and -all",
                "source": "dns_mail_profile",
                "confidence": "high",
                "last_verified_at": now,
                "evidence_ref": "evidence.dns_mail_profile.spf_raw",
            }
        )
    if dmarc.get("raw") is None:
        backlog.append(
            {
                "title": "Publish DMARC record",
                "priority": "High",
                "evidence": "No DMARC record found",
                "remediation": "Create DMARC with quarantine or reject",
                "source": "dns_mail_profile",
                "confidence": "high",
                "last_verified_at": now,
                "evidence_ref": "evidence.dns_mail_profile.dmarc_raw",
            }
        )
    if dmarc.get("policy") == "none":
        backlog.append(
            {
                "title": "Enforce DMARC",
                "priority": "Medium",
                "evidence": "DMARC policy set to none",
                "remediation": "Move to quarantine/reject once reports are stable",
                "source": "dns_mail_profile",
                "confidence": "high",
                "last_verified_at": now,
                "evidence_ref": "evidence.dns_mail_profile.dmarc_raw",
            }
        )
    if dkim.get("status") == "checked" and not dkim.get("found"):
        backlog.append(
            {
                "title": "Enable DKIM signing",
                "priority": "Medium",
                "evidence": "No DKIM selectors detected in safe list",
                "remediation": "Enable DKIM on outbound mail system",
                "source": "dns_mail_profile",
                "confidence": "medium",
                "last_verified_at": now,
                "evidence_ref": "evidence.dns_mail_profile.dkim_selectors_checked",
            }
        )
    for sh in security_headers or []:
        missing = sh.get("missing", [])
        if missing:
            backlog.append(
                {
                    "title": f"Add missing security headers on {sh['url']}",
                    "priority": "Medium",
                    "evidence": f"Missing headers: {', '.join(missing)}",
                    "remediation": "Configure web server to send " + ", ".join(missing),
                    "source": "web_signals",
                    "confidence": "high",
                    "last_verified_at": now,
                    "evidence_ref": "evidence.web_signals.security_headers",
                }
            )

    for candidate in takeover_candidates or []:
        sub = candidate.get("subdomain", "")
        service = candidate.get("service", "unknown service")
        cname_target = candidate.get("cname_target", "")
        confidence = candidate.get("confidence", "medium")
        priority = candidate.get("priority", "Medium")
        if candidate.get("nxdomain"):
            evidence = f"{sub} CNAME → {cname_target} (NXDOMAIN — unclaimed {service} resource)"
            remediation = (
                f"Remove the CNAME record for {sub} or reclaim the {service} resource "
                "immediately; an attacker can host content under your subdomain."
            )
        else:
            evidence = f"{sub} CNAME → {cname_target} ({service})"
            remediation = (
                f"Verify that the {service} resource at {cname_target} is owned and active; "
                f"if decommissioned, remove the CNAME for {sub}."
            )
        backlog.append(
            {
                "title": f"Investigate subdomain takeover risk: {sub}",
                "priority": priority,
                "evidence": evidence,
                "remediation": remediation,
                "source": "takeover_signals",
                "confidence": confidence,
                "last_verified_at": now,
                "evidence_ref": "evidence.takeover_signals.candidates",
            }
        )

    for h in tls_hosts or []:
        host = h.get("host", "")
        cert = h.get("cert") or {}
        days = cert.get("days_until_expiry")
        if cert.get("is_self_signed"):
            backlog.append(
                {
                    "title": f"Replace self-signed certificate on {host}",
                    "priority": "High",
                    "evidence": f"{host} presented a self-signed TLS certificate",
                    "remediation": (
                        "Replace with a certificate from a trusted CA (e.g. Let's Encrypt). "
                        "Browsers will warn users and block automated clients."
                    ),
                    "source": "tls_profile",
                    "confidence": "high",
                    "last_verified_at": now,
                    "evidence_ref": "evidence.tls_profile.hosts",
                }
            )
        elif days is not None and days <= 30:
            backlog.append(
                {
                    "title": f"Certificate expiring in {days} day(s) on {host}",
                    "priority": "High",
                    "evidence": f"TLS certificate for {host} expires in {days} days",
                    "remediation": f"Renew the TLS certificate for {host} immediately.",
                    "source": "tls_profile",
                    "confidence": "high",
                    "last_verified_at": now,
                    "evidence_ref": "evidence.tls_profile.hosts",
                }
            )
        elif days is not None and days <= 90:
            backlog.append(
                {
                    "title": f"Certificate expiring within 90 days on {host}",
                    "priority": "Medium",
                    "evidence": f"TLS certificate for {host} expires in {days} days",
                    "remediation": f"Schedule renewal of the TLS certificate for {host}.",
                    "source": "tls_profile",
                    "confidence": "high",
                    "last_verified_at": now,
                    "evidence_ref": "evidence.tls_profile.hosts",
                }
            )

    return backlog


def run(results: dict) -> SynthesisModuleResult:
    dns = results.get("dns_mail_profile", {})
    third_party = results.get("third_party_intel", {})
    web = results.get("web_signals", {})
    users = results.get("passive_users", {})
    takeover = results.get("takeover_signals", {})
    tls = results.get("tls_profile", {})

    spf = dns.get("spf", {})
    dmarc = dns.get("dmarc", {})
    dkim = dns.get("dkim", {})
    services = third_party.get("services", [])
    security_headers = web.get("security_headers", [])
    takeover_candidates = takeover.get("candidates", [])
    tls_hosts = tls.get("hosts", [])

    email_score, email_notes, email_applied_rules = score_email_posture(spf, dmarc, dkim)
    exposure_score, exposure_notes, exposure_applied_rules = score_exposure(
        services, security_headers, takeover_candidates, tls_hosts
    )

    scoring_rubric = {
        "email_posture": {
            "max": 100,
            "rules": [
                {
                    "id": "email.spf.missing",
                    "label": "No SPF record",
                    "deduction": 25,
                    "evidence_ref": "evidence.dns_mail_profile.spf_raw",
                },
                {
                    "id": "email.dmarc.missing",
                    "label": "No DMARC record",
                    "deduction": 35,
                    "evidence_ref": "evidence.dns_mail_profile.dmarc_raw",
                },
                {
                    "id": "email.dmarc.policy_none",
                    "label": "DMARC policy is none",
                    "deduction": 15,
                    "evidence_ref": "evidence.dns_mail_profile.dmarc_raw",
                },
                {
                    "id": "email.dkim.not_detected_safe_list",
                    "label": "No DKIM selectors found in safe list",
                    "deduction": 10,
                    "evidence_ref": "evidence.dns_mail_profile.dkim_selectors_checked",
                },
            ],
            "applied_rules": email_applied_rules,
        },
        "exposure": {
            "max": 100,
            "rules": [
                {
                    "id": "exposure.third_party.services_detected",
                    "label": "Third-party intel shows exposed services",
                    "deduction_formula": "min(30, 5 * service_count)",
                    "evidence_ref": "evidence.third_party_intel.services",
                },
                {
                    "id": "exposure.web.missing_security_headers",
                    "label": "Web portals missing security headers",
                    "deduction_formula": "min(20, 5 * sites_missing_headers)",
                    "evidence_ref": "evidence.web_signals.security_headers",
                },
                {
                    "id": "exposure.takeover.nxdomain_candidates",
                    "label": "Potential subdomain takeover (NXDOMAIN CNAME)",
                    "deduction_formula": "min(40, 20 * nxdomain_count)",
                    "evidence_ref": "evidence.takeover_signals.candidates",
                },
                {
                    "id": "exposure.tls.self_signed_cert",
                    "label": "Self-signed TLS certificate on public portal",
                    "deduction_formula": "min(30, 15 * self_signed_count)",
                    "evidence_ref": "evidence.tls_profile.hosts",
                },
                {
                    "id": "exposure.tls.cert_expiring_soon",
                    "label": "TLS certificate expiring within 30 days",
                    "deduction_formula": "min(20, 10 * expiring_count)",
                    "evidence_ref": "evidence.tls_profile.hosts",
                },
            ],
            "applied_rules": exposure_applied_rules,
        },
    }

    prioritized = build_backlog(spf, dmarc, dkim, security_headers, takeover_candidates, tls_hosts)

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
            "provenance": {
                "source": "dns_mail_profile",
                "confidence": "high",
                "last_verified_at": datetime.now(timezone.utc).isoformat(),
            },
        },
        "third_party_intel": third_party,
        "passive_users": users,
        "tls_profile": {
            "hosts": tls_hosts,
            "new_subdomains_from_san": tls.get("new_subdomains_from_san", []),
            "provenance": {
                "source": "tls_profile",
                "confidence": "high",
                "last_verified_at": datetime.now(timezone.utc).isoformat(),
            },
        },
        "takeover_signals": {
            "candidates": takeover_candidates,
            "provenance": {
                "source": "takeover_signals",
                "confidence": "high",
                "last_verified_at": datetime.now(timezone.utc).isoformat(),
            },
        },
        "web_signals": {
            "security_headers": security_headers,
            "provenance": {
                "source": "web_signals",
                "confidence": "high",
                "last_verified_at": datetime.now(timezone.utc).isoformat(),
            },
        },
    }

    return SynthesisModuleResult(
        summary=summary,
        scoring_rubric=scoring_rubric,
        prioritized_backlog=prioritized,
        evidence=evidence,
    )
