from __future__ import annotations

from .common import (
    applied_scoring_rules,
    backlog_counts,
    evidence_snapshot,
    generated_at,
    score_items,
    sorted_backlog,
    subdomain_attribution,
    subdomain_items,
)


def build_summary(findings: dict) -> str:
    summary = findings.get("summary", {})
    backlog = findings.get("prioritized_backlog", [])
    scoring_rubric = findings.get("scoring_rubric", {})
    evidence = findings.get("evidence", {})
    sorted_items = sorted_backlog(backlog)

    lines = ["# OSINT Posture Summary", "", f"Generated: {generated_at()}", ""]

    lines.append("## Executive Overview")
    for item in score_items(summary):
        lines.append(f"- {item['label']}: {item['score']} ({item['band']})")
    counts = backlog_counts(backlog)
    if counts:
        rendered_counts = ", ".join(f"{count} {priority}" for priority, count in counts.items())
        lines.append(f"- Remediation backlog: {len(backlog)} item(s) ({rendered_counts})")
    else:
        lines.append("- Remediation backlog: 0 item(s)")
    lines.append("")

    lines.append("## Findings")
    notes = [*summary.get("email_notes", []), *summary.get("exposure_notes", [])]
    if notes:
        for note in notes:
            lines.append(f"- {note}")
    else:
        lines.append("- No score-impacting findings were identified.")
    lines.append("")

    lines.append("## Scoring Rationale")
    applied_rules = applied_scoring_rules(scoring_rubric)
    if not applied_rules:
        lines.append("- No scoring deductions were applied.")
    for rule in applied_rules:
        lines.append(
            f"- {rule['category']} | -{rule['deduction']}: {rule['label']} "
            f"({rule['evidence_ref']})"
        )
    lines.append("")

    lines.append("## Evidence Snapshot")
    for item in evidence_snapshot(evidence):
        lines.append(f"- {item['label']}: {item['value']} (source={item['source']})")
    lines.append("")

    lines.append("## Discovered Subdomains")
    subdomains = subdomain_items(findings)
    attribution = subdomain_attribution(findings)
    if not subdomains:
        lines.append("- No subdomains were discovered from passive sources.")
    else:
        per_source = attribution.get("per_source_counts", {})
        if per_source:
            rendered_counts = ", ".join(f"{source}: {count}" for source, count in per_source.items())
            lines.append(f"- Source counts: {rendered_counts}")
        warnings = attribution.get("warnings", [])
        if warnings:
            for warning in warnings:
                lines.append(f"- Source warning: {warning}")
        for subdomain in subdomains:
            lines.append(f"- {subdomain}")
    lines.append("")

    lines.append("## Prioritized Remediation Backlog")
    if not sorted_items:
        lines.append("- No prioritized items.")
    for item in sorted_items:
        source = item.get("source", "unknown")
        confidence = item.get("confidence", "unknown")
        lines.append(f"### {item.get('priority', 'Unspecified')} | {item.get('title', 'Untitled')}")
        lines.append(f"- Evidence: {item.get('evidence', 'n/a')}")
        lines.append(f"- Remediation: {item.get('remediation', 'n/a')}")
        lines.append(f"- Source: {source}")
        lines.append(f"- Confidence: {confidence}")
        if item.get("evidence_ref"):
            lines.append(f"- Evidence ref: {item['evidence_ref']}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
