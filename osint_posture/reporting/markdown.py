from __future__ import annotations

from datetime import datetime


def build_summary(findings: dict) -> str:
    summary = findings.get("summary", {})
    backlog = findings.get("prioritized_backlog", [])

    lines = ["# OSINT Posture Summary", "", f"Generated: {datetime.utcnow().isoformat()}", ""]
    lines.append("## Scores")
    lines.append(f"- Email posture: {summary.get('email_posture_score', 'n/a')}")
    lines.append(f"- Exposure: {summary.get('exposure_score', 'n/a')}")
    lines.append("")

    lines.append("## Findings")
    for note in summary.get("email_notes", []):
        lines.append(f"- {note}")
    for note in summary.get("exposure_notes", []):
        lines.append(f"- {note}")
    lines.append("")

    lines.append("## Prioritized Remediation Backlog")
    if not backlog:
        lines.append("- No prioritized items.")
    for item in backlog:
        lines.append(f"- {item.get('priority')} | {item.get('title')}: {item.get('remediation')}")

    return "\n".join(lines)
