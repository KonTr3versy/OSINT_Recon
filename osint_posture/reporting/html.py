from __future__ import annotations

from datetime import datetime
from html import escape


def build_html(findings: dict) -> str:
    summary = findings.get("summary", {})
    backlog = findings.get("prioritized_backlog", [])

    email_score = summary.get("email_posture_score", "n/a")
    exposure_score = summary.get("exposure_score", "n/a")
    email_notes = summary.get("email_notes", [])
    exposure_notes = summary.get("exposure_notes", [])

    def li(items: list[str]) -> str:
        if not items:
            return "<li>None</li>"
        return "".join(f"<li>{escape(str(x))}</li>" for x in items)

    backlog_rows = ""
    for item in backlog:
        backlog_rows += (
            "<tr>"
            f"<td>{escape(str(item.get('priority', '')))}</td>"
            f"<td>{escape(str(item.get('title', '')))}</td>"
            f"<td>{escape(str(item.get('evidence', '')))}</td>"
            f"<td>{escape(str(item.get('remediation', '')))}</td>"
            f"<td>{escape(str(item.get('source', '')))}</td>"
            f"<td>{escape(str(item.get('confidence', '')))}</td>"
            "</tr>"
        )

    generated = datetime.utcnow().isoformat()

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>OSINT Posture Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #222; }}
    h1, h2 {{ margin-bottom: 0.25rem; }}
    .meta {{ color: #666; margin-bottom: 1.5rem; }}
    .scores {{ display: flex; gap: 24px; margin-bottom: 1rem; }}
    .score {{ padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f7f7f7; }}
  </style>
</head>
<body>
  <h1>OSINT Posture Report</h1>
  <div class=\"meta\">Generated: {escape(generated)}</div>

  <h2>Scores</h2>
  <div class=\"scores\">
    <div class=\"score\"><strong>Email posture</strong><div>{escape(str(email_score))}</div></div>
    <div class=\"score\"><strong>Exposure</strong><div>{escape(str(exposure_score))}</div></div>
  </div>

  <h2>Findings</h2>
  <h3>Email notes</h3>
  <ul>{li(email_notes)}</ul>
  <h3>Exposure notes</h3>
  <ul>{li(exposure_notes)}</ul>

  <h2>Prioritized Remediation Backlog</h2>
  <table>
    <thead>
      <tr>
        <th>Priority</th>
        <th>Title</th>
        <th>Evidence</th>
        <th>Remediation</th>
        <th>Source</th>
        <th>Confidence</th>
      </tr>
    </thead>
    <tbody>
      {backlog_rows or '<tr><td colspan="6">No prioritized items.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""
