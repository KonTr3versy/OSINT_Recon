from __future__ import annotations

from html import escape

from .common import (
    applied_scoring_rules,
    backlog_counts,
    evidence_snapshot,
    generated_at,
    score_items,
    sorted_backlog,
    subdomain_attribution,
    subdomain_items,
    technology_fingerprints,
    verified_surface,
    well_known_metadata,
)


def build_html(findings: dict) -> str:
    summary = findings.get("summary", {})
    backlog = findings.get("prioritized_backlog", [])
    scoring_rubric = findings.get("scoring_rubric", {})
    evidence = findings.get("evidence", {})
    scores = score_items(summary)
    counts = backlog_counts(backlog)
    applied_rules = applied_scoring_rules(scoring_rubric)
    snapshot = evidence_snapshot(evidence)
    subdomains = subdomain_items(findings)
    subdomain_sources = subdomain_attribution(findings)
    notes = [*summary.get("email_notes", []), *summary.get("exposure_notes", [])]

    def li(items: list[str]) -> str:
        if not items:
            return "<li>No score-impacting findings were identified.</li>"
        return "".join(f"<li>{escape(str(x))}</li>" for x in items)

    score_cards = "".join(
        "<div class=\"score\">"
        f"<span>{escape(item['label'])}</span>"
        f"<strong>{escape(str(item['score']))}</strong>"
        f"<em>{escape(item['band'])}</em>"
        "</div>"
        for item in scores
    )

    count_pills = "".join(
        f"<span class=\"pill\">{escape(priority)}: {count}</span>"
        for priority, count in counts.items()
    ) or "<span class=\"pill\">No backlog items</span>"

    evidence_rows = "".join(
        "<tr>"
        f"<td>{escape(item['label'])}</td>"
        f"<td>{escape(str(item['value']))}</td>"
        f"<td>{escape(item['source'])}</td>"
        "</tr>"
        for item in snapshot
    )

    scoring_rows = "".join(
        "<tr>"
        f"<td>{escape(str(rule['category']))}</td>"
        f"<td>{escape(str(rule['label']))}</td>"
        f"<td>{escape(str(rule['deduction']))}</td>"
        f"<td>{escape(str(rule['evidence_ref']))}</td>"
        "</tr>"
        for rule in applied_rules
    )

    subdomain_source_counts = subdomain_sources.get("per_source_counts", {})
    subdomain_source_html = "".join(
        f"<span class=\"pill\">{escape(str(source))}: {escape(str(count))}</span>"
        for source, count in subdomain_source_counts.items()
    ) or "<span class=\"pill\">No passive source counts</span>"
    subdomain_warnings = "".join(
        f"<li>{escape(str(warning))}</li>"
        for warning in subdomain_sources.get("warnings", [])
    )
    subdomain_rows = "".join(
        f"<tr><td>{escape(subdomain)}</td></tr>"
        for subdomain in subdomains
    )
    verified = verified_surface(findings)
    verified_rows = "".join(
        "<tr>"
        f"<td>{escape(str(item.get('url', item.get('host', ''))))}</td>"
        f"<td>{escape(str(item.get('method', 'HEAD')))}</td>"
        f"<td>{escape(str(item.get('status', 'unknown')))}</td>"
        "</tr>"
        for item in verified.get("hosts", []) if isinstance(item, dict)
    )
    well_known = well_known_metadata(findings)
    well_known_rows = "".join(
        "<tr>"
        f"<td>{escape(str(item.get('url', '')))}</td>"
        f"<td>{escape(str(item.get('status', 'unknown')))}</td>"
        f"<td>{escape(str(item.get('content_type', '')))}</td>"
        "</tr>"
        for item in well_known.get("checks", []) if isinstance(item, dict)
    )
    fingerprints = technology_fingerprints(findings)
    fingerprint_rows = "".join(
        "<tr>"
        f"<td>{escape(str(item.get('technology', '')))}</td>"
        f"<td>{escape(str(item.get('source', '')))}</td>"
        f"<td>{escape(str(item.get('evidence', '')))}</td>"
        "</tr>"
        for item in fingerprints.get("hints", []) if isinstance(item, dict)
    )

    backlog_rows = ""
    for item in sorted_backlog(backlog):
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

    generated = generated_at()

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>OSINT Posture Report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #172026;
      --muted: #5f6b73;
      --line: #d8dee3;
      --panel: #f6f8f9;
      --accent: #0f6b6e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: Arial, sans-serif;
      line-height: 1.45;
      margin: 0;
      color: var(--ink);
      background: #fff;
    }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px; }}
    h1, h2 {{ margin: 0 0 0.45rem; }}
    h1 {{ font-size: 2rem; }}
    h2 {{ font-size: 1.25rem; padding-top: 1.2rem; border-top: 1px solid var(--line); }}
    .meta {{ color: var(--muted); margin-bottom: 1.5rem; }}
    .scores {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 1rem 0; }}
    .score {{ padding: 14px 16px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); }}
    .score span, .score em {{ display: block; color: var(--muted); font-style: normal; }}
    .score strong {{ display: block; font-size: 2rem; color: var(--accent); margin: 0.2rem 0; }}
    .pills {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 0.75rem 0 1rem; }}
    .pill {{ border: 1px solid var(--line); border-radius: 999px; padding: 4px 10px; color: var(--muted); }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.95rem; }}
    th, td {{ border: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: var(--panel); }}
    ul {{ margin-top: 0.5rem; }}
    @media print {{
      main {{ max-width: none; padding: 0; }}
      body {{ font-size: 11pt; }}
      .score {{ break-inside: avoid; }}
      table {{ break-inside: auto; }}
      tr {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
<main>
  <h1>OSINT Posture Report</h1>
  <div class=\"meta\">Generated: {escape(generated)}</div>

  <h2>Executive Overview</h2>
  <div class=\"scores\">{score_cards}</div>
  <div class=\"pills\">{count_pills}</div>

  <h2>Findings</h2>
  <ul>{li(notes)}</ul>

  <h2>Scoring Rationale</h2>
  <table>
    <thead>
      <tr>
        <th>Category</th>
        <th>Rule</th>
        <th>Deduction</th>
        <th>Evidence Ref</th>
      </tr>
    </thead>
    <tbody>
      {scoring_rows or '<tr><td colspan="4">No scoring deductions were applied.</td></tr>'}
    </tbody>
  </table>

  <h2>Evidence Snapshot</h2>
  <table>
    <thead>
      <tr>
        <th>Signal</th>
        <th>Value</th>
        <th>Source</th>
      </tr>
    </thead>
    <tbody>
      {evidence_rows}
    </tbody>
  </table>

  <h2>Discovered Subdomains</h2>
  <div class=\"pills\">{subdomain_source_html}</div>
  {f'<ul>{subdomain_warnings}</ul>' if subdomain_warnings else ''}
  <table>
    <thead>
      <tr>
        <th>Subdomain</th>
      </tr>
    </thead>
    <tbody>
      {subdomain_rows or '<tr><td>No subdomains were discovered from passive sources.</td></tr>'}
    </tbody>
  </table>

  <h2>Verified External Surface</h2>
  <table>
    <thead>
      <tr>
        <th>URL</th>
        <th>Method</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      {verified_rows or '<tr><td colspan="3">No verified HTTP surfaces recorded.</td></tr>'}
    </tbody>
  </table>

  <h2>Well-Known Metadata</h2>
  <table>
    <thead>
      <tr>
        <th>URL</th>
        <th>Status</th>
        <th>Content Type</th>
      </tr>
    </thead>
    <tbody>
      {well_known_rows or '<tr><td colspan="3">No well-known metadata checks recorded.</td></tr>'}
    </tbody>
  </table>

  <h2>Technology Fingerprints</h2>
  <table>
    <thead>
      <tr>
        <th>Technology</th>
        <th>Source</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      {fingerprint_rows or '<tr><td colspan="3">No technology fingerprints recorded.</td></tr>'}
    </tbody>
  </table>

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
</main>
</body>
</html>"""
