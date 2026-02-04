from __future__ import annotations

import csv
from io import StringIO


def build_csv(findings: dict) -> str:
    backlog = findings.get("prioritized_backlog", [])
    buf = StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=["priority", "title", "evidence", "remediation"]
    )
    writer.writeheader()
    for item in backlog:
        writer.writerow(
            {
                "priority": item.get("priority"),
                "title": item.get("title"),
                "evidence": item.get("evidence"),
                "remediation": item.get("remediation"),
            }
        )
    return buf.getvalue()
