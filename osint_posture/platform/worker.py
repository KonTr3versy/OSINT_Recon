from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from ..agent.tools import compare_runs
from ..models.config import DnsPolicy, Mode
from ..pipeline.service import create_run_config, execute_run, load_run_artifacts
from .db import (
    Artifact,
    AuditEvent,
    BacklogItem,
    Finding,
    Run,
    RunModule,
    utcnow,
)


ARTIFACTS = {
    "summary_md": ("artifacts/summary.md", "text/markdown"),
    "remediation_backlog_csv": ("artifacts/remediation_backlog.csv", "text/csv"),
    "report_html": ("artifacts/report.html", "text/html"),
    "findings_json": ("findings.json", "application/json"),
    "network_ledger_json": ("raw/network_ledger.json", "application/json"),
    "run_manifest_json": ("raw/run_manifest.json", "application/json"),
}


def process_next_run(session: Session, *, out_dir: str = "./output") -> Run | None:
    run = session.query(Run).filter_by(status="queued").order_by(Run.created_at.asc()).first()
    if run is None:
        return None
    return execute_platform_run(session, run, out_dir=out_dir)


def execute_platform_run(session: Session, run: Run, *, out_dir: str = "./output") -> Run:
    asset = run.asset
    plan = run.recon_plan
    if plan and plan.requires_approval and plan.approval_status != "approved":
        run.status = "blocked"
        run.error = "Run requires approved recon plan."
        session.add(AuditEvent(action="run.blocked", target_type="run", target_id=run.id, payload={}))
        return run

    run.status = "running"
    run.started_at = utcnow()
    session.flush()

    try:
        config = create_run_config(
            domain=asset.domain,
            company=asset.company,
            out_dir=out_dir,
            mode=Mode((plan.requested_mode if plan else "passive")),
            dns_policy=DnsPolicy((plan.requested_dns_policy if plan else "minimal")),
            enable_third_party_intel=bool(plan.enable_third_party_intel) if plan else False,
            max_target_http_requests_total=(plan.budgets or {}).get("max_target_http_requests_total", 12)
            if plan
            else 12,
            max_target_http_per_host=(plan.budgets or {}).get("max_target_http_per_host", 3)
            if plan
            else 3,
            max_target_http_per_minute=(plan.budgets or {}).get("max_target_http_per_minute", 12)
            if plan
            else 12,
            max_target_dns_queries=(plan.budgets or {}).get("max_target_dns_queries", 25)
            if plan
            else 25,
        )
        run.config = config.model_dump(mode="json")
        result = execute_run(config)
        run.run_path = result["run_path"]
        run.summary = result.get("synthesis", {}).get("summary", {})

        for module in result.get("modules", []):
            session.add(
                RunModule(
                    run_id=run.id,
                    module=module.get("module", ""),
                    status=module.get("status", ""),
                    warnings=module.get("warnings", []),
                    errors=module.get("errors", []),
                    data=module.get("data", {}),
                )
            )

        loaded = load_run_artifacts(result["run_path"])
        findings = loaded.get("findings", {})
        ledger = loaded.get("network_ledger", {})
        run.ledger_totals = ledger.get("totals", {}) if isinstance(ledger, dict) else {}
        _persist_findings(session, run, findings if isinstance(findings, dict) else {})
        _persist_artifacts(session, run)

        previous = (
            session.query(Run)
            .filter(Run.asset_id == run.asset_id, Run.id != run.id, Run.status == "completed")
            .order_by(Run.finished_at.desc())
            .first()
        )
        run.drift = compare_runs(previous, run)
        run.status = "completed"
        run.finished_at = utcnow()
        session.add(
            AuditEvent(
                action="run.completed",
                target_type="run",
                target_id=run.id,
                payload={"run_path": run.run_path, "ledger_totals": run.ledger_totals},
            )
        )
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = utcnow()
        session.add(
            AuditEvent(
                action="run.failed",
                target_type="run",
                target_id=run.id,
                payload={"error": str(exc)},
            )
        )
    return run


def _persist_findings(session: Session, run: Run, findings: dict) -> None:
    for item in findings.get("prioritized_backlog", []):
        title = item.get("title", "Untitled finding")
        priority = item.get("priority", "Unspecified")
        existing = (
            session.query(BacklogItem)
            .filter(
                BacklogItem.asset_id == run.asset_id,
                BacklogItem.title == title,
                BacklogItem.evidence_ref == item.get("evidence_ref"),
                BacklogItem.status != "resolved",
            )
            .one_or_none()
        )
        if existing:
            existing.last_seen_run_id = run.id
            existing.updated_at = utcnow()
            existing.priority = priority
            existing.evidence = item.get("evidence", "")
            existing.remediation = item.get("remediation", "")
        else:
            session.add(
                BacklogItem(
                    asset_id=run.asset_id,
                    run_id=run.id,
                    title=title,
                    priority=priority,
                    evidence=item.get("evidence", ""),
                    remediation=item.get("remediation", ""),
                    source=item.get("source"),
                    confidence=item.get("confidence"),
                    evidence_ref=item.get("evidence_ref"),
                    first_seen_run_id=run.id,
                    last_seen_run_id=run.id,
                )
            )
        session.add(
            Finding(
                run_id=run.id,
                title=title,
                severity=priority,
                evidence_ref=item.get("evidence_ref"),
                source=item.get("source"),
                confidence=item.get("confidence"),
                details=item,
            )
        )


def _persist_artifacts(session: Session, run: Run) -> None:
    if not run.run_path:
        return
    base = Path(run.run_path)
    for artifact_type, (relative, content_type) in ARTIFACTS.items():
        path = base / relative
        if path.exists():
            session.add(
                Artifact(
                    run_id=run.id,
                    type=artifact_type,
                    path=str(path),
                    content_type=content_type,
                )
            )

