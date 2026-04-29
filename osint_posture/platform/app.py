from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..agent.tools import propose_recon_plan, start_approved_run, update_backlog
from ..models.config import DnsPolicy, Mode
from .db import (
    ApprovalRequest,
    Artifact,
    Asset,
    AuditEvent,
    BacklogItem,
    Database,
    Organization,
    ReconPlan,
    Run,
    User,
    seed_defaults,
    utcnow,
)
from .security import has_permission


class AssetCreate(BaseModel):
    domain: str
    company: str | None = None
    organization_id: int | None = None
    allowed_mode: Mode = Mode.passive
    dns_policy_ceiling: DnsPolicy = DnsPolicy.minimal
    third_party_intel_allowed: bool = False
    default_schedule: str = "weekly"


class ReconPlanCreate(BaseModel):
    asset_id: int
    schedule: str = "weekly"
    requested_mode: Mode = Mode.passive
    requested_dns_policy: DnsPolicy = DnsPolicy.minimal
    enable_third_party_intel: bool = False
    budgets: dict = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    note: str | None = None


class RunCreate(BaseModel):
    recon_plan_id: int
    execute_now: bool = False


class BacklogUpdate(BaseModel):
    status: str | None = None
    remediation: str | None = None


def create_app(
    *,
    database_url: str | None = None,
    artifact_root: str = "./output",
    execute_runs_inline: bool = False,
) -> FastAPI:
    database = Database(database_url)
    database.create_all()
    with database.session() as session:
        seed_defaults(session)

    app = FastAPI(title="OSINT Posture Platform", version="0.1.0")
    app.state.database = database
    app.state.artifact_root = artifact_root
    app.state.execute_runs_inline = execute_runs_inline

    def get_session():
        with database.session() as session:
            yield session

    def current_user(
        session: Session = Depends(get_session),
        x_user_email: str | None = Header(default=None, alias="X-User-Email"),
    ) -> User:
        email = x_user_email or "admin@example.com"
        user = session.query(User).filter_by(email=email, is_active=True).one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="Unknown or inactive user")
        return user

    def require(permission: str):
        def dependency(user: User = Depends(current_user)) -> User:
            if not has_permission(user.role, permission):
                raise HTTPException(status_code=403, detail="Insufficient role permission")
            return user

        return dependency

    @app.get("/", response_class=HTMLResponse)
    def dashboard(session: Session = Depends(get_session)):
        assets = session.query(Asset).order_by(Asset.domain.asc()).all()
        runs = session.query(Run).order_by(Run.created_at.desc()).limit(10).all()
        backlog = session.query(BacklogItem).filter(BacklogItem.status != "resolved").limit(10).all()
        return _render_dashboard(assets, runs, backlog)

    @app.post("/assets")
    def create_asset(
        payload: AssetCreate,
        session: Session = Depends(get_session),
        user: User = Depends(require("assets:write")),
    ):
        org_id = payload.organization_id
        if org_id is None:
            org_id = session.query(Organization.id).order_by(Organization.id.asc()).scalar()
        asset = Asset(
            organization_id=org_id,
            domain=payload.domain.lower().strip(),
            company=payload.company,
            allowed_mode=payload.allowed_mode.value,
            dns_policy_ceiling=payload.dns_policy_ceiling.value,
            third_party_intel_allowed=payload.third_party_intel_allowed,
            default_schedule=payload.default_schedule,
        )
        session.add(asset)
        session.flush()
        _audit(session, user, "asset.created", "asset", asset.id, {"domain": asset.domain})
        return _asset_dict(asset)

    @app.get("/assets")
    def get_assets(
        session: Session = Depends(get_session),
        _: User = Depends(require("assets:read")),
    ):
        return [_asset_dict(asset) for asset in session.query(Asset).order_by(Asset.domain.asc()).all()]

    @app.post("/recon-plans")
    def create_recon_plan(
        payload: ReconPlanCreate,
        session: Session = Depends(get_session),
        user: User = Depends(require("plans:write")),
    ):
        asset = session.get(Asset, payload.asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        proposal = propose_recon_plan(
            asset,
            requested_mode=payload.requested_mode.value,
            requested_dns_policy=payload.requested_dns_policy.value,
            enable_third_party_intel=payload.enable_third_party_intel,
            budgets=payload.budgets,
        )
        plan = ReconPlan(
            asset_id=asset.id,
            schedule=payload.schedule,
            requested_mode=proposal.requested_mode,
            requested_dns_policy=proposal.requested_dns_policy,
            enable_third_party_intel=proposal.enable_third_party_intel,
            budgets=proposal.budgets,
            expected_sources=proposal.expected_sources,
            requires_approval=proposal.requires_approval,
            approval_status="pending" if proposal.requires_approval else "approved",
            rationale=proposal.rationale,
            created_by_user_id=user.id,
        )
        session.add(plan)
        session.flush()
        if plan.requires_approval:
            session.add(
                ApprovalRequest(
                    recon_plan_id=plan.id,
                    reason=plan.rationale,
                    status="pending",
                )
            )
        _audit(
            session,
            user,
            "recon_plan.proposed",
            "recon_plan",
            plan.id,
            {"requires_approval": plan.requires_approval, "expected_sources": plan.expected_sources},
        )
        return _plan_dict(plan)

    @app.get("/recon-plans/{plan_id}")
    def get_recon_plan(
        plan_id: int,
        session: Session = Depends(get_session),
        _: User = Depends(require("plans:read")),
    ):
        plan = session.get(ReconPlan, plan_id)
        if not plan:
            raise HTTPException(status_code=404, detail="Recon plan not found")
        approvals = session.query(ApprovalRequest).filter_by(recon_plan_id=plan.id).all()
        data = _plan_dict(plan)
        data["approval_requests"] = [_approval_dict(approval) for approval in approvals]
        return data

    @app.post("/approval-requests/{approval_id}/approve")
    def approve_request(
        approval_id: int,
        payload: ApprovalDecision,
        session: Session = Depends(get_session),
        user: User = Depends(require("approvals:decide")),
    ):
        approval = _get_approval(session, approval_id)
        approval.status = "approved"
        approval.decided_by_user_id = user.id
        approval.decision_note = payload.note
        approval.decided_at = utcnow()
        approval.recon_plan.approval_status = "approved"
        _audit(session, user, "approval.approved", "approval_request", approval.id, {"note": payload.note})
        return _approval_dict(approval)

    @app.post("/approval-requests/{approval_id}/reject")
    def reject_request(
        approval_id: int,
        payload: ApprovalDecision,
        session: Session = Depends(get_session),
        user: User = Depends(require("approvals:decide")),
    ):
        approval = _get_approval(session, approval_id)
        approval.status = "rejected"
        approval.decided_by_user_id = user.id
        approval.decision_note = payload.note
        approval.decided_at = utcnow()
        approval.recon_plan.approval_status = "rejected"
        _audit(session, user, "approval.rejected", "approval_request", approval.id, {"note": payload.note})
        return _approval_dict(approval)

    @app.post("/runs")
    def create_run(
        payload: RunCreate,
        session: Session = Depends(get_session),
        user: User = Depends(require("runs:write")),
    ):
        plan = session.get(ReconPlan, payload.recon_plan_id)
        if not plan:
            raise HTTPException(status_code=404, detail="Recon plan not found")
        if not start_approved_run(plan):
            raise HTTPException(status_code=409, detail="Recon plan requires approval before execution")
        run = Run(
            asset_id=plan.asset_id,
            recon_plan_id=plan.id,
            status="queued",
            created_by_user_id=user.id,
        )
        session.add(run)
        session.flush()
        _audit(session, user, "run.queued", "run", run.id, {"recon_plan_id": plan.id})
        if payload.execute_now or app.state.execute_runs_inline:
            from .worker import execute_platform_run

            execute_platform_run(session, run, out_dir=app.state.artifact_root)
        return _run_dict(run)

    @app.get("/runs")
    def get_runs(
        session: Session = Depends(get_session),
        _: User = Depends(require("runs:read")),
    ):
        return [_run_dict(run) for run in session.query(Run).order_by(Run.created_at.desc()).all()]

    @app.get("/runs/{run_id}")
    def get_run(
        run_id: int,
        session: Session = Depends(get_session),
        _: User = Depends(require("runs:read")),
    ):
        run = session.get(Run, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        data = _run_dict(run)
        data["modules"] = [
            {
                "module": module.module,
                "status": module.status,
                "warnings": module.warnings,
                "errors": module.errors,
            }
            for module in run_modules(session, run.id)
        ]
        return data

    @app.get("/runs/{run_id}/artifacts/{artifact_type}")
    def get_artifact(
        run_id: int,
        artifact_type: str,
        session: Session = Depends(get_session),
        _: User = Depends(require("runs:read")),
    ):
        artifact = session.query(Artifact).filter_by(run_id=run_id, type=artifact_type).one_or_none()
        if not artifact:
            raise HTTPException(status_code=404, detail="Artifact not found")
        path = Path(artifact.path)
        if not path.exists():
            raise HTTPException(status_code=404, detail="Artifact file missing")
        text = path.read_text(encoding="utf-8")
        response_class = HTMLResponse if artifact.content_type == "text/html" else PlainTextResponse
        return response_class(text, media_type=artifact.content_type)

    @app.get("/backlog")
    def get_backlog(
        session: Session = Depends(get_session),
        _: User = Depends(require("backlog:read")),
    ):
        items = session.query(BacklogItem).order_by(BacklogItem.updated_at.desc()).all()
        return [_backlog_dict(item) for item in items]

    @app.patch("/backlog/{item_id}")
    def patch_backlog(
        item_id: int,
        payload: BacklogUpdate,
        session: Session = Depends(get_session),
        user: User = Depends(require("backlog:write")),
    ):
        item = session.get(BacklogItem, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Backlog item not found")
        update_backlog(item, status=payload.status, remediation=payload.remediation)
        item.updated_at = utcnow()
        _audit(session, user, "backlog.updated", "backlog_item", item.id, payload.model_dump())
        return _backlog_dict(item)

    return app


def run_modules(session: Session, run_id: int):
    from .db import RunModule

    return session.query(RunModule).filter_by(run_id=run_id).order_by(RunModule.id.asc()).all()


def _get_approval(session: Session, approval_id: int) -> ApprovalRequest:
    approval = session.get(ApprovalRequest, approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if approval.status != "pending":
        raise HTTPException(status_code=409, detail="Approval request already decided")
    return approval


def _audit(session: Session, user: User, action: str, target_type: str, target_id: int, payload: dict) -> None:
    session.add(
        AuditEvent(
            actor_user_id=user.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            payload=payload,
        )
    )


def _asset_dict(asset: Asset) -> dict:
    return {
        "id": asset.id,
        "organization_id": asset.organization_id,
        "domain": asset.domain,
        "company": asset.company,
        "allowed_mode": asset.allowed_mode,
        "dns_policy_ceiling": asset.dns_policy_ceiling,
        "third_party_intel_allowed": asset.third_party_intel_allowed,
        "default_schedule": asset.default_schedule,
    }


def _plan_dict(plan: ReconPlan) -> dict:
    return {
        "id": plan.id,
        "asset_id": plan.asset_id,
        "schedule": plan.schedule,
        "requested_mode": plan.requested_mode,
        "requested_dns_policy": plan.requested_dns_policy,
        "enable_third_party_intel": plan.enable_third_party_intel,
        "budgets": plan.budgets,
        "expected_sources": plan.expected_sources,
        "requires_approval": plan.requires_approval,
        "approval_status": plan.approval_status,
        "rationale": plan.rationale,
    }


def _approval_dict(approval: ApprovalRequest) -> dict:
    return {
        "id": approval.id,
        "recon_plan_id": approval.recon_plan_id,
        "status": approval.status,
        "reason": approval.reason,
        "decision_note": approval.decision_note,
        "decided_by_user_id": approval.decided_by_user_id,
    }


def _run_dict(run: Run) -> dict:
    return {
        "id": run.id,
        "asset_id": run.asset_id,
        "recon_plan_id": run.recon_plan_id,
        "status": run.status,
        "run_path": run.run_path,
        "summary": run.summary,
        "ledger_totals": run.ledger_totals,
        "drift": run.drift,
        "error": run.error,
    }


def _backlog_dict(item: BacklogItem) -> dict:
    return {
        "id": item.id,
        "asset_id": item.asset_id,
        "run_id": item.run_id,
        "title": item.title,
        "priority": item.priority,
        "evidence": item.evidence,
        "remediation": item.remediation,
        "source": item.source,
        "confidence": item.confidence,
        "evidence_ref": item.evidence_ref,
        "status": item.status,
        "first_seen_run_id": item.first_seen_run_id,
        "last_seen_run_id": item.last_seen_run_id,
    }


def _render_dashboard(assets: list[Asset], runs: list[Run], backlog: list[BacklogItem]) -> Response:
    asset_rows = "".join(f"<tr><td>{a.domain}</td><td>{a.allowed_mode}</td><td>{a.default_schedule}</td></tr>" for a in assets)
    run_rows = "".join(f"<tr><td>{r.id}</td><td>{r.status}</td><td>{r.run_path or ''}</td></tr>" for r in runs)
    backlog_rows = "".join(f"<tr><td>{b.priority}</td><td>{b.title}</td><td>{b.status}</td></tr>" for b in backlog)
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OSINT Posture Platform</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; color: #172026; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px; }}
    h1 {{ margin-top: 0; }}
    section {{ margin-top: 28px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #d8dee3; padding: 8px; text-align: left; }}
    th {{ background: #f6f8f9; }}
  </style>
</head>
<body>
<main>
  <h1>OSINT Posture Platform</h1>
  <section><h2>Assets</h2><table><tr><th>Domain</th><th>Allowed Mode</th><th>Schedule</th></tr>{asset_rows}</table></section>
  <section><h2>Recent Runs</h2><table><tr><th>ID</th><th>Status</th><th>Path</th></tr>{run_rows}</table></section>
  <section><h2>Backlog</h2><table><tr><th>Priority</th><th>Title</th><th>Status</th></tr>{backlog_rows}</table></section>
</main>
</body>
</html>"""
    )
