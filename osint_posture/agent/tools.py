from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..models.config import DnsPolicy, Mode
from ..platform.db import Asset, BacklogItem, ReconPlan, Run


DNS_RANK = {DnsPolicy.none.value: 0, DnsPolicy.minimal.value: 1, DnsPolicy.full.value: 2}
MODE_RANK = {Mode.passive.value: 0, Mode.low_noise.value: 1}


@dataclass(frozen=True)
class ProposedPlan:
    requested_mode: str
    requested_dns_policy: str
    enable_third_party_intel: bool
    budgets: dict
    expected_sources: list[str]
    requires_approval: bool
    rationale: str


def list_assets(session: Session) -> list[dict]:
    assets = session.query(Asset).order_by(Asset.domain.asc()).all()
    return [
        {
            "id": asset.id,
            "domain": asset.domain,
            "company": asset.company,
            "allowed_mode": asset.allowed_mode,
            "dns_policy_ceiling": asset.dns_policy_ceiling,
            "third_party_intel_allowed": asset.third_party_intel_allowed,
            "default_schedule": asset.default_schedule,
        }
        for asset in assets
    ]


def get_asset_history(session: Session, asset_id: int, limit: int = 10) -> list[dict]:
    runs = (
        session.query(Run)
        .filter(Run.asset_id == asset_id)
        .order_by(Run.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": run.id,
            "status": run.status,
            "summary": run.summary,
            "ledger_totals": run.ledger_totals,
            "drift": run.drift,
            "created_at": run.created_at.isoformat(),
        }
        for run in runs
    ]


def propose_recon_plan(
    asset: Asset,
    *,
    requested_mode: str | None = None,
    requested_dns_policy: str | None = None,
    enable_third_party_intel: bool | None = None,
    budgets: dict | None = None,
) -> ProposedPlan:
    mode = requested_mode or Mode.passive.value
    dns_policy = requested_dns_policy or DnsPolicy.minimal.value
    third_party = bool(enable_third_party_intel)
    resolved_budgets = {
        "max_target_http_requests_total": 12,
        "max_target_http_per_host": 3,
        "max_target_http_per_minute": 12,
        "max_target_dns_queries": 25,
        **(budgets or {}),
    }

    requires_approval = any(
        [
            mode == Mode.low_noise.value,
            dns_policy == DnsPolicy.full.value,
            third_party,
            MODE_RANK[mode] > MODE_RANK[asset.allowed_mode],
            DNS_RANK[dns_policy] > DNS_RANK[asset.dns_policy_ceiling],
            third_party and not asset.third_party_intel_allowed,
        ]
    )
    expected_sources = ["dns_mail_profile", "passive_subdomains", "passive_users", "web_signals"]
    if third_party:
        expected_sources.append("third_party_intel")
    if mode == Mode.low_noise.value:
        expected_sources.append("doc_signals")
        if dns_policy == DnsPolicy.full.value:
            expected_sources.extend(
                [
                    "passive_tool_subdomains",
                    "subdomain_resolution",
                    "verified_surface",
                    "well_known_metadata",
                    "technology_fingerprints",
                ]
            )

    rationale = (
        "Scheduled posture run using deterministic recon modules. "
        "Approval is required for low-noise target contact, full DNS, or third-party intel."
    )
    return ProposedPlan(
        requested_mode=mode,
        requested_dns_policy=dns_policy,
        enable_third_party_intel=third_party,
        budgets=resolved_budgets,
        expected_sources=expected_sources,
        requires_approval=requires_approval,
        rationale=rationale,
    )


def request_approval(plan: ReconPlan) -> bool:
    return bool(plan.requires_approval and plan.approval_status == "pending")


def start_approved_run(plan: ReconPlan) -> bool:
    return not plan.requires_approval or plan.approval_status == "approved"


def summarize_run(run: Run) -> dict:
    scores = run.summary or {}
    return {
        "run_id": run.id,
        "status": run.status,
        "email_posture_score": scores.get("email_posture_score"),
        "exposure_score": scores.get("exposure_score"),
        "drift": run.drift or {},
    }


def compare_runs(previous: Run | None, current: Run) -> dict:
    if previous is None:
        return {"new_run": True, "score_changes": {}, "summary": "No previous run to compare."}
    score_changes = {}
    for key in ("email_posture_score", "exposure_score"):
        old = (previous.summary or {}).get(key)
        new = (current.summary or {}).get(key)
        if isinstance(old, int | float) and isinstance(new, int | float):
            score_changes[key] = new - old
    return {"new_run": False, "score_changes": score_changes}


def update_backlog(item: BacklogItem, *, status: str | None = None, remediation: str | None = None) -> BacklogItem:
    if status is not None:
        item.status = status
    if remediation is not None:
        item.remediation = remediation
    return item
