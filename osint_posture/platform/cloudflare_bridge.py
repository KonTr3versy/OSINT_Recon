from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..models.config import DnsPolicy, Mode
from ..pipeline.service import create_run_config, execute_run, load_run_artifacts


class CloudflareReconJob(BaseModel):
    cloudflare_job_id: int = Field(alias="cloudflareJobId")
    org_id: str = Field(alias="orgId")
    asset_id: int = Field(alias="assetId")
    recon_plan_id: int = Field(alias="reconPlanId")
    domain: str
    company: str | None = None
    mode: Mode = Mode.passive
    dns_policy: DnsPolicy = Field(default=DnsPolicy.minimal, alias="dnsPolicy")
    enable_third_party_intel: bool = Field(default=False, alias="enableThirdPartyIntel")
    budgets: dict[str, int] = Field(default_factory=dict)
    recon_level: str | None = Field(default=None, alias="reconLevel")


def execute_cloudflare_job(job: CloudflareReconJob, *, out_dir: str = "./output") -> dict[str, Any]:
    config = create_run_config(
        domain=job.domain,
        company=job.company,
        recon_level=job.recon_level,
        out_dir=out_dir,
        mode=job.mode,
        dns_policy=job.dns_policy,
        enable_third_party_intel=job.enable_third_party_intel,
        max_target_http_requests_total=job.budgets.get("max_target_http_requests_total", 12),
        max_target_http_per_host=job.budgets.get("max_target_http_per_host", 3),
        max_target_http_per_minute=job.budgets.get("max_target_http_per_minute", 12),
        max_target_dns_queries=job.budgets.get("max_target_dns_queries", 25),
    )
    result = execute_run(config)
    artifacts = load_run_artifacts(result["run_path"])
    findings = artifacts.get("findings", {})
    evidence = findings.get("evidence", {}) if isinstance(findings, dict) else {}
    module_statuses = [
        {
            "module": module.get("module"),
            "status": module.get("status"),
            "warnings": module.get("warnings", []),
            "errors": module.get("errors", []),
        }
        for module in result.get("modules", [])
    ]
    summary = result.get("synthesis", {}).get("summary", {})
    ledger = artifacts.get("network_ledger", {})
    artifact_prefix = _artifact_prefix(result["run_path"], out_dir)
    return {
        "cloudflareJobId": job.cloudflare_job_id,
        "orgId": job.org_id,
        "assetId": job.asset_id,
        "reconPlanId": job.recon_plan_id,
        "status": "completed",
        "runPath": result["run_path"],
        "artifactPrefix": artifact_prefix,
        "reconLevel": job.recon_level,
        "summary": summary,
        "findings": findings,
        "moduleStatuses": module_statuses,
        "ledgerTotals": ledger.get("totals", {}) if isinstance(ledger, dict) else {},
        "verifiedSurface": evidence.get("verified_surface", {}) if isinstance(evidence, dict) else {},
        "wellKnownMetadata": evidence.get("well_known_metadata", {}) if isinstance(evidence, dict) else {},
        "technologyFingerprints": evidence.get("technology_fingerprints", {}) if isinstance(evidence, dict) else {},
    }


def _artifact_prefix(run_path: str, out_dir: str) -> str:
    path = Path(run_path).resolve()
    root = Path(out_dir).resolve()
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
