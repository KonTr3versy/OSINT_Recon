from __future__ import annotations

import json

from osint_posture.platform.cloudflare_bridge import CloudflareReconJob, execute_cloudflare_job


def test_cloudflare_job_payload_accepts_worker_shape():
    job = CloudflareReconJob.model_validate(
        {
            "cloudflareJobId": 7,
            "orgId": "default",
            "assetId": 2,
            "reconPlanId": 3,
            "domain": "example.com",
            "mode": "passive",
            "dnsPolicy": "minimal",
            "enableThirdPartyIntel": False,
            "reconLevel": "low-noise-verified-surface",
            "budgets": {"max_target_dns_queries": 9},
        }
    )

    assert job.cloudflare_job_id == 7
    assert job.dns_policy == "minimal"
    assert job.recon_level == "low-noise-verified-surface"
    assert job.budgets["max_target_dns_queries"] == 9


def test_execute_cloudflare_job_returns_worker_result(tmp_path, monkeypatch):
    run_path = tmp_path / "output" / "example.com" / "20260101_000000"
    (run_path / "raw").mkdir(parents=True)
    (run_path / "artifacts").mkdir()
    (run_path / "raw" / "network_ledger.json").write_text(
        json.dumps({"totals": {"counts": {"target_http": 0}}}),
        encoding="utf-8",
    )
    (run_path / "findings.json").write_text(
        json.dumps({
            "prioritized_backlog": [{"title": "Enforce DMARC"}],
            "evidence": {
                "verified_surface": {"hosts": [{"host": "login.example.com"}]},
                "well_known_metadata": {"checks": [{"url": "https://example.com/security.txt"}]},
                "technology_fingerprints": {"hints": [{"technology": "Microsoft 365"}]},
            },
        }),
        encoding="utf-8",
    )

    def fake_execute_run(config):
        return {
            "run_path": str(run_path),
            "synthesis": {"summary": {"email_posture_score": 100, "exposure_score": 95}},
            "modules": [{"module": "dns_mail_profile", "status": "ok", "warnings": [], "errors": []}],
        }

    monkeypatch.setattr("osint_posture.platform.cloudflare_bridge.execute_run", fake_execute_run)
    job = CloudflareReconJob.model_validate(
        {
            "cloudflareJobId": 7,
            "orgId": "default",
            "assetId": 2,
            "reconPlanId": 3,
            "domain": "example.com",
            "mode": "passive",
            "dnsPolicy": "minimal",
            "enableThirdPartyIntel": False,
            "reconLevel": "low-noise-verified-surface",
            "budgets": {},
        }
    )

    result = execute_cloudflare_job(job, out_dir=str(tmp_path / "output"))

    assert result["cloudflareJobId"] == 7
    assert result["status"] == "completed"
    assert result["reconLevel"] == "low-noise-verified-surface"
    assert result["artifactPrefix"] == "example.com/20260101_000000"
    assert result["ledgerTotals"]["counts"]["target_http"] == 0
    assert result["findings"]["prioritized_backlog"][0]["title"] == "Enforce DMARC"
    assert result["moduleStatuses"][0]["module"] == "dns_mail_profile"
    assert result["verifiedSurface"]["hosts"][0]["host"] == "login.example.com"
    assert result["wellKnownMetadata"]["checks"][0]["url"] == "https://example.com/security.txt"
    assert result["technologyFingerprints"]["hints"][0]["technology"] == "Microsoft 365"
