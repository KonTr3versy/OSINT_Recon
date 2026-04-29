from __future__ import annotations

import json

from fastapi.testclient import TestClient

from osint_posture.platform.app import create_app


def _client(tmp_path):
    app = create_app(
        database_url="sqlite:///:memory:",
        artifact_root=str(tmp_path / "output"),
        execute_runs_inline=False,
    )
    return TestClient(app)


def test_rbac_viewer_cannot_create_asset(tmp_path):
    client = _client(tmp_path)
    response = client.post(
        "/assets",
        headers={"X-User-Email": "viewer@example.com"},
        json={"domain": "example.com"},
    )
    assert response.status_code == 403


def test_asset_to_plan_requires_approval_for_low_noise(tmp_path):
    client = _client(tmp_path)
    asset = client.post("/assets", json={"domain": "example.com"}).json()
    plan = client.post(
        "/recon-plans",
        json={
            "asset_id": asset["id"],
            "requested_mode": "low-noise",
            "requested_dns_policy": "full",
        },
    ).json()

    assert plan["requires_approval"] is True
    assert plan["approval_status"] == "pending"

    detail = client.get(f"/recon-plans/{plan['id']}").json()
    assert detail["approval_requests"][0]["status"] == "pending"


def test_rejected_approval_blocks_run_creation(tmp_path):
    client = _client(tmp_path)
    asset = client.post("/assets", json={"domain": "example.com"}).json()
    plan = client.post(
        "/recon-plans",
        json={"asset_id": asset["id"], "requested_mode": "low-noise"},
    ).json()
    approval = client.get(f"/recon-plans/{plan['id']}").json()["approval_requests"][0]
    client.post(f"/approval-requests/{approval['id']}/reject", json={"note": "not today"})

    response = client.post("/runs", json={"recon_plan_id": plan["id"]})

    assert response.status_code == 409


def test_passive_plan_can_queue_run(tmp_path):
    client = _client(tmp_path)
    asset = client.post("/assets", json={"domain": "example.com"}).json()
    plan = client.post("/recon-plans", json={"asset_id": asset["id"]}).json()

    run = client.post("/runs", json={"recon_plan_id": plan["id"]}).json()

    assert run["status"] == "queued"
    assert run["asset_id"] == asset["id"]


def test_artifact_endpoint_returns_persisted_report(tmp_path, monkeypatch):
    output = tmp_path / "output"
    run_path = output / "example.com" / "20260101_000000"
    (run_path / "artifacts").mkdir(parents=True)
    (run_path / "raw").mkdir()
    (run_path / "artifacts" / "summary.md").write_text("# Summary", encoding="utf-8")
    (run_path / "artifacts" / "remediation_backlog.csv").write_text(
        "priority,title,evidence,remediation,source,confidence,evidence_ref\n",
        encoding="utf-8",
    )
    (run_path / "artifacts" / "report.html").write_text("<h1>Report</h1>", encoding="utf-8")
    (run_path / "findings.json").write_text(
        json.dumps(
            {
                "summary": {"email_posture_score": 80, "exposure_score": 90},
                "prioritized_backlog": [
                    {
                        "priority": "High",
                        "title": "Publish SPF",
                        "evidence": "No SPF",
                        "remediation": "Add SPF",
                        "source": "dns_mail_profile",
                        "confidence": "high",
                        "evidence_ref": "evidence.dns_mail_profile.spf_raw",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (run_path / "raw" / "network_ledger.json").write_text(
        json.dumps({"entries": [], "totals": {"counts": {"target_http": 0}}}),
        encoding="utf-8",
    )
    (run_path / "raw" / "run_manifest.json").write_text(json.dumps({"budgets": {}}), encoding="utf-8")

    def fake_execute_run(config):
        return {
            "run_path": str(run_path),
            "modules": [
                {
                    "module": "dns_mail_profile",
                    "status": "ok",
                    "warnings": [],
                    "errors": [],
                    "data": {},
                }
            ],
            "synthesis": {"summary": {"email_posture_score": 80, "exposure_score": 90}},
        }

    monkeypatch.setattr("osint_posture.platform.worker.execute_run", fake_execute_run)

    app = create_app(
        database_url="sqlite:///:memory:",
        artifact_root=str(output),
        execute_runs_inline=True,
    )
    client = TestClient(app)
    asset = client.post("/assets", json={"domain": "example.com"}).json()
    plan = client.post("/recon-plans", json={"asset_id": asset["id"]}).json()
    run = client.post("/runs", json={"recon_plan_id": plan["id"]}).json()

    assert run["status"] == "completed"
    assert run["ledger_totals"]["counts"]["target_http"] == 0
    assert client.get(f"/runs/{run['id']}/artifacts/report_html").text == "<h1>Report</h1>"
    backlog = client.get("/backlog").json()
    assert backlog[0]["title"] == "Publish SPF"

