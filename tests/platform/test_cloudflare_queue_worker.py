from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from osint_posture.platform.cloudflare_queue import decode_queue_body, decode_queue_message
from osint_posture.platform.cloudflare_worker import CloudflareControlPlaneClient, CloudflareReconWorker


def _job_payload():
    return {
        "cloudflareJobId": 11,
        "orgId": "default",
        "assetId": 2,
        "reconPlanId": 3,
        "domain": "example.com",
        "mode": "passive",
        "dnsPolicy": "minimal",
        "enableThirdPartyIntel": False,
        "budgets": {},
    }


def test_decode_queue_body_accepts_base64_json():
    encoded = base64.b64encode(json.dumps(_job_payload()).encode("utf-8")).decode("ascii")

    assert decode_queue_body(encoded)["cloudflareJobId"] == 11


def test_decode_queue_message_requires_lease_id():
    message = decode_queue_message({"id": "m1", "lease_id": "lease-1", "body": _job_payload()})

    assert message.id == "m1"
    assert message.lease_id == "lease-1"
    assert message.body["domain"] == "example.com"


def test_worker_processes_message_uploads_artifacts_and_acks(monkeypatch):
    queue = _FakeQueue()
    control_plane = _FakeControlPlane()
    r2 = _FakeR2()

    def fake_execute(job, *, out_dir):
        return {
            "cloudflareJobId": job.cloudflare_job_id,
            "orgId": job.org_id,
            "assetId": job.asset_id,
            "reconPlanId": job.recon_plan_id,
            "status": "completed",
            "runPath": "/tmp/run",
            "artifactPrefix": "example.com/20260101_000000",
            "summary": {"email_posture_score": 100},
            "ledgerTotals": {"counts": {"target_http": 0}},
        }

    monkeypatch.setattr("osint_posture.platform.cloudflare_worker.execute_cloudflare_job", fake_execute)
    worker = CloudflareReconWorker(queue=queue, control_plane=control_plane, r2=r2)

    result = worker.run_once()

    assert result.processed == 1
    assert result.succeeded == 1
    assert result.failed == 0
    assert queue.acked == ["lease-1"]
    assert queue.retried == []
    assert control_plane.results[0]["artifacts"][0]["key"] == "runs/example/report.html"


def test_worker_posts_failed_result_when_processing_fails(monkeypatch):
    queue = _FakeQueue()
    control_plane = _FakeControlPlane()

    def fake_execute(job, *, out_dir):
        raise RuntimeError("boom")

    monkeypatch.setattr("osint_posture.platform.cloudflare_worker.execute_cloudflare_job", fake_execute)
    worker = CloudflareReconWorker(queue=queue, control_plane=control_plane)

    result = worker.run_once()

    assert result.succeeded == 1
    assert result.failed == 0
    assert queue.acked == ["lease-1"]
    assert queue.retried == []
    assert control_plane.results[0]["status"] == "failed"
    assert control_plane.results[0]["error"] == "boom"


def test_control_plane_client_sends_access_service_token_headers(monkeypatch):
    captured = {}

    class FakeClient:
        def post(self, url, *, headers, json):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return _FakeResponse()

    client = CloudflareControlPlaneClient(
        base_url="https://worker.example",
        api_token="callback-token",
        access_client_id="service-id",
        access_client_secret="service-secret",
    )
    client.client = FakeClient()

    client.post_job_result(12, {"status": "completed"})

    assert captured["url"] == "https://worker.example/api/jobs/12/result"
    assert captured["headers"]["authorization"] == "Bearer callback-token"
    assert captured["headers"]["cf-access-client-id"] == "service-id"
    assert captured["headers"]["cf-access-client-secret"] == "service-secret"


class _FakeQueue:
    def __init__(self):
        self.acked = []
        self.retried = []

    def pull(self, *, batch_size, visibility_timeout_ms):
        return [decode_queue_message({"id": "m1", "lease_id": "lease-1", "body": _job_payload()})]

    def ack(self, *, acks, retries, retry_delay_seconds=None):
        self.acked = acks
        self.retried = retries
        return {}


class _FakeControlPlane:
    def __init__(self):
        self.results = []

    def post_job_result(self, job_id, payload):
        self.results.append(payload)


class _FakeResponse:
    status_code = 200
    text = "ok"


@dataclass(frozen=True)
class _FakeUpload:
    key: str
    content_type: str
    bytes: int


class _FakeR2:
    def upload_run_artifacts(self, *, run_path, artifact_prefix):
        return [_FakeUpload(key="runs/example/report.html", content_type="text/html", bytes=14)]
