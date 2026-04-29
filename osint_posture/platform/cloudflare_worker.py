from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .cloudflare_bridge import CloudflareReconJob, execute_cloudflare_job
from .cloudflare_queue import CloudflareQueueClient, CloudflareQueueMessage
from .r2_artifacts import R2ArtifactUploader, UploadedArtifact

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CloudflareWorkerResult:
    processed: int
    succeeded: int
    failed: int


class CloudflareControlPlaneClient:
    def __init__(
        self,
        *,
        base_url: str,
        org_id: str = "default",
        api_token: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self.api_token = api_token
        self.client = httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        self.client.close()

    def post_job_result(self, job_id: int, payload: dict[str, Any]) -> None:
        headers = {
            "content-type": "application/json",
            "x-org-id": self.org_id,
        }
        if self.api_token:
            headers["authorization"] = f"Bearer {self.api_token}"
        response = self.client.post(
            f"{self.base_url}/api/jobs/{job_id}/result",
            headers=headers,
            json=payload,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Control-plane callback failed: {response.status_code} {response.text}")


class CloudflareReconWorker:
    def __init__(
        self,
        *,
        queue: CloudflareQueueClient,
        control_plane: CloudflareControlPlaneClient,
        r2: R2ArtifactUploader | None = None,
        out_dir: str = "./output",
        batch_size: int = 1,
        visibility_timeout_ms: int = 3_600_000,
        retry_delay_seconds: int = 300,
    ) -> None:
        self.queue = queue
        self.control_plane = control_plane
        self.r2 = r2
        self.out_dir = out_dir
        self.batch_size = batch_size
        self.visibility_timeout_ms = visibility_timeout_ms
        self.retry_delay_seconds = retry_delay_seconds

    def run_once(self) -> CloudflareWorkerResult:
        messages = self.queue.pull(
            batch_size=self.batch_size,
            visibility_timeout_ms=self.visibility_timeout_ms,
        )
        acks: list[str] = []
        retries: list[str] = []
        succeeded = 0
        failed = 0
        for message in messages:
            try:
                self.process_message(message)
                acks.append(message.lease_id)
                succeeded += 1
            except Exception:
                logger.exception("Failed to process Cloudflare queue message")
                retries.append(message.lease_id)
                failed += 1
        if acks or retries:
            self.queue.ack(
                acks=acks,
                retries=retries,
                retry_delay_seconds=self.retry_delay_seconds if retries else None,
            )
        return CloudflareWorkerResult(processed=len(messages), succeeded=succeeded, failed=failed)

    def run_forever(self, *, poll_interval_seconds: float = 10.0) -> None:
        while True:
            result = self.run_once()
            if result.processed == 0:
                time.sleep(poll_interval_seconds)

    def process_message(self, message: CloudflareQueueMessage) -> None:
        job = CloudflareReconJob.model_validate(message.body)
        try:
            result = execute_cloudflare_job(job, out_dir=self.out_dir)
            uploads = self._upload_artifacts(result)
            callback_payload = {
                **result,
                "artifacts": [_artifact_dict(upload) for upload in uploads],
            }
        except Exception as exc:
            callback_payload = {
                "cloudflareJobId": job.cloudflare_job_id,
                "orgId": job.org_id,
                "assetId": job.asset_id,
                "reconPlanId": job.recon_plan_id,
                "status": "failed",
                "error": str(exc),
                "artifacts": [],
            }
        self.control_plane.post_job_result(job.cloudflare_job_id, callback_payload)

    def _upload_artifacts(self, result: dict[str, Any]) -> list[UploadedArtifact]:
        if not self.r2:
            return []
        artifact_prefix = str(result.get("artifactPrefix") or result["cloudflareJobId"])
        return self.r2.upload_run_artifacts(
            run_path=str(result["runPath"]),
            artifact_prefix=artifact_prefix,
        )


def _artifact_dict(upload: UploadedArtifact) -> dict[str, Any]:
    return {
        "key": upload.key,
        "contentType": upload.content_type,
        "bytes": upload.bytes,
    }
