from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

import httpx


class CloudflareQueueError(RuntimeError):
    pass


@dataclass(frozen=True)
class CloudflareQueueMessage:
    id: str | None
    lease_id: str
    body: dict[str, Any]
    attempts: int | None = None


class CloudflareQueueClient:
    def __init__(
        self,
        *,
        account_id: str,
        queue_id: str,
        api_token: str,
        api_base: str = "https://api.cloudflare.com/client/v4",
        timeout_seconds: float = 30.0,
    ) -> None:
        self.account_id = account_id
        self.queue_id = queue_id
        self.api_token = api_token
        self.api_base = api_base.rstrip("/")
        self.client = httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        self.client.close()

    def pull(self, *, batch_size: int = 1, visibility_timeout_ms: int = 3_600_000) -> list[CloudflareQueueMessage]:
        payload = {"batch_size": batch_size, "visibility_timeout_ms": visibility_timeout_ms}
        data = self._post("pull", payload)
        messages = data.get("messages", [])
        return [decode_queue_message(message) for message in messages]

    def ack(
        self,
        *,
        acks: list[str],
        retries: list[str],
        retry_delay_seconds: int | None = None,
    ) -> dict[str, Any]:
        retry_items: list[dict[str, Any]] = []
        for lease_id in retries:
            item: dict[str, Any] = {"lease_id": lease_id}
            if retry_delay_seconds is not None:
                item["delay_seconds"] = retry_delay_seconds
            retry_items.append(item)
        return self._post(
            "ack",
            {
                "acks": [{"lease_id": lease_id} for lease_id in acks],
                "retries": retry_items,
            },
        )

    def _post(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = (
            f"{self.api_base}/accounts/{self.account_id}/queues/"
            f"{self.queue_id}/messages/{action}"
        )
        response = self.client.post(
            url,
            headers={
                "authorization": f"Bearer {self.api_token}",
                "content-type": "application/json",
            },
            json=payload,
        )
        if response.status_code >= 400:
            raise CloudflareQueueError(f"Cloudflare Queue {action} failed: {response.status_code} {response.text}")
        envelope = response.json()
        if envelope.get("success") is False:
            raise CloudflareQueueError(f"Cloudflare Queue {action} failed: {envelope}")
        return envelope.get("result", envelope)


def decode_queue_message(message: dict[str, Any]) -> CloudflareQueueMessage:
    lease_id = message.get("lease_id")
    if not lease_id:
        raise CloudflareQueueError(f"Queue message missing lease_id: {message}")
    return CloudflareQueueMessage(
        id=message.get("id"),
        lease_id=lease_id,
        body=decode_queue_body(message.get("body")),
        attempts=int(message["attempts"]) if message.get("attempts") is not None else None,
    )


def decode_queue_body(body: Any) -> dict[str, Any]:
    if isinstance(body, dict):
        return body
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    if not isinstance(body, str):
        raise CloudflareQueueError(f"Unsupported queue body type: {type(body).__name__}")

    for candidate in _body_candidates(body):
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, str):
            try:
                decoded = json.loads(decoded)
            except json.JSONDecodeError:
                continue
        if isinstance(decoded, dict):
            return decoded
    raise CloudflareQueueError("Queue body was not valid JSON or base64-encoded JSON")


def _body_candidates(body: str) -> list[str]:
    candidates = [body]
    try:
        candidates.append(base64.b64decode(body, validate=True).decode("utf-8"))
    except Exception:
        pass
    return candidates

