from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

from .network import NetworkLedger, NetworkPolicy, NetworkPolicyError
from .rate_limit import AsyncRateLimiter

logger = logging.getLogger(__name__)


class HttpClient:
    def __init__(
        self,
        timeout_seconds: float = 8.0,
        retries: int = 2,
        rate_limiter: Optional[AsyncRateLimiter] = None,
        policy: NetworkPolicy | None = None,
        ledger: NetworkLedger | None = None,
    ) -> None:
        self.timeout = httpx.Timeout(timeout_seconds)
        self.retries = retries
        self.rate_limiter = rate_limiter
        self.policy = policy
        self.ledger = ledger
        self.follow_redirects = False
        self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=self.follow_redirects)

    async def close(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, headers: Optional[dict] = None) -> httpx.Response:
        return await self.request("GET", url, headers=headers)

    async def head(self, url: str, headers: Optional[dict] = None) -> httpx.Response:
        return await self.request("HEAD", url, headers=headers)

    async def post(self, url: str, json: Optional[dict] = None, headers: Optional[dict] = None) -> httpx.Response:
        return await self.request("POST", url, json=json, headers=headers)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        json: Optional[dict] = None,
    ) -> httpx.Response:
        method = method.upper()
        category = "third_party_http"
        if self.policy:
            category = self.policy.enforce_http_request(method, url)

        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            if self.rate_limiter:
                await self.rate_limiter.wait()

            start = time.monotonic()
            bytes_out = len((str(headers) if headers else "").encode("utf-8"))
            if json is not None:
                bytes_out += len(str(json).encode("utf-8"))
            try:
                async with self._client.stream(method, url, headers=headers, json=json) as resp:
                    content = bytearray()
                    async for chunk in resp.aiter_bytes():
                        content.extend(chunk)
                        if self.policy and len(content) > self.policy.max_bytes_per_response:
                            raise NetworkPolicyError("response byte cap exceeded")
                    response = httpx.Response(
                        status_code=resp.status_code,
                        headers=resp.headers,
                        content=bytes(content),
                        request=resp.request,
                    )
                    if self.ledger:
                        self.ledger.add(
                            type=category,
                            destination_host=resp.request.url.host or "",
                            url=str(resp.request.url),
                            method=method,
                            status=resp.status_code,
                            bytes_out=bytes_out,
                            bytes_in=len(content),
                            duration_ms=int((time.monotonic() - start) * 1000),
                        )
                    return response
            except NetworkPolicyError:
                raise
            except Exception as exc:  # pragma: no cover - best-effort network
                last_exc = exc
                if self.ledger:
                    self.ledger.add(
                        type=category,
                        destination_host=httpx.URL(url).host or "",
                        url=url,
                        method=method,
                        status=None,
                        error=str(exc),
                        bytes_out=bytes_out,
                        bytes_in=0,
                        duration_ms=int((time.monotonic() - start) * 1000),
                    )
                logger.debug("http error", extra={"url": url, "error": str(exc), "attempt": attempt})
                await asyncio.sleep(0.2 * (attempt + 1))
        if last_exc:
            raise last_exc
        raise RuntimeError("http request failed")
