from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from .rate_limit import AsyncRateLimiter

logger = logging.getLogger(__name__)


class HttpClient:
    def __init__(
        self,
        timeout_seconds: float = 8.0,
        retries: int = 2,
        rate_limiter: Optional[AsyncRateLimiter] = None,
    ) -> None:
        self.timeout = httpx.Timeout(timeout_seconds)
        self.retries = retries
        self.rate_limiter = rate_limiter

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
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            if self.rate_limiter:
                await self.rate_limiter.wait()
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.request(method, url, headers=headers, json=json)
                    return resp
            except Exception as exc:  # pragma: no cover - best-effort network
                last_exc = exc
                logger.debug("http error", extra={"url": url, "error": str(exc), "attempt": attempt})
                await asyncio.sleep(0.2 * (attempt + 1))
        if last_exc:
            raise last_exc
        raise RuntimeError("http request failed")
