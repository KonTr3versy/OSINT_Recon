from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    def __init__(self, max_per_minute: int) -> None:
        self.max_per_minute = max(1, max_per_minute)
        self.interval = 60.0 / self.max_per_minute
        self._lock = asyncio.Lock()
        self._next_time = time.monotonic()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if now < self._next_time:
                await asyncio.sleep(self._next_time - now)
            self._next_time = max(now, self._next_time) + self.interval
