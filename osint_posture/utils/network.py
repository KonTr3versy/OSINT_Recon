from __future__ import annotations

import ipaddress
import socket
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ..models.config import DnsPolicy, Mode, RunConfig


class NetworkPolicyError(RuntimeError):
    pass


@dataclass
class NetworkLedgerEntry:
    timestamp: str
    type: str
    destination_host: str
    url: str | None = None
    method: str | None = None
    status: int | str | None = None
    error: str | None = None
    bytes_out: int = 0
    bytes_in: int = 0
    duration_ms: int = 0
    query_name: str | None = None
    record_type: str | None = None
    success: bool | None = None


@dataclass
class NetworkLedger:
    entries: list[NetworkLedgerEntry] = field(default_factory=list)

    def add(self, **kwargs: Any) -> None:
        self.entries.append(NetworkLedgerEntry(timestamp=datetime.now(timezone.utc).isoformat(), **kwargs))

    def to_dict(self) -> dict[str, Any]:
        return {"entries": [e.__dict__ for e in self.entries], "totals": self.totals()}

    def totals(self) -> dict[str, Any]:
        counts = defaultdict(int)
        bytes_out = defaultdict(int)
        bytes_in = defaultdict(int)
        for entry in self.entries:
            counts[entry.type] += 1
            bytes_out[entry.type] += entry.bytes_out
            bytes_in[entry.type] += entry.bytes_in
        return {
            "counts": dict(counts),
            "bytes_out": dict(bytes_out),
            "bytes_in": dict(bytes_in),
            "total_entries": len(self.entries),
        }


@dataclass
class NetworkPolicy:
    domain: str
    mode: Mode
    dns_policy: DnsPolicy
    max_target_http_requests_total: int
    max_target_http_per_host: int
    max_target_http_per_minute: int
    max_redirects: int
    max_bytes_per_response: int
    max_target_dns_queries: int
    target_http_total: int = 0
    target_http_per_host: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    target_dns_total: int = 0
    _minute_window_start: float = field(default_factory=time.monotonic)
    _minute_count: int = 0

    @classmethod
    def from_config(cls, config: RunConfig) -> "NetworkPolicy":
        return cls(
            domain=config.domain.lower(),
            mode=config.mode,
            dns_policy=config.dns_policy,
            max_target_http_requests_total=config.max_target_http_requests_total,
            max_target_http_per_host=config.max_target_http_per_host,
            max_target_http_per_minute=config.max_target_http_per_minute,
            max_redirects=config.max_redirects,
            max_bytes_per_response=config.max_bytes_per_response,
            max_target_dns_queries=config.max_target_dns_queries,
        )

    @property
    def allow_target_http(self) -> bool:
        return self.mode == Mode.low_noise

    def classify_http(self, url: str) -> str:
        host = (urlparse(url).hostname or "").lower()
        if host == self.domain or host.endswith(f".{self.domain}"):
            return "target_http"
        return "third_party_http"

    def enforce_http_request(self, method: str, url: str) -> str:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        category = self.classify_http(url)
        if category != "target_http":
            if self.allow_target_http and method.upper() == "HEAD":
                raise NetworkPolicyError("off-domain HEAD requests are blocked in low-noise mode")
            return category

        if not self.allow_target_http:
            raise NetworkPolicyError("target HTTP is disabled in passive mode")
        if self.max_redirects != 0:
            raise NetworkPolicyError("redirects must remain disabled for target HTTP")
        if method.upper() not in {"HEAD", "GET"}:
            raise NetworkPolicyError("only HEAD/GET are allowed for target HTTP")
        if self.target_http_total >= self.max_target_http_requests_total:
            raise NetworkPolicyError("target HTTP total budget exceeded")
        if self.target_http_per_host[host] >= self.max_target_http_per_host:
            raise NetworkPolicyError(f"target HTTP per-host budget exceeded for {host}")

        now = time.monotonic()
        if now - self._minute_window_start >= 60:
            self._minute_window_start = now
            self._minute_count = 0
        if self._minute_count >= self.max_target_http_per_minute:
            raise NetworkPolicyError("target HTTP per-minute budget exceeded")

        self._assert_host_in_scope(host)
        self._assert_public_resolution(host)

        self.target_http_total += 1
        self.target_http_per_host[host] += 1
        self._minute_count += 1
        return category

    def _assert_host_in_scope(self, host: str) -> None:
        if not (host == self.domain or host.endswith(f".{self.domain}")):
            raise NetworkPolicyError("host outside target domain scope")

    def _assert_public_resolution(self, host: str) -> None:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            raise NetworkPolicyError(f"failed to resolve host {host}: {exc}") from exc

        for info in infos:
            ip_raw = info[4][0]
            ip = ipaddress.ip_address(ip_raw)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise NetworkPolicyError(f"blocked target HTTP to non-public IP {ip}")

    def enforce_dns_query(self, query_name: str, record_type: str) -> None:
        q = query_name.lower().rstrip(".")
        rt = record_type.upper()
        if self.dns_policy == DnsPolicy.none:
            raise NetworkPolicyError("DNS policy is none; DNS queries are disabled")
        if self.target_dns_total >= self.max_target_dns_queries:
            raise NetworkPolicyError("target DNS query budget exceeded")

        if self.dns_policy == DnsPolicy.minimal:
            allowed = {
                (self.domain, "TXT"),
                (f"_dmarc.{self.domain}", "TXT"),
                (self.domain, "MX"),
            }
            if (q, rt) not in allowed:
                raise NetworkPolicyError(f"DNS query blocked by minimal policy: {q} {rt}")

        self.target_dns_total += 1

    def budgets(self) -> dict[str, Any]:
        return {
            "allow_target_http": self.allow_target_http,
            "dns_policy": self.dns_policy.value,
            "max_target_http_requests_total": self.max_target_http_requests_total,
            "max_target_http_per_host": self.max_target_http_per_host,
            "max_target_http_per_minute": self.max_target_http_per_minute,
            "max_redirects": self.max_redirects,
            "max_bytes_per_response": self.max_bytes_per_response,
            "max_target_dns_queries": self.max_target_dns_queries,
        }
