from __future__ import annotations

from dataclasses import dataclass

from ..models.config import RunConfig
from ..utils.cache import CacheBase
from ..utils.dns import DnsClient
from ..utils.http import HttpClient
from ..utils.network import NetworkLedger, NetworkPolicy


@dataclass
class RunContext:
    config: RunConfig
    policy: NetworkPolicy
    ledger: NetworkLedger
    http_client: HttpClient
    dns_client: DnsClient
    cache: CacheBase | None
