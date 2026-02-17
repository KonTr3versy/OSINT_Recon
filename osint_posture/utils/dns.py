from __future__ import annotations

import logging
import time
from typing import List

import dns.resolver

from .network import NetworkLedger, NetworkPolicy, NetworkPolicyError

logger = logging.getLogger(__name__)


class DnsClient:
    def __init__(self, policy: NetworkPolicy | None = None, ledger: NetworkLedger | None = None) -> None:
        self.policy = policy
        self.ledger = ledger

    def resolve_records(self, domain: str, record_type: str) -> List[str]:
        start = time.monotonic()
        success = False
        error: str | None = None
        values: list[str] = []
        try:
            if self.policy:
                self.policy.enforce_dns_query(domain, record_type)
            answers = dns.resolver.resolve(domain, record_type)
            values = [r.to_text() for r in answers]
            success = True
            return values
        except NetworkPolicyError as exc:
            error = str(exc)
            logger.debug("dns query blocked", extra={"domain": domain, "type": record_type, "error": error})
            return []
        except Exception as exc:  # pragma: no cover - network
            error = str(exc)
            logger.debug("dns lookup failed", extra={"domain": domain, "type": record_type, "error": error})
            return []
        finally:
            if self.ledger:
                self.ledger.add(
                    type="target_dns",
                    destination_host=domain,
                    query_name=domain,
                    record_type=record_type.upper(),
                    method="DNS",
                    status="ok" if success else "error",
                    error=error,
                    success=success,
                    duration_ms=int((time.monotonic() - start) * 1000),
                )


def resolve_records(domain: str, record_type: str, client: DnsClient | None = None) -> List[str]:
    resolver = client or DnsClient()
    return resolver.resolve_records(domain, record_type)
