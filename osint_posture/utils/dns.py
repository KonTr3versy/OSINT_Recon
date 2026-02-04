from __future__ import annotations

import logging
from typing import List

import dns.resolver

logger = logging.getLogger(__name__)


def resolve_records(domain: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [r.to_text() for r in answers]
    except Exception as exc:  # pragma: no cover - network
        logger.debug("dns lookup failed", extra={"domain": domain, "type": record_type, "error": str(exc)})
        return []
