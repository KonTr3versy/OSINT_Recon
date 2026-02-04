from __future__ import annotations

from datetime import datetime

from ..models.results import ScopeInitResult
from ..utils.normalize import normalize_domain


def run(domain: str, config_snapshot: dict) -> ScopeInitResult:
    normalized = normalize_domain(domain)
    run_id = config_snapshot["run_id"]
    timestamp = datetime.utcnow().isoformat()
    return ScopeInitResult(
        normalized_domain=normalized,
        run_id=run_id,
        timestamp=timestamp,
        config_snapshot=config_snapshot,
    )
