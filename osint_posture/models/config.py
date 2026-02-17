from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Mode(str, Enum):
    passive = "passive"
    low_noise = "low-noise"


class DnsPolicy(str, Enum):
    none = "none"
    minimal = "minimal"
    full = "full"


class CacheMode(str, Enum):
    sqlite = "sqlite"
    files = "files"
    none = "none"


class RunConfig(BaseModel):
    domain: str
    company: Optional[str] = None
    mode: Mode = Mode.passive
    dns_policy: DnsPolicy = DnsPolicy.minimal
    cache: CacheMode = CacheMode.sqlite
    max_requests_per_minute: int = 60
    enable_third_party_intel: bool = False
    shodan_key: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    out_dir: str = "./output"
    run_id: str
    timestamp: datetime
    max_pages: int = 10
    timeout_seconds: float = 8.0
    retries: int = 2
    max_target_http_requests_total: int = 12
    max_target_http_per_host: int = 3
    max_target_http_per_minute: int = 12
    max_redirects: int = 0
    max_bytes_per_response: int = 262_144
    max_target_dns_queries: int = 25

    @property
    def run_path(self) -> str:
        return f"{self.out_dir}/{self.domain}/{self.timestamp.strftime('%Y%m%d_%H%M%S')}"


class ModuleResult(BaseModel):
    module: str
    status: str
    data: dict = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime


class FullRunResult(BaseModel):
    config: RunConfig
    modules: list[ModuleResult]
    synthesis: dict


class SynthesisResult(BaseModel):
    summary: dict
    scoring_rubric: dict
    prioritized_backlog: list[dict]
