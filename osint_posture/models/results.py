from __future__ import annotations

from pydantic import BaseModel, Field


class ScopeInitResult(BaseModel):
    normalized_domain: str
    run_id: str
    timestamp: str
    config_snapshot: dict


class DnsMailProfileResult(BaseModel):
    records: dict
    spf: dict
    dmarc: dict
    dkim: dict
    risk_flags: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class PassiveSubdomainsResult(BaseModel):
    subdomains: list[str]
    attribution: dict
    removed_wildcards: int = 0
    invalid_entries: int = 0
    total_seen: int = 0




class PassiveUsersResult(BaseModel):
    status: str
    users: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    attribution: dict = Field(default_factory=dict)

class ThirdPartyIntelResult(BaseModel):
    status: str
    services: list[dict] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class WebSignalsResult(BaseModel):
    portal_candidates: list[str] = Field(default_factory=list)
    technology_hints: list[str] = Field(default_factory=list)
    headers_samples: list[dict] = Field(default_factory=list)
    security_headers: list[dict] = Field(default_factory=list)


class DocSignalsResult(BaseModel):
    documents: list[dict] = Field(default_factory=list)


class SynthesisModuleResult(BaseModel):
    summary: dict
    scoring_rubric: dict
    prioritized_backlog: list[dict]
    evidence: dict
