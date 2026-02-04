from __future__ import annotations

import re

DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$")


def normalize_domain(domain: str) -> str:
    value = domain.strip().lower()
    value = value.rstrip(".")
    return value


def is_valid_subdomain(name: str) -> bool:
    if not DOMAIN_RE.match(name):
        return False
    if ".." in name:
        return False
    return True


def normalize_subdomain(name: str) -> str:
    value = name.strip().lower().rstrip(".")
    value = value.lstrip("*.")
    return value


def dedupe_subdomains(names: list[str]) -> list[str]:
    seen = set()
    out = []
    for raw in names:
        value = normalize_subdomain(raw)
        if not value or not is_valid_subdomain(value):
            continue
        if value not in seen:
            seen.add(value)
            out.append(value)
    return sorted(out)


def sanitize_headers(headers: dict) -> dict:
    sanitized = {}
    for k, v in headers.items():
        key = k.lower()
        if key in {"authorization", "cookie", "set-cookie"}:
            sanitized[k] = "[redacted]"
        else:
            sanitized[k] = v
    return sanitized
