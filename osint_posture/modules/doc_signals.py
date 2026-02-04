from __future__ import annotations

from typing import Iterable

from ..models.results import DocSignalsResult
from ..utils.http import HttpClient

DOCUMENT_EXTS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")
COMMON_PATHS = ["/privacy", "/security", "/policies", "/documents"]


def build_candidates(domain: str, subdomains: Iterable[str]) -> list[str]:
    urls = []
    for sub in set([f"www.{domain}"] + list(subdomains)):
        for path in COMMON_PATHS:
            urls.append(f"https://{sub}{path}")
    return urls


async def run(domain: str, subdomains: list[str], http: HttpClient, max_pages: int) -> DocSignalsResult:
    docs = []
    candidates = build_candidates(domain, subdomains)[:max_pages]
    for url in candidates:
        try:
            resp = await http.head(url)
            content_type = resp.headers.get("content-type", "")
            content_len = resp.headers.get("content-length")
            if content_len and int(content_len) > 5_000_000:
                continue
            if any(ext in url for ext in DOCUMENT_EXTS) or "pdf" in content_type:
                docs.append(
                    {
                        "url": url,
                        "type": content_type or "unknown",
                        "discovered_via": "heuristic",
                        "metadata_summary": {
                            "content_type": content_type,
                            "content_length": content_len,
                        },
                    }
                )
        except Exception:
            continue

    return DocSignalsResult(documents=docs)
