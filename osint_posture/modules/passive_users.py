from __future__ import annotations

from urllib.parse import quote

from ..utils.http import HttpClient


def _query_terms(domain: str, company: str | None) -> list[str]:
    terms = [domain]
    if company:
        terms.append(company)
    return list(dict.fromkeys([t.strip() for t in terms if t and t.strip()]))


async def run(domain: str, company: str | None, http: HttpClient, max_results: int = 10) -> dict:
    users: list[dict] = []
    warnings: list[str] = []

    for term in _query_terms(domain, company):
        url = f"https://api.github.com/search/users?q={quote(term)}&per_page={max_results}"
        try:
            resp = await http.get(url)
            data = resp.json()
            for item in data.get("items", []):
                users.append(
                    {
                        "handle": item.get("login"),
                        "profile_url": item.get("html_url"),
                        "type": item.get("type"),
                        "score": item.get("score"),
                        "source": "github_search",
                        "query": term,
                    }
                )
        except Exception:
            warnings.append(f"GitHub user search failed for query: {term}")

    # dedupe by handle while preserving order
    deduped: list[dict] = []
    seen = set()
    for user in users:
        key = (user.get("handle") or "").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(user)

    return {
        "status": "ok",
        "users": deduped[:max_results],
        "warnings": warnings,
        "attribution": {
            "sources": ["github_search"],
            "note": "Passive third-party user discovery; validate association before action.",
        },
    }
