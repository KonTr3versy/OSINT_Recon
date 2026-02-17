from __future__ import annotations

from urllib.parse import quote

from ..utils.http import HttpClient


def _base_company_terms(company: str | None) -> list[str]:
    if not company:
        return []
    values = [company.strip()]
    normalized = company.lower().replace(" ", "")
    dashed = company.lower().replace(" ", "-")
    values.extend([normalized, dashed])
    return [v for v in values if v]


def _query_terms(domain: str, company: str | None) -> list[str]:
    domain = domain.strip().lower()
    root = domain.split(".")[0] if "." in domain else domain
    terms = [domain, root]
    terms.extend(_base_company_terms(company))
    return list(dict.fromkeys([t.strip() for t in terms if t and t.strip()]))


def _confidence(handle: str, query: str, domain: str) -> str:
    h = (handle or "").lower()
    q = query.lower()
    d = domain.lower()
    if h == q or h == d:
        return "high"
    if q in h or d.split(".")[0] in h:
        return "medium"
    return "low"


async def _github_users(term: str, domain: str, http: HttpClient, max_results: int) -> tuple[list[dict], str | None]:
    url = f"https://api.github.com/search/users?q={quote(term)}&per_page={max_results}"
    try:
        resp = await http.get(url)
        data = resp.json()
    except Exception as exc:
        return [], f"GitHub user search failed for query '{term}': {exc}"

    out: list[dict] = []
    for item in data.get("items", []) if isinstance(data, dict) else []:
        handle = item.get("login")
        out.append(
            {
                "handle": handle,
                "profile_url": item.get("html_url"),
                "type": item.get("type"),
                "score": item.get("score"),
                "source": "github_search",
                "query": term,
                "confidence": _confidence(str(handle or ""), term, domain),
            }
        )
    return out, None


async def _gitlab_users(term: str, domain: str, http: HttpClient, max_results: int) -> tuple[list[dict], str | None]:
    url = f"https://gitlab.com/api/v4/users?search={quote(term)}&per_page={max_results}"
    try:
        resp = await http.get(url)
        data = resp.json()
    except Exception as exc:
        return [], f"GitLab user search failed for query '{term}': {exc}"

    out: list[dict] = []
    for item in data if isinstance(data, list) else []:
        handle = item.get("username")
        out.append(
            {
                "handle": handle,
                "profile_url": item.get("web_url"),
                "type": "User",
                "score": None,
                "source": "gitlab_search",
                "query": term,
                "confidence": _confidence(str(handle or ""), term, domain),
            }
        )
    return out, None


async def _keybase_users(term: str, domain: str, http: HttpClient, max_results: int) -> tuple[list[dict], str | None]:
    url = f"https://keybase.io/_/api/1.0/user/autocomplete.json?q={quote(term)}"
    try:
        resp = await http.get(url)
        data = resp.json()
    except Exception as exc:
        return [], f"Keybase user search failed for query '{term}': {exc}"

    completions = data.get("completions", []) if isinstance(data, dict) else []
    out: list[dict] = []
    for item in completions[:max_results]:
        handle = item.get("components", {}).get("username", {}).get("val")
        if not handle:
            continue
        out.append(
            {
                "handle": handle,
                "profile_url": f"https://keybase.io/{handle}",
                "type": "User",
                "score": None,
                "source": "keybase_autocomplete",
                "query": term,
                "confidence": _confidence(str(handle), term, domain),
            }
        )
    return out, None


async def run(domain: str, company: str | None, http: HttpClient, max_results: int = 10) -> dict:
    users: list[dict] = []
    warnings: list[str] = []
    per_source_counts = {"github_search": 0, "gitlab_search": 0, "keybase_autocomplete": 0}

    terms = _query_terms(domain, company)
    for term in terms:
        for source_name, fetcher in (
            ("github_search", _github_users),
            ("gitlab_search", _gitlab_users),
            ("keybase_autocomplete", _keybase_users),
        ):
            found, error = await fetcher(term, domain, http, max_results=max_results)
            if error:
                warnings.append(error)
                continue
            users.extend(found)
            per_source_counts[source_name] += len(found)

    deduped: list[dict] = []
    seen = set()
    for user in users:
        handle = (user.get("handle") or "").lower()
        source = user.get("source")
        key = (source, handle)
        if not handle or key in seen:
            continue
        seen.add(key)
        deduped.append(user)

    weight = {"high": 0, "medium": 1, "low": 2}
    deduped.sort(key=lambda u: (weight.get(u.get("confidence", "low"), 3), u.get("handle", "")))

    return {
        "status": "ok",
        "users": deduped[:max_results],
        "warnings": warnings,
        "attribution": {
            "sources": ["github_search", "gitlab_search", "keybase_autocomplete"],
            "per_source_counts": per_source_counts,
            "queries": terms,
            "note": "Passive third-party user discovery; validate association before action.",
        },
    }
