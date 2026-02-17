import asyncio

from osint_posture.modules.passive_users import _confidence, _query_terms, run


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _Http:
    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(url)
        if self.payloads:
            return _Resp(self.payloads.pop(0))
        raise RuntimeError("boom")


def test_query_terms_expand_and_dedupe():
    terms = _query_terms("example.com", "Example Org")
    assert terms[0] == "example.com"
    assert "example" in terms
    assert "exampleorg" in terms
    assert "example-org" in terms


def test_confidence_rules():
    assert _confidence("example", "example", "example.com") == "high"
    assert _confidence("example-sec", "example", "example.com") == "medium"
    assert _confidence("alice", "example", "example.com") == "low"


def test_passive_users_collects_from_multiple_sources_and_sorts():
    http = _Http(
        [
            {"items": [{"login": "example", "html_url": "g1", "type": "User", "score": 10.0}]},
            {"completions": [{"components": {"username": {"val": "example-sec"}}}]},
            {"items": [{"login": "alice", "html_url": "g2", "type": "User", "score": 1.0}]},
            {"completions": []},
        ]
    )
    result = asyncio.run(run("example.com", None, http, max_results=10))
    assert result["status"] == "ok"
    handles = [u["handle"] for u in result["users"]]
    assert handles[0] == "example"
    assert "example-sec" in handles
    assert result["attribution"]["per_source_counts"]["github_search"] >= 1
    assert result["attribution"]["per_source_counts"]["keybase_autocomplete"] >= 1


def test_passive_users_handles_source_errors():
    class _ErrHttp:
        async def get(self, url, **kwargs):
            raise RuntimeError("nope")

    result = asyncio.run(run("example.com", None, _ErrHttp(), max_results=5))
    assert result["users"] == []
    assert result["warnings"]
