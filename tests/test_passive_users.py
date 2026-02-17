import asyncio

from osint_posture.modules.passive_users import _query_terms, run


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


def test_query_terms_dedupes():
    assert _query_terms("example.com", "Example") == ["example.com", "Example"]
    assert _query_terms("example.com", "") == ["example.com"]


def test_passive_users_collects_and_dedupes_handles():
    http = _Http(
        [
            {"items": [{"login": "alice", "html_url": "u1", "type": "User", "score": 1.0}]},
            {"items": [{"login": "alice", "html_url": "u1", "type": "User", "score": 2.0}, {"login": "bob", "html_url": "u2", "type": "User", "score": 3.0}]},
        ]
    )
    result = asyncio.run(run("example.com", "Example", http, max_results=10))
    assert result["status"] == "ok"
    assert [u["handle"] for u in result["users"]] == ["alice", "bob"]
    assert len(http.calls) == 2


def test_passive_users_handles_errors():
    class _ErrHttp:
        async def get(self, url, **kwargs):
            raise RuntimeError("nope")

    result = asyncio.run(run("example.com", None, _ErrHttp(), max_results=5))
    assert result["users"] == []
    assert result["warnings"]
