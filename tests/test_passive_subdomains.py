import asyncio

from osint_posture.modules.passive_subdomains import _clean_candidates, run


class _Resp:
    def __init__(self, text=None, payload=None):
        self.text = text or ""
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no payload")
        return self._payload


class _Http:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(url)
        return self.responses.pop(0)


def test_clean_candidates_normalizes_and_counts():
    cleaned, wild, invalid = _clean_candidates(["*.a.example.com", "foo.example.com", "bad..example.com"])
    assert "a.example.com" in cleaned
    assert "foo.example.com" in cleaned
    assert wild == 1
    assert invalid == 1


def test_passive_subdomains_aggregates_multiple_sources():
    crt = _Resp(text='[{"name_value":"foo.example.com\\n*.bar.example.com"}]')
    certspotter = _Resp(payload=[{"dns_names": ["api.example.com", "foo.example.com"]}])
    bufferover = _Resp(payload={"FDNS_A": ["1.1.1.1,dev.example.com"]})
    http = _Http([crt, certspotter, bufferover])

    result = asyncio.run(run("example.com", http))
    assert sorted(result.subdomains) == ["api.example.com", "bar.example.com", "dev.example.com", "foo.example.com"]
    assert result.attribution["per_source_counts"]["crt.sh"] == 2
    assert result.attribution["per_source_counts"]["certspotter"] == 2
    assert result.attribution["per_source_counts"]["bufferover"] == 1


def test_passive_subdomains_collects_warnings_on_source_errors():
    class _ErrHttp:
        async def get(self, url, **kwargs):
            raise RuntimeError("down")

    result = asyncio.run(run("example.com", _ErrHttp()))
    assert result.subdomains == []
    assert result.attribution["warnings"]
