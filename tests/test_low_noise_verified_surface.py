import asyncio

from osint_posture.modules import passive_tool_subdomains, subdomain_resolution, verified_surface, well_known_metadata


def test_passive_tool_subdomains_missing_tools_skip_without_failure(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda command: None)

    result = asyncio.run(passive_tool_subdomains.run("example.com", "low-noise", "full", enabled=True))

    assert result["status"] == "skipped"
    assert result["subdomains"] == []
    assert "subfinder skipped" in " ".join(result["attribution"]["warnings"])


def test_passive_tool_subdomains_filters_out_of_scope_hosts(monkeypatch):
    async def fake_run_tool(source, command):
        return ["login.example.com", "evil.com", "*.vpn.example.com"], None

    monkeypatch.setattr(passive_tool_subdomains, "_run_tool", fake_run_tool)

    result = asyncio.run(passive_tool_subdomains.run("example.com", "low-noise", "full", enabled=True))

    assert result["status"] == "ok"
    assert result["subdomains"] == ["login.example.com", "vpn.example.com"]
    assert result["rejected_by_scope"] == 2
    assert ["subfinder", "-silent", "-passive", "-d", "example.com"] in result["allowlisted_commands"]


def test_subdomain_resolution_respects_mode_and_records_resolved_hosts():
    skipped = subdomain_resolution.run("example.com", ["login.example.com"], "passive", "minimal", _FakeDns({}), 25, enabled=True)
    assert skipped["status"] == "skipped"

    dns = _FakeDns({("login.example.com", "A"): ["203.0.113.10"], ("www.example.com", "CNAME"): ["example.com."]})
    result = subdomain_resolution.run("example.com", ["login.example.com"], "low-noise", "full", dns, 9, enabled=True)

    assert result["status"] == "ok"
    assert any(item["host"] == "login.example.com" for item in result["resolved"])
    assert ("login.example.com", "A") in dns.queries


def test_verified_surface_uses_head_only_and_preserves_headers():
    http = _FakeHttp()
    resolution = {"resolved": [{"host": "login.example.com", "records": {"A": ["203.0.113.10"]}}]}

    skipped = asyncio.run(verified_surface.run("example.com", resolution, "low-noise", "minimal", http, 2, enabled=True))
    assert skipped["status"] == "skipped"

    result = asyncio.run(verified_surface.run("example.com", resolution, "low-noise", "full", http, 2, enabled=True))

    assert result["hosts"][0]["method"] == "HEAD"
    assert http.calls == ["https://example.com", "https://www.example.com"]
    assert "x-frame-options" in result["security_headers"][0]["missing"]


def test_well_known_metadata_uses_head_only_with_fixed_paths():
    http = _FakeHttp()

    result = asyncio.run(well_known_metadata.run("example.com", {"resolved": []}, "low-noise", "full", http, 1, enabled=True))

    assert len(result["checks"]) == 3
    assert all(check["method"] == "HEAD" for check in result["checks"])
    assert http.calls == [
        "https://example.com/.well-known/security.txt",
        "https://example.com/security.txt",
        "https://example.com/.well-known/change-password",
    ]


class _FakeDns:
    def __init__(self, records):
        self.records = records
        self.queries = []

    def resolve_records(self, host, record_type):
        self.queries.append((host, record_type))
        return self.records.get((host, record_type), [])


class _FakeResponse:
    status_code = 200
    headers = {"server": "nginx"}


class _FakeHttp:
    def __init__(self):
        self.calls = []

    async def head(self, url, **kwargs):
        self.calls.append(url)
        return _FakeResponse()
