from datetime import datetime, timezone

from osint_posture.models.config import CacheMode, DnsPolicy, Mode, RunConfig
from osint_posture.pipeline.runner import run_pipeline_sync


def test_pipeline_runs_passive_users_and_writes_raw_artifact(tmp_path, monkeypatch):
    async def fake_passive_users(domain, company, http, max_results=10):
        return {
            "status": "ok",
            "users": [{"handle": "example-user", "query": company}],
            "warnings": [],
            "attribution": {"sources": ["test"]},
        }

    monkeypatch.setattr("osint_posture.pipeline.runner.passive_users.run", fake_passive_users)
    monkeypatch.setattr(
        "osint_posture.pipeline.runner.passive_subdomains.run",
        lambda domain, http, cache: _async_result({"subdomains": [], "attribution": {}}),
    )
    monkeypatch.setattr(
        "osint_posture.pipeline.runner.third_party_intel.run",
        lambda domain, enable, shodan_key, censys_id, censys_secret, http: _async_result({"status": "skipped"}),
    )

    config = RunConfig(
        domain="example.com",
        company="Example",
        mode=Mode.passive,
        dns_policy=DnsPolicy.none,
        cache=CacheMode.none,
        out_dir=str(tmp_path),
        run_id="test-run",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    result = run_pipeline_sync(config)

    module_names = [module["module"] for module in result["modules"]]
    assert "passive_users" in module_names
    raw = tmp_path / "example.com" / "20260101_000000" / "raw" / "passive_users.json"
    assert raw.exists()
    assert "example-user" in raw.read_text(encoding="utf-8")


async def _async_result(value):
    return value
