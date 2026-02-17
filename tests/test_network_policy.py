from datetime import datetime
import httpx
import pytest

from osint_posture.models.config import DnsPolicy, Mode, RunConfig
from osint_posture.utils.dns import DnsClient
from osint_posture.utils.http import HttpClient
from osint_posture.utils.network import NetworkLedger, NetworkPolicy, NetworkPolicyError


def _config(**overrides):
    base = dict(
        domain="example.com",
        run_id="r1",
        timestamp=datetime.utcnow(),
    )
    base.update(overrides)
    return RunConfig(**base)


def test_policy_alias_defaults_and_ledger_totals():
    ledger = NetworkLedger()
    ledger.add(type="third_party_http", destination_host="crt.sh", method="GET")
    ledger.add(type="target_dns", destination_host="example.com", method="DNS")
    totals = ledger.totals()
    assert totals["counts"]["third_party_http"] == 1
    assert totals["counts"]["target_dns"] == 1


def test_policy_blocks_off_domain_hosts():
    policy = NetworkPolicy.from_config(_config(mode=Mode.low_noise))
    with pytest.raises(NetworkPolicyError):
        policy.enforce_http_request("HEAD", "https://evil.com")


def test_policy_blocks_redirect_when_budget_nonzero():
    policy = NetworkPolicy.from_config(_config(mode=Mode.low_noise, max_redirects=1))
    with pytest.raises(NetworkPolicyError):
        policy.enforce_http_request("HEAD", "https://example.com")


def test_policy_blocks_private_ip_resolution(monkeypatch):
    policy = NetworkPolicy.from_config(_config(mode=Mode.low_noise))

    def fake_getaddrinfo(host, port):
        return [(None, None, None, None, ("127.0.0.1", 0))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(NetworkPolicyError):
        policy.enforce_http_request("HEAD", "https://example.com")


def test_http_follow_redirects_disabled_and_byte_cap(monkeypatch):
    policy = NetworkPolicy.from_config(_config(mode=Mode.low_noise, max_bytes_per_response=3))
    ledger = NetworkLedger()
    client = HttpClient(policy=policy, ledger=ledger, retries=0)
    assert client.follow_redirects is False

    class FakeStream:
        status_code = 200
        headers = {}
        request = httpx.Request("HEAD", "https://example.com")

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def aiter_bytes(self):
            yield b"abcd"

    monkeypatch.setattr(client._client, "stream", lambda *args, **kwargs: FakeStream())
    monkeypatch.setattr("socket.getaddrinfo", lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))])

    with pytest.raises(NetworkPolicyError):
        import asyncio

        asyncio.run(client.request("HEAD", "https://example.com"))


def test_dns_policy_none_and_minimal(monkeypatch):
    none_policy = NetworkPolicy.from_config(_config(dns_policy=DnsPolicy.none))
    dns_none = DnsClient(policy=none_policy)
    assert dns_none.resolve_records("example.com", "TXT") == []

    minimal_policy = NetworkPolicy.from_config(_config(dns_policy=DnsPolicy.minimal))
    dns_min = DnsClient(policy=minimal_policy)

    class FakeAnswer:
        def __init__(self, value):
            self.value = value

        def to_text(self):
            return self.value

    monkeypatch.setattr("dns.resolver.resolve", lambda *args, **kwargs: [FakeAnswer("ok")])
    assert dns_min.resolve_records("example.com", "TXT") == ["ok"]
    assert dns_min.resolve_records("example.com", "A") == []
