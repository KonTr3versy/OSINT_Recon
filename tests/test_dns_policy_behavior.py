from datetime import datetime

from osint_posture.models.config import DnsPolicy, Mode, RunConfig
from osint_posture.modules import dns_mail_profile
from osint_posture.utils.dns import DnsClient
from osint_posture.utils.network import NetworkLedger, NetworkPolicy


def _client(policy: DnsPolicy) -> DnsClient:
    cfg = RunConfig(domain="example.com", run_id="r", timestamp=datetime.utcnow(), mode=Mode.passive, dns_policy=policy)
    return DnsClient(policy=NetworkPolicy.from_config(cfg), ledger=NetworkLedger())


def test_dns_policy_none_makes_no_dns_attempts(monkeypatch):
    calls = []

    def fake_resolve(*args, **kwargs):
        calls.append(args)
        return []

    monkeypatch.setattr("dns.resolver.resolve", fake_resolve)
    client = _client(DnsPolicy.none)
    result = dns_mail_profile.run("example.com", mode=Mode.passive, dns_client=client)
    assert calls == []
    assert result.records == {"A": [], "AAAA": [], "NS": [], "MX": [], "TXT": []}
    assert any("skipped" in flag.lower() for flag in result.risk_flags)


def test_dns_policy_minimal_only_queries_txt_mx_and_dmarc(monkeypatch):
    calls = []

    class FakeAnswer:
        def __init__(self, value):
            self.value = value

        def to_text(self):
            return self.value

    def fake_resolve(name, record_type):
        calls.append((name, record_type))
        return [FakeAnswer("v=spf1 -all")]

    monkeypatch.setattr("dns.resolver.resolve", fake_resolve)
    client = _client(DnsPolicy.minimal)
    dns_mail_profile.run("example.com", mode=Mode.passive, dns_client=client)
    assert calls == [
        ("example.com", "MX"),
        ("example.com", "TXT"),
        ("_dmarc.example.com", "TXT"),
    ]
