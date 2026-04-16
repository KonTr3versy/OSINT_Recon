from __future__ import annotations

import re
from typing import Dict, List

from ..models.config import DnsPolicy, Mode
from ..models.results import DnsMailProfileResult
from ..utils.dns import DnsClient, resolve_records

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "k2"]

SPF_RE = re.compile(r"v=spf1\s+(.*)", re.IGNORECASE)
DMARC_RE = re.compile(r"v=DMARC1;\s*(.*)", re.IGNORECASE)
_MTA_STS_RE = re.compile(r"v=STSv1", re.IGNORECASE)
_TLS_RPT_RE = re.compile(r"v=TLSRPTv1", re.IGNORECASE)
_BIMI_RE = re.compile(r"v=BIMI1", re.IGNORECASE)


def parse_spf(txt_records: List[str]) -> Dict:
    spf = {
        "raw": None,
        "mechanisms": [],
        "all": None,
        "warnings": [],
        "redirect": None,
        "exp": None,
        "include_count": 0,
        "has_overly_broad_ip": False,
    }
    for rec in txt_records:
        match = SPF_RE.search(rec)
        if not match:
            continue
        spf["raw"] = rec
        parts = match.group(1).split()
        for part in parts:
            if part.startswith("redirect="):
                spf["redirect"] = part.split("=", 1)[1]
                continue
            if part.startswith("exp="):
                spf["exp"] = part.split("=", 1)[1]
                continue
            if part.startswith("include:"):
                spf["include_count"] += 1
            if part.endswith("all"):
                spf["all"] = part
                if part.startswith("~"):
                    spf["warnings"].append("SPF uses softfail (~all). Consider -all for stricter policy.")
                if part.startswith("+") or part == "all" or part.startswith("?"):
                    spf["warnings"].append("SPF allows all. Consider restricting with -all.")
            else:
                spf["mechanisms"].append(part)
        if spf["include_count"] > 10:
            spf["warnings"].append("SPF contains many includes; review for overly broad scope.")
        if "ip4:0.0.0.0/0" in rec or "ip6::/0" in rec:
            spf["has_overly_broad_ip"] = True
            spf["warnings"].append("SPF contains overly broad IP ranges (0.0.0.0/0 or ::/0).")
        break
    if not spf["raw"]:
        spf["warnings"].append("No SPF record found.")
    return spf


def _parse_mailto(value: str) -> list[str]:
    uris = []
    for item in value.split(","):
        item = item.strip()
        if item.lower().startswith("mailto:"):
            uris.append(item)
    return uris


def parse_dmarc(txt_records: List[str]) -> Dict:
    dmarc = {
        "raw": None,
        "policy": None,
        "pct": None,
        "rua": None,
        "ruf": None,
        "alignment": {},
        "warnings": [],
        "valid": True,
        "invalid_tags": [],
        "rua_parsed": [],
        "ruf_parsed": [],
    }
    for rec in txt_records:
        match = DMARC_RE.search(rec)
        if not match:
            continue
        dmarc["raw"] = rec
        tags = match.group(1).split(";")
        for tag in tags:
            tag = tag.strip()
            if not tag:
                continue
            if tag.startswith("p="):
                dmarc["policy"] = tag.split("=", 1)[1]
            if tag.startswith("pct="):
                dmarc["pct"] = tag.split("=", 1)[1]
            if tag.startswith("rua="):
                dmarc["rua"] = tag.split("=", 1)[1]
                dmarc["rua_parsed"] = _parse_mailto(dmarc["rua"])
            if tag.startswith("ruf="):
                dmarc["ruf"] = tag.split("=", 1)[1]
                dmarc["ruf_parsed"] = _parse_mailto(dmarc["ruf"])
            if tag.startswith("adkim="):
                dmarc["alignment"]["adkim"] = tag.split("=", 1)[1]
            if tag.startswith("aspf="):
                dmarc["alignment"]["aspf"] = tag.split("=", 1)[1]
        if dmarc["policy"] not in (None, "none", "quarantine", "reject"):
            dmarc["valid"] = False
            dmarc["invalid_tags"].append("p")
        if dmarc["pct"] is not None:
            try:
                pct_val = int(dmarc["pct"])
                if pct_val < 0 or pct_val > 100:
                    raise ValueError
            except ValueError:
                dmarc["valid"] = False
                dmarc["invalid_tags"].append("pct")
        if dmarc["policy"] in ("none", None):
            dmarc["warnings"].append("DMARC policy is none; consider quarantine or reject.")
        if dmarc["pct"] and dmarc["pct"] != "100":
            dmarc["warnings"].append("DMARC enforcement is not 100% (pct != 100).")
        if dmarc["policy"] in ("quarantine", "reject") and not dmarc.get("rua"):
            dmarc["warnings"].append("DMARC policy is enforce but rua reporting is missing.")
        break
    if not dmarc["raw"]:
        dmarc["warnings"].append("No DMARC record found.")
    return dmarc


def check_dkim(domain: str, mode: Mode, dns_client: DnsClient | None = None) -> Dict:
    if mode != Mode.low_noise:
        return {
            "status": "unknown",
            "selectors_checked": [],
            "found": [],
            "mode": "passive",
            "note": "Passive mode does not query DKIM selectors.",
        }
    effective_dns_policy = (
        dns_client.policy.dns_policy if (dns_client and dns_client.policy) else DnsPolicy.full
    )
    if effective_dns_policy != DnsPolicy.full:
        return {
            "status": "skipped",
            "selectors_checked": [],
            "found": [],
            "mode": "low-noise",
            "note": "DKIM selector checks require --dns-policy full.",
        }
    found = []
    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        recs = resolve_records(name, "TXT", client=dns_client)
        if recs:
            found.append({"selector": selector, "records": recs})
    return {
        "status": "checked",
        "selectors_checked": COMMON_DKIM_SELECTORS,
        "found": found,
        "mode": "low-noise",
        "note": "Low-noise mode checked common safe-list selectors.",
    }


def check_mta_sts(domain: str, dns_client: DnsClient | None = None) -> dict:
    """Check for an MTA-STS TXT record at _mta-sts.<domain> (RFC 8461).

    MTA-STS enforces TLS for inbound SMTP. The TXT record signals its presence;
    the full policy (mode: enforce/testing/none) lives in the HTTPS policy file
    which requires an HTTP request and is not fetched here.
    """
    recs = resolve_records(f"_mta-sts.{domain}", "TXT", client=dns_client)
    raw = next((r for r in recs if _MTA_STS_RE.search(r)), None)
    return {
        "raw": raw,
        "present": raw is not None,
        "note": (
            "Policy mode (enforce/testing/none) requires fetching "
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        ),
    }


def check_tls_rpt(domain: str, dns_client: DnsClient | None = None) -> dict:
    """Check for a TLS-RPT TXT record at _smtp._tls.<domain> (RFC 8460).

    TLS-RPT enables SMTP TLS failure reporting. Should be present alongside MTA-STS.
    """
    recs = resolve_records(f"_smtp._tls.{domain}", "TXT", client=dns_client)
    raw = next((r for r in recs if _TLS_RPT_RE.search(r)), None)
    rua = None
    if raw:
        for tag in raw.strip('"').split(";"):
            tag = tag.strip()
            if tag.lower().startswith("rua="):
                rua = tag.split("=", 1)[1].strip()
                break
    return {"raw": raw, "present": raw is not None, "rua": rua}


def check_bimi(domain: str, dns_client: DnsClient | None = None) -> dict:
    """Check for a BIMI TXT record at default._bimi.<domain> (RFC 9091).

    BIMI (Brand Indicators for Message Identification) requires enforced DMARC.
    Absence is not a risk signal; presence indicates email brand maturity.
    """
    recs = resolve_records(f"default._bimi.{domain}", "TXT", client=dns_client)
    raw = next((r for r in recs if _BIMI_RE.search(r)), None)
    location = authority = None
    if raw:
        for tag in raw.strip('"').split(";"):
            tag = tag.strip()
            if tag.lower().startswith("l="):
                location = tag.split("=", 1)[1].strip()
            elif tag.lower().startswith("a="):
                authority = tag.split("=", 1)[1].strip()
    return {
        "raw": raw,
        "present": raw is not None,
        "location": location,
        "authority": authority,
    }


def _extract_mx_hostnames(mx_records: list[str]) -> list[str]:
    """Parse hostnames from MX record strings like '10 mail.example.com.'"""
    hosts: list[str] = []
    for rec in mx_records:
        parts = rec.split()
        if len(parts) >= 2:
            host = parts[-1].rstrip(".")
            if host:
                hosts.append(host)
    return hosts


def check_dane(mx_hosts: list[str], dns_client: DnsClient | None = None) -> dict:
    """Check for DANE TLSA records at _25._tcp.<mx-host> (RFC 7671).

    DANE pins MX server certificates via DNS. Absence is informational only.
    Checks the first five MX hosts to stay within DNS budget.
    """
    found: list[dict] = []
    checked = mx_hosts[:5]
    for host in checked:
        name = f"_25._tcp.{host}"
        recs = resolve_records(name, "TLSA", client=dns_client)
        if recs:
            found.append({"host": host, "tlsa_records": recs})
    return {
        "present": len(found) > 0,
        "hosts_with_dane": found,
        "hosts_checked": checked,
    }


def run(domain: str, mode: Mode = Mode.passive, dns_client: DnsClient | None = None) -> DnsMailProfileResult:
    records = {
        "A": resolve_records(domain, "A", client=dns_client),
        "AAAA": resolve_records(domain, "AAAA", client=dns_client),
        "NS": resolve_records(domain, "NS", client=dns_client),
        "MX": resolve_records(domain, "MX", client=dns_client),
        "TXT": resolve_records(domain, "TXT", client=dns_client),
    }

    spf = parse_spf(records["TXT"])
    dmarc = parse_dmarc(resolve_records(f"_dmarc.{domain}", "TXT", client=dns_client))
    dkim = check_dkim(domain, mode=mode, dns_client=dns_client)

    # Extended email authentication checks — require dns_policy=full.
    effective_policy = (
        dns_client.policy.dns_policy if (dns_client and dns_client.policy) else DnsPolicy.full
    )
    _skipped: dict = {"status": "skipped", "note": "Requires dns_policy=full", "present": False}
    if effective_policy == DnsPolicy.full:
        mta_sts = check_mta_sts(domain, dns_client)
        tls_rpt = check_tls_rpt(domain, dns_client)
        bimi = check_bimi(domain, dns_client)
        mx_hosts = _extract_mx_hostnames(records.get("MX", []))
        dane = check_dane(mx_hosts, dns_client)
    else:
        mta_sts = {**_skipped}
        tls_rpt = {**_skipped, "rua": None}
        bimi = {**_skipped, "location": None, "authority": None}
        dane = {**_skipped, "hosts_with_dane": [], "hosts_checked": []}

    risk_flags = []
    recommendations = []

    if dns_client and dns_client.policy and dns_client.policy.dns_policy.value == "none":
        risk_flags.append("DNS policy is none; DNS-based checks were skipped.")
    if spf["warnings"]:
        risk_flags.extend(spf["warnings"])
    if dmarc["warnings"]:
        risk_flags.extend(dmarc["warnings"])
    if not mta_sts.get("present") and mta_sts.get("status") != "skipped":
        risk_flags.append("No MTA-STS record found; inbound TLS not enforced.")
    if mta_sts.get("present") and not tls_rpt.get("present") and tls_rpt.get("status") != "skipped":
        risk_flags.append("MTA-STS present but TLS-RPT reporting not configured.")

    if spf["raw"] is None:
        recommendations.append("Publish an SPF record scoped to authorized senders.")
    if dmarc["raw"] is None:
        recommendations.append("Publish a DMARC record with at least quarantine policy.")
    if dmarc.get("policy") == "none":
        recommendations.append("Move DMARC policy to quarantine or reject once monitoring is stable.")
    if dkim.get("status") == "checked" and not dkim.get("found"):
        recommendations.append("Confirm DKIM signing is enabled for outbound mail.")
    if not mta_sts.get("present") and mta_sts.get("status") != "skipped":
        recommendations.append("Publish MTA-STS to enforce TLS for inbound SMTP (RFC 8461).")

    return DnsMailProfileResult(
        records=records,
        spf=spf,
        dmarc=dmarc,
        dkim=dkim,
        mta_sts=mta_sts,
        tls_rpt=tls_rpt,
        bimi=bimi,
        dane=dane,
        risk_flags=risk_flags,
        recommendations=recommendations,
    )
