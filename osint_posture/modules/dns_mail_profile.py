from __future__ import annotations

import re
from typing import Dict, List

from ..models.results import DnsMailProfileResult
from ..utils.dns import resolve_records

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "k2"]

SPF_RE = re.compile(r"v=spf1\s+(.*)", re.IGNORECASE)
DMARC_RE = re.compile(r"v=DMARC1;\s*(.*)", re.IGNORECASE)


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


def check_dkim(domain: str, enhanced: bool) -> Dict:
    if not enhanced:
        return {
            "status": "unknown",
            "selectors_checked": [],
            "found": [],
            "mode": "passive",
            "note": "Passive mode does not query selectors.",
        }
    found = []
    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        recs = resolve_records(name, "TXT")
        if recs:
            found.append({"selector": selector, "records": recs})
    return {
        "status": "checked",
        "selectors_checked": COMMON_DKIM_SELECTORS,
        "found": found,
        "mode": "enhanced",
        "note": "Enhanced mode checked common safe-list selectors.",
    }


def run(domain: str, enhanced: bool) -> DnsMailProfileResult:
    records = {
        "A": resolve_records(domain, "A"),
        "AAAA": resolve_records(domain, "AAAA"),
        "NS": resolve_records(domain, "NS"),
        "MX": resolve_records(domain, "MX"),
        "TXT": resolve_records(domain, "TXT"),
    }

    spf = parse_spf(records["TXT"])
    dmarc = parse_dmarc(resolve_records(f"_dmarc.{domain}", "TXT"))
    dkim = check_dkim(domain, enhanced)

    risk_flags = []
    recommendations = []

    if spf["warnings"]:
        risk_flags.extend(spf["warnings"])
    if dmarc["warnings"]:
        risk_flags.extend(dmarc["warnings"])

    if spf["raw"] is None:
        recommendations.append("Publish an SPF record scoped to authorized senders.")
    if dmarc["raw"] is None:
        recommendations.append("Publish a DMARC record with at least quarantine policy.")
    if dmarc.get("policy") == "none":
        recommendations.append("Move DMARC policy to quarantine or reject once monitoring is stable.")
    if dkim.get("status") == "checked" and not dkim.get("found"):
        recommendations.append("Confirm DKIM signing is enabled for outbound mail.")

    return DnsMailProfileResult(
        records=records,
        spf=spf,
        dmarc=dmarc,
        dkim=dkim,
        risk_flags=risk_flags,
        recommendations=recommendations,
    )
