from __future__ import annotations

import re
from typing import Dict, List

from ..models.results import DnsMailProfileResult
from ..utils.dns import resolve_records

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "k2"]

SPF_RE = re.compile(r"v=spf1\s+(.*)", re.IGNORECASE)
DMARC_RE = re.compile(r"v=DMARC1;\s*(.*)", re.IGNORECASE)


def parse_spf(txt_records: List[str]) -> Dict:
    spf = {"raw": None, "mechanisms": [], "all": None, "warnings": []}
    for rec in txt_records:
        match = SPF_RE.search(rec)
        if not match:
            continue
        spf["raw"] = rec
        parts = match.group(1).split()
        for part in parts:
            if part.endswith("all"):
                spf["all"] = part
                if part.startswith("~"):
                    spf["warnings"].append("SPF uses softfail (~all). Consider -all for stricter policy.")
                if part.startswith("+") or part == "all":
                    spf["warnings"].append("SPF allows all. Consider restricting with -all.")
            else:
                spf["mechanisms"].append(part)
        if "include:" in rec and rec.count("include:") > 5:
            spf["warnings"].append("SPF contains many includes; review for overly broad scope.")
        break
    if not spf["raw"]:
        spf["warnings"].append("No SPF record found.")
    return spf


def parse_dmarc(txt_records: List[str]) -> Dict:
    dmarc = {
        "raw": None,
        "policy": None,
        "pct": None,
        "rua": None,
        "ruf": None,
        "alignment": {},
        "warnings": [],
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
            if tag.startswith("ruf="):
                dmarc["ruf"] = tag.split("=", 1)[1]
            if tag.startswith("adkim="):
                dmarc["alignment"]["adkim"] = tag.split("=", 1)[1]
            if tag.startswith("aspf="):
                dmarc["alignment"]["aspf"] = tag.split("=", 1)[1]
        if dmarc["policy"] in ("none", None):
            dmarc["warnings"].append("DMARC policy is none; consider quarantine or reject.")
        if dmarc["pct"] and dmarc["pct"] != "100":
            dmarc["warnings"].append("DMARC enforcement is not 100% (pct != 100).")
        break
    if not dmarc["raw"]:
        dmarc["warnings"].append("No DMARC record found.")
    return dmarc


def check_dkim(domain: str, enhanced: bool) -> Dict:
    if not enhanced:
        return {"status": "unknown", "selectors_checked": [], "found": []}
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
