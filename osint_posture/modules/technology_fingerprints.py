from __future__ import annotations


def _append_hint(hints: list[dict], source: str, value: str, evidence: str) -> None:
    hints.append({"source": source, "technology": value, "evidence": evidence})


def run(dns_mail_profile: dict, subdomains: list[str], resolution: dict, verified_surface: dict) -> dict:
    hints: list[dict] = []
    mx_records = dns_mail_profile.get("records", {}).get("MX", []) if isinstance(dns_mail_profile, dict) else []
    txt_records = dns_mail_profile.get("records", {}).get("TXT", []) if isinstance(dns_mail_profile, dict) else []

    for record in mx_records:
        text = str(record).lower()
        if "mimecast" in text:
            _append_hint(hints, "dns_mail_profile", "Mimecast", str(record))
        if "protection.outlook.com" in text:
            _append_hint(hints, "dns_mail_profile", "Microsoft 365", str(record))
        if "google.com" in text or "googlemail.com" in text:
            _append_hint(hints, "dns_mail_profile", "Google Workspace", str(record))

    for record in txt_records:
        text = str(record).lower()
        if "spf.protection.outlook.com" in text or "ms=" in text:
            _append_hint(hints, "dns_mail_profile", "Microsoft 365", str(record)[:160])
        if "_spf.google.com" in text or "google-site-verification" in text:
            _append_hint(hints, "dns_mail_profile", "Google Workspace", str(record)[:160])
        if "hubspot" in text:
            _append_hint(hints, "dns_mail_profile", "HubSpot", str(record)[:160])

    for subdomain in subdomains:
        text = subdomain.lower()
        if "okta" in text:
            _append_hint(hints, "subdomain_inventory", "Okta", subdomain)
        if "adfs" in text:
            _append_hint(hints, "subdomain_inventory", "ADFS", subdomain)
        if "vpn" in text:
            _append_hint(hints, "subdomain_inventory", "Remote access/VPN", subdomain)

    for item in resolution.get("resolved", []) if isinstance(resolution, dict) else []:
        records = item.get("records", {}) if isinstance(item, dict) else {}
        for cname in records.get("CNAME", []) if isinstance(records, dict) else []:
            text = str(cname).lower()
            if "cloudfront.net" in text:
                _append_hint(hints, "subdomain_resolution", "AWS CloudFront", str(cname))
            if "azure" in text:
                _append_hint(hints, "subdomain_resolution", "Microsoft Azure", str(cname))
            if "cloudflare" in text:
                _append_hint(hints, "subdomain_resolution", "Cloudflare", str(cname))

    for item in verified_surface.get("hosts", []) if isinstance(verified_surface, dict) else []:
        headers = item.get("headers", {}) if isinstance(item, dict) else {}
        server = headers.get("server") or headers.get("Server")
        powered_by = headers.get("x-powered-by") or headers.get("X-Powered-By")
        if server:
            _append_hint(hints, "verified_surface", f"Server: {server}", item.get("url", ""))
        if powered_by:
            _append_hint(hints, "verified_surface", f"X-Powered-By: {powered_by}", item.get("url", ""))

    deduped = []
    seen = set()
    for hint in hints:
        key = (hint["source"], hint["technology"], hint["evidence"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hint)

    return {
        "status": "ok",
        "hints": deduped,
        "count": len(deduped),
        "note": "Fingerprints are deterministic hints from DNS, headers, and hostnames; validate before remediation.",
    }
