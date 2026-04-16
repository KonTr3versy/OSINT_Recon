from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional

from ..models.results import TlsProfileResult
from ..utils.network import NetworkLedger, NetworkPolicy, NetworkPolicyError

_TLS_PORT = 443
# Cap to stay within the target HTTP budget (each check consumes one slot).
_MAX_HOSTS = 10


def _parse_cert_date(date_str: str) -> datetime | None:
    """Parse ssl.getpeercert() date string into a UTC datetime."""
    try:
        ts = ssl.cert_time_to_seconds(date_str)  # handles "Jan  1 00:00:00 2025 GMT"
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None


def _get_cn(rdns: tuple) -> str | None:
    """Extract commonName from a getpeercert() subject/issuer tuple."""
    for rdn in rdns:
        for name, value in rdn:
            if name == "commonName":
                return value
    return None


def parse_cert_dict(cert: dict) -> dict:
    """Convert a raw ssl.getpeercert() dict into structured metadata.

    Public so it can be unit-tested without a real TLS connection.
    """
    expiry_dt = _parse_cert_date(cert.get("notAfter", ""))
    issued_dt = _parse_cert_date(cert.get("notBefore", ""))
    days_until_expiry = (
        (expiry_dt - datetime.now(timezone.utc)).days if expiry_dt else None
    )

    sans: list[str] = [
        value.lower()
        for kind, value in cert.get("subjectAltName", [])
        if kind.upper() == "DNS"
    ]

    subject_cn = _get_cn(cert.get("subject", ()))
    issuer_cn = _get_cn(cert.get("issuer", ()))
    is_self_signed = bool(subject_cn and issuer_cn and subject_cn == issuer_cn)
    has_wildcard = any(san.startswith("*.") for san in sans)

    return {
        "not_before": issued_dt.isoformat() if issued_dt else None,
        "not_after": expiry_dt.isoformat() if expiry_dt else None,
        "days_until_expiry": days_until_expiry,
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "sans": sans,
        "is_self_signed": is_self_signed,
        "has_wildcard": has_wildcard,
    }


def _check_host_tls(host: str, timeout: float = 5.0) -> dict:
    """Perform a TLS handshake with host and return certificate metadata.

    Attempt 1 — strict validation (CERT_REQUIRED):
        If the cert is valid, returns it fully parsed.
    Attempt 2 — CERT_NONE fallback:
        Used when validation fails (self-signed, expired, hostname mismatch).
        Certificate is still parsed; is_self_signed is forced True.
    """
    result: dict = {"host": host, "error": None, "cert": None, "tls_ok": False}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, _TLS_PORT), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                raw = ssock.getpeercert()
                if raw:
                    result["cert"] = parse_cert_dict(raw)
                result["tls_ok"] = True
                return result
    except ssl.SSLCertVerificationError:
        pass  # cert exists but failed validation — fall through
    except (ssl.SSLError, OSError) as exc:
        result["error"] = str(exc)
        return result

    # Fallback: inspect the certificate without verification.
    ctx_loose = ssl.create_default_context()
    ctx_loose.check_hostname = False
    ctx_loose.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, _TLS_PORT), timeout=timeout) as sock:
            with ctx_loose.wrap_socket(sock, server_hostname=host) as ssock:
                raw = ssock.getpeercert()
                if raw:
                    parsed = parse_cert_dict(raw)
                    parsed["is_self_signed"] = True  # cert failed strict validation
                    result["cert"] = parsed
                else:
                    result["error"] = "certificate present but could not be decoded"
    except (ssl.SSLError, OSError) as exc:
        result["error"] = str(exc)

    return result


def run(
    domain: str,
    portal_candidates: list[str],
    mode: str,
    policy: Optional[NetworkPolicy] = None,
    ledger: Optional[NetworkLedger] = None,
    timeout: float = 5.0,
) -> TlsProfileResult:
    """Inspect live TLS certificates for portal candidates (low-noise mode only).

    Uses stdlib ssl/socket — zero new dependencies. Each check consumes one
    target_http budget slot. SANs found in certificates may reveal additional
    subdomains not yet in the passive discovery list.
    """
    if mode != "low-noise":
        return TlsProfileResult(
            status="skipped",
            skipped_reason=f"mode={mode}; TLS profile checks require low-noise mode",
        )

    warnings: list[str] = []
    hosts = list(dict.fromkeys(portal_candidates))[:_MAX_HOSTS]
    host_results: list[dict] = []
    new_subdomains: list[str] = []
    known = set(portal_candidates)

    for host in hosts:
        if policy:
            try:
                policy.enforce_http_request("HEAD", f"https://{host}")
            except NetworkPolicyError as exc:
                warnings.append(f"Budget limit reached before {host}: {exc}")
                break

        t0 = time.monotonic()
        host_result = _check_host_tls(host, timeout=timeout)
        duration_ms = int((time.monotonic() - t0) * 1000)

        if ledger:
            ledger.add(
                type="target_http",
                destination_host=host,
                url=f"https://{host}:{_TLS_PORT}",
                method="TLS_HANDSHAKE",
                status="ok" if host_result["tls_ok"] else "error",
                error=host_result.get("error"),
                duration_ms=duration_ms,
            )

        host_results.append(host_result)

        # Harvest subdomains from SANs that are within scope but not yet known.
        cert = host_result.get("cert") or {}
        for san in cert.get("sans", []):
            bare = san.lstrip("*.")
            if bare.endswith(f".{domain}") and bare not in known:
                new_subdomains.append(bare)
                known.add(bare)

    if len(portal_candidates) > _MAX_HOSTS:
        warnings.append(
            f"Only checked first {_MAX_HOSTS} of {len(portal_candidates)} candidates "
            "to stay within the HTTP budget."
        )

    return TlsProfileResult(
        status="ok",
        hosts=host_results,
        new_subdomains_from_san=list(dict.fromkeys(new_subdomains)),
        warnings=warnings,
    )
