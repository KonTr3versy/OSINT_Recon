from __future__ import annotations

import hashlib
import hmac
import os
from enum import StrEnum


class Role(StrEnum):
    admin = "admin"
    analyst = "analyst"
    approver = "approver"
    viewer = "viewer"


ROLE_PERMISSIONS = {
    Role.admin: {
        "assets:write",
        "assets:read",
        "plans:write",
        "plans:read",
        "approvals:decide",
        "runs:write",
        "runs:read",
        "backlog:write",
        "backlog:read",
    },
    Role.analyst: {
        "assets:write",
        "assets:read",
        "plans:write",
        "plans:read",
        "runs:write",
        "runs:read",
        "backlog:write",
        "backlog:read",
    },
    Role.approver: {
        "assets:read",
        "plans:read",
        "approvals:decide",
        "runs:read",
        "backlog:read",
    },
    Role.viewer: {
        "assets:read",
        "plans:read",
        "runs:read",
        "backlog:read",
    },
}


def has_permission(role: str, permission: str) -> bool:
    try:
        return permission in ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return False


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = encoded.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    candidate = hash_password(password, bytes.fromhex(salt_hex)).split("$", 2)[2]
    return hmac.compare_digest(candidate, digest_hex)

