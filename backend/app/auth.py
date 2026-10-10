"""Session-based authentication with a secure first-run admin account.

On first start (no users in the database) a single ``admin`` account is created
with a randomly generated password that is printed once to the server console.
The account is flagged to force a password change on first login. There is no
hardcoded credential anywhere in the source.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from typing import Optional

from app import db

logger = logging.getLogger("sas.webapp")

_VALID_USERNAME = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

# Stdlib PBKDF2-HMAC-SHA256 password hashing (no external crypto dependency,
# avoiding passlib/bcrypt version-compatibility issues). Format:
#   pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
_ITERATIONS = 240_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = password_hash.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def ensure_first_run_admin() -> None:
    """Create the admin account with a random password if no users exist."""
    if db.user_count() > 0:
        return
    password = secrets.token_urlsafe(15)
    db.create_user("admin", hash_password(password), must_change=True,
                   role="admin")
    banner = "=" * 68
    logger.warning(
        "\n%s\n  FIRST-RUN ADMIN ACCOUNT CREATED\n"
        "  username: admin\n  password: %s\n"
        "  You must change this password at first login. It is shown ONCE.\n%s",
        banner, password, banner,
    )


def authenticate(username: str, password: str) -> Optional[dict]:
    user = db.get_user(username)
    if user is None or not verify_password(password, user["password_hash"]):
        return None
    return {
        "username": user["username"],
        "must_change_password": bool(user["must_change_password"]),
        "role": user["role"],
    }


def create_managed_user(username: str, role: str) -> str:
    """Admin-created account: random temp password (returned once), must change."""
    username = (username or "").strip()
    if not _VALID_USERNAME.match(username):
        raise ValueError("Username must be 3-32 chars: letters, digits, . _ -")
    if role not in ("admin", "user"):
        raise ValueError("Role must be 'admin' or 'user'.")
    if db.get_user(username) is not None:
        raise ValueError(f"User '{username}' already exists.")
    temp_password = secrets.token_urlsafe(12)
    db.create_user(username, hash_password(temp_password), must_change=True,
                   role=role)
    return temp_password


def is_strong_enough(password: str) -> Optional[str]:
    """Return an error message if the new password is too weak, else None."""
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if password.lower() in {"password", "admin", "changeme"}:
        return "Choose a less predictable password."
    return None
