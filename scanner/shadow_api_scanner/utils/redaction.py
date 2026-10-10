"""Redact credentials and tokens before proof-of-concept data is reported."""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


REDACTED = "[REDACTED]"
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
}
SENSITIVE_FIELDS = {
    "access_token",
    "accesstoken",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "csrf",
    "password",
    "passwd",
    "refresh_token",
    "refreshtoken",
    "secret",
    "session",
    "token",
    # Kept in sync with DataExposureValidator.FIELD_CATEGORIES
    # (phase3/validators/data_exposure.py) so that any field the scanner
    # flags as a sensitive-exposure finding is also redacted from PoC
    # evidence before it reaches a report. Both the underscore-separated
    # and fully-concatenated spellings are listed because the two
    # normalization functions differ: this module collapses separator
    # runs to a single "_", while DataExposureValidator strips them
    # entirely.
    "pwd",
    "password_hash",
    "passwordhash",
    "password_digest",
    "passworddigest",
    "reset_token",
    "resettoken",
    "auth_token",
    "authtoken",
    "session_id",
    "sessionid",
    "session_token",
    "sessiontoken",
    "jwt",
    "client_secret",
    "clientsecret",
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "ssn",
    "national_id",
    "nationalid",
    "passport_number",
    "passportnumber",
    "credit_card",
    "creditcard",
    "card_number",
    "cardnumber",
    "card_owner_name",
    "cardownername",
    "card_type",
    "cardtype",
    "card_expiry",
    "cardexpiry",
    "cvv",
    "cvc",
    "bank_account",
    "bankaccount",
    "routing_number",
    "routingnumber",
    "iban",
    "salary",
    "permissions",
    "permission",
    "roles",
    "role",
    "scopes",
    "internal_id",
    "internalid",
    "database_url",
    "databaseurl",
    "internal_host",
    "internalhost",
    "internal_ip",
    "internalip",
    "hostname",
    "email",
    "phone_number",
    "phonenumber",
    "phone",
    "date_of_birth",
    "dateofbirth",
    "dob",
    "home_address",
    "homeaddress",
}
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)
COOKIE_PATTERN = re.compile(
    r"(?i)\b(session|token|auth|jwt)=([^;\s]+)"
)
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
HEADER_LINE = re.compile(r"^(\s*)([^:\n]+):\s*(.*)$")


def redact_headers(headers: dict) -> dict:
    """Return a copy with sensitive header values removed."""
    return {
        name: REDACTED if name.lower() in SENSITIVE_HEADERS else value
        for name, value in headers.items()
    }


def redact_data(value):
    """Return recursively redacted structured evidence.

    Runtime discovery retains structured query and body parameters so later
    validators can reason about them.  Reports must never expose sensitive
    values from those structures, including nested JSON objects.
    """
    return _redact_value(value)


def redact_url(url: str) -> str:
    """Remove credentials from URL userinfo and sensitive query values."""
    parsed = urlparse(url)
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc += f":{parsed.port}"

    query = urlencode([
        (
            name,
            REDACTED if _is_sensitive_name(name) else value,
        )
        for name, value in parse_qsl(
            parsed.query, keep_blank_values=True
        )
    ], safe="[]")
    return urlunparse((
        parsed.scheme,
        netloc,
        parsed.path,
        parsed.params,
        query,
        parsed.fragment,
    ))


def redact_body(body: str | None) -> str | None:
    """Redact sensitive fields from JSON, forms, or plain text bodies."""
    if body is None:
        return None

    try:
        payload = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        payload = None
    if payload is not None:
        return json.dumps(_redact_value(payload), separators=(",", ":"))

    if "\n" not in body and re.match(
        r"^[A-Za-z0-9_.\[\]-]+=", body
    ):
        pairs = parse_qsl(body, keep_blank_values=True)
        if pairs:
            return urlencode([
                (
                    name,
                    REDACTED if _is_sensitive_name(name) else value,
                )
                for name, value in pairs
            ])

    redacted = redact_text(body)
    for field in SENSITIVE_FIELDS:
        redacted = re.sub(
            rf'(?i)("{re.escape(field)}"\s*:\s*)"[^"]*"',
            rf'\1"{REDACTED}"',
            redacted,
        )
    return redacted


def redact_text(text: str) -> str:
    """Redact common credentials and sensitive URL queries in free text."""
    redacted = JWT_PATTERN.sub(REDACTED, text)
    redacted = BEARER_PATTERN.sub(f"Bearer {REDACTED}", redacted)
    redacted = COOKIE_PATTERN.sub(
        lambda match: f"{match.group(1)}={REDACTED}",
        redacted,
    )
    return URL_PATTERN.sub(
        lambda match: redact_url(match.group(0)),
        redacted,
    )


def redact_poc_request(request: str | None) -> str | None:
    """Redact a formatted proof-of-concept HTTP request."""
    if not request:
        return request

    lines = request.splitlines()
    if lines:
        first = lines[0].split(" ", 1)
        if len(first) == 2:
            lines[0] = f"{first[0]} {redact_url(first[1])}"

    for index, line in enumerate(lines[1:], start=1):
        header_match = HEADER_LINE.match(line)
        if not header_match:
            continue
        indent, name, value = header_match.groups()
        if name.lower() == "body":
            lines[index] = f"{indent}{name}: {redact_body(value)}"
        elif name.lower() in SENSITIVE_HEADERS:
            lines[index] = f"{indent}{name}: {REDACTED}"

    return JWT_PATTERN.sub(REDACTED, "\n".join(lines))


def redact_poc_response(response: str | None) -> str | None:
    """Redact common secret forms from proof-of-concept response text."""
    if not response:
        return response
    return redact_body(response)


def _redact_value(value):
    if isinstance(value, dict):
        return {
            key: REDACTED if _is_sensitive_name(str(key))
            else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _is_sensitive_name(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return normalized in SENSITIVE_FIELDS or any(
        normalized.endswith(suffix)
        for suffix in (
            "_password",
            "_secret",
            "_token",
            "_api_key",
            "_session",
        )
    )
