"""Materialize the web UI's advanced options into scanner inputs.

The web form collects everything the CLI exposes. This module turns that JSON
into (a) plain ScanConfig keyword overrides, and (b) on-disk validator/login
config files — while preserving the scanner's security contract that **secrets
never touch disk**: every credential the user types is assigned a unique,
per-scan environment-variable name; the config files reference only that name,
and the actual value is returned in a secret map that ScanManager sets in the
process environment for the duration of the one scan and then clears.

Nothing here reimplements scanning logic; it only prepares standard inputs the
validated scanner already accepts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_HEADER_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_INJECTION_CATEGORIES = {"sql", "nosql", "command", "template"}


class OptionsError(ValueError):
    """Raised when the submitted advanced options are invalid."""


class _Secrets:
    """Allocates unique env-var names for secret values within one scan."""

    def __init__(self, scan_id: str) -> None:
        self._prefix = f"SASWEB_{re.sub(r'[^0-9A-Za-z]', '', scan_id)[:16]}"
        self._n = 0
        self.env: dict[str, str] = {}

    def add(self, value: str) -> str:
        value = "" if value is None else str(value)
        if "\r" in value or "\n" in value:
            raise OptionsError("Credential values must not contain newlines.")
        self._n += 1
        name = f"{self._prefix}_{self._n}"
        self.env[name] = value
        return name


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _method(value: Any, default: str = "GET") -> str:
    method = _s(value).upper() or default
    if method not in _METHODS:
        raise OptionsError(f"Unsupported HTTP method: {method!r}")
    return method


def _header_name(value: Any, default: str = "Authorization") -> str:
    name = _s(value) or default
    if not _HEADER_RE.fullmatch(name):
        raise OptionsError(f"Invalid header name: {name!r}")
    return name


def _paths(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_s(item) for item in value if _s(item)]


def _json_obj(text: Any, what: str) -> Any:
    text = _s(text)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise OptionsError(f"{what} must be valid JSON: {exc}") from exc


def _write(cfg_dir: Path, name: str, data: dict) -> str:
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / f"{name}.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# Validator config builders (friendly form dict -> scanner config dict)
# --------------------------------------------------------------------------- #

def _build_bola(v: dict, hosts: list[str], secrets: _Secrets) -> dict:
    idents = v.get("identities") or {}
    header = _header_name(v.get("header_name"))

    def identity(key: str) -> dict:
        raw = idents.get(key) or {}
        value = _s(raw.get("auth_value"))
        if not value:
            raise OptionsError(f"BOLA {key} requires a credential value.")
        return {"header_env": {header: secrets.add(value)}}

    cases = []
    for i, raw in enumerate(v.get("cases") or [], start=1):
        case = {
            "name": _s(raw.get("name")) or f"bola-case-{i}",
            "method": _method(raw.get("method")),
            "url": _s(raw.get("url")),
            "object_location": _s(raw.get("object_location")) or "path",
            "object_name": _s(raw.get("object_name")),
            "object_value": _s(raw.get("object_value")),
            "evidence_paths": _paths(raw.get("evidence_paths")),
        }
        body = _json_obj(raw.get("json_body_text"), f"BOLA case {i} body")
        if body is not None:
            case["json_body"] = body
        cases.append(case)
    if not cases:
        raise OptionsError("BOLA requires at least one case.")
    return {
        "authorized_hosts": hosts,
        "identities": {"user_a": identity("user_a"), "user_b": identity("user_b")},
        "cases": cases,
    }


def _build_auth(v: dict, secrets: _Secrets) -> dict:
    valid = _s(v.get("valid_value"))
    if not valid:
        raise OptionsError("Broken-auth validation requires a valid token value.")
    payload: dict[str, Any] = {
        "header_name": _header_name(v.get("header_name")),
        "valid_env": secrets.add(valid),
    }
    if _s(v.get("invalid_value")):
        payload["invalid_env"] = secrets.add(_s(v.get("invalid_value")))
    if _s(v.get("expired_value")):
        payload["expired_env"] = secrets.add(_s(v.get("expired_value")))
    cases = []
    for i, raw in enumerate(v.get("cases") or [], start=1):
        case = {
            "name": _s(raw.get("name")) or f"auth-case-{i}",
            "method": _method(raw.get("method")),
            "url": _s(raw.get("url")),
            "evidence_paths": _paths(raw.get("evidence_paths")),
            "allow_state_change": bool(raw.get("allow_state_change")),
        }
        body = _json_obj(raw.get("json_body_text"), f"Auth case {i} body")
        if body is not None:
            case["json_body"] = body
        cases.append(case)
    if not cases:
        raise OptionsError("Broken-auth validation requires at least one case.")
    payload["cases"] = cases
    return payload


def _build_parameter(v: dict) -> dict:
    cases = []
    for i, raw in enumerate(v.get("cases") or [], start=1):
        verify = raw.get("verify") or {}
        cleanup = raw.get("cleanup") or {}
        case = {
            "name": _s(raw.get("name")) or f"param-case-{i}",
            "method": _method(raw.get("method"), "PATCH"),
            "url": _s(raw.get("url")),
            "parameter": _s(raw.get("parameter")),
            "mutation_body": _json_obj(
                raw.get("mutation_body_text"), f"Case {i} mutation body"
            ) or {},
            "verify": {
                "method": _method(verify.get("method"), "GET"),
                "url": _s(verify.get("url")),
                "json_path": _s(verify.get("json_path")),
                "original_value": verify.get("original_value"),
                "mutated_value": verify.get("mutated_value"),
            },
            "cleanup": {
                "method": _method(cleanup.get("method"), "PATCH"),
                "url": _s(cleanup.get("url")),
                "json_body": _json_obj(
                    cleanup.get("json_body_text"), f"Case {i} cleanup body"
                ) or {},
            },
            # Mass-assignment mutates state, so the scanner requires the operator
            # to affirm the record is synthetic and that mutation is allowed.
            "synthetic_record": True,
            "allow_state_change": True,
        }
        cases.append(case)
    if not cases:
        raise OptionsError("Mass-assignment validation requires at least one case.")
    return {"cases": cases}


def _build_injection(v: dict) -> dict:
    cases = []
    for i, raw in enumerate(v.get("cases") or [], start=1):
        categories = [
            _s(c).lower() for c in (raw.get("categories") or []) if _s(c)
        ]
        bad = set(categories) - _INJECTION_CATEGORIES
        if bad:
            raise OptionsError(
                f"Injection case {i}: unknown categories {sorted(bad)} "
                "(use sql, nosql, command, template)."
            )
        if not categories:
            raise OptionsError(f"Injection case {i} needs at least one category.")
        cases.append({
            "name": _s(raw.get("name")) or f"inj-case-{i}",
            "method": _method(raw.get("method")),
            "url": _s(raw.get("url")),
            "parameter": _s(raw.get("parameter")),
            "baseline_value": _s(raw.get("baseline_value")),
            "categories": categories,
        })
    if not cases:
        raise OptionsError("Injection validation requires at least one case.")
    return {"cases": cases}


def _build_access(v: dict, secrets: _Secrets) -> dict:
    identities = []
    for raw in v.get("identities") or []:
        value = _s(raw.get("value"))
        name = _s(raw.get("name"))
        if not name or not value:
            raise OptionsError("Each access-control identity needs a name and value.")
        identities.append({
            "name": name,
            "header_name": _header_name(raw.get("header_name")),
            "value_env": secrets.add(value),
        })
    if len(identities) < 2:
        raise OptionsError("Access-control validation needs at least two identities.")
    cases = []
    for i, raw in enumerate(v.get("cases") or [], start=1):
        cases.append({
            "name": _s(raw.get("name")) or f"access-case-{i}",
            "type": _s(raw.get("type")) or "object",
            "method": _method(raw.get("method")),
            "url": _s(raw.get("url")),
            "allowed_identity": _s(raw.get("allowed_identity")),
            "denied_identities": [
                _s(d) for d in (raw.get("denied_identities") or []) if _s(d)
            ],
            "evidence_paths": _paths(raw.get("evidence_paths")),
        })
    if not cases:
        raise OptionsError("Access-control validation requires at least one case.")
    return {"identities": identities, "cases": cases}


# --------------------------------------------------------------------------- #
# Login (Mode A API / Mode B browser)
# --------------------------------------------------------------------------- #

def _build_login(login: dict, secrets: _Secrets) -> dict:
    mode = _s(login.get("mode")).lower() or "api"
    if mode == "browser":
        fields = {}
        for raw in login.get("fields") or []:
            selector = _s(raw.get("selector"))
            if not selector:
                continue
            value = _s(raw.get("value"))
            fields[selector] = (
                "${%s}" % secrets.add(value) if raw.get("secret") else value
            )
        spec: dict[str, Any] = {
            "mode": "browser",
            "login_url": _s(login.get("login_url")) or _s(login.get("url")),
            "fields": fields,
        }
        if _s(login.get("submit")):
            spec["submit"] = _s(login.get("submit"))
        if _s(login.get("wait_for")):
            spec["wait_for"] = _s(login.get("wait_for"))
        if not spec["login_url"] or not fields:
            raise OptionsError("Browser login needs a login URL and at least one field.")
        return spec

    # Mode A: API login.
    body = {}
    for raw in login.get("body") or []:
        key = _s(raw.get("key"))
        if not key:
            continue
        value = _s(raw.get("value"))
        body[key] = "${%s}" % secrets.add(value) if raw.get("secret") else value
    spec = {
        "mode": "api",
        "url": _s(login.get("url")),
        "method": _method(login.get("method"), "POST"),
        "body_type": _s(login.get("body_type")).lower() or "json",
        "body": body,
        "token_extract": {
            "from": _s(login.get("token_from")).lower() or "json",
            "path": _s(login.get("token_path")),
        },
        "inject": {
            "as": _s(login.get("inject_as")).lower() or "header",
            "name": _s(login.get("inject_name")) or "Authorization",
            "template": _s(login.get("inject_template")) or "Bearer {token}",
        },
    }
    if not spec["url"] or not body:
        raise OptionsError("API login needs a URL and at least one body field.")
    return spec


# --------------------------------------------------------------------------- #
# Top-level entry point
# --------------------------------------------------------------------------- #

def materialize(
    options: dict | None,
    scan_id: str,
    job_dir: Path,
    target_url: str,
    security_enabled: bool,
) -> tuple[dict, dict]:
    """Return (scanconfig_overrides, secret_env). Raises OptionsError."""
    options = options or {}
    if not isinstance(options, dict):
        raise OptionsError("Options must be an object.")
    secrets = _Secrets(scan_id)
    cfg_dir = job_dir / "config"
    overrides: dict[str, Any] = {}
    target_host = (urlparse(target_url).hostname or "").lower()

    # ---- Discovery -------------------------------------------------------- #
    disc = options.get("discovery") or {}
    if disc.get("no_browser"):
        overrides["browser_timeout"] = 0
    if disc.get("discovery_only"):
        overrides["enable_security_testing"] = False
        security_enabled = False
    if _s(disc.get("concurrency")):
        try:
            overrides["max_discovery_concurrency"] = max(1, min(20, int(disc["concurrency"])))
        except (TypeError, ValueError):
            raise OptionsError("Discovery concurrency must be a number 1-20.")
    if _s(disc.get("openapi_url")):
        overrides["openapi_spec_url"] = _s(disc.get("openapi_url"))
    if _s(disc.get("openapi_text")):
        _json_obj(disc.get("openapi_text"), "OpenAPI spec")
        overrides["openapi_spec_file"] = _write_text(cfg_dir, "openapi", disc["openapi_text"], ".json")
    extra_hosts = [
        _s(h).lower() for h in (disc.get("extra_hosts") or []) if _s(h)
    ]

    # ---- Authentication --------------------------------------------------- #
    auth = options.get("auth") or {}
    if _s(auth.get("token")):
        overrides["auth_token"] = _s(auth.get("token"))
        overrides["auth_header"] = _header_name(auth.get("token_header"))
    if _s(auth.get("cookie")):
        overrides["cookie"] = _s(auth.get("cookie"))
    custom_headers = {}
    for raw in auth.get("headers") or []:
        name = _s(raw.get("name"))
        if name:
            custom_headers[_header_name(name)] = _s(raw.get("value"))
    if custom_headers:
        overrides["custom_headers"] = custom_headers
    if auth.get("login"):
        overrides["login_config_file"] = _write(
            cfg_dir, "login", _build_login(auth["login"], secrets)
        )

    # ---- Active testing --------------------------------------------------- #
    if options.get("active_testing") and security_enabled:
        overrides["enable_active_testing"] = True

    # ---- Evidence --------------------------------------------------------- #
    ev = options.get("evidence") or {}
    if _s(ev.get("har_text")):
        overrides["har_files"] = [
            _write_text(cfg_dir, "traffic", ev["har_text"], ".har")
        ]
    if _s(ev.get("traffic_log_text")):
        overrides["traffic_log_files"] = [
            _write_text(cfg_dir, "traffic", ev["traffic_log_text"], ".log")
        ]
    if _s(ev.get("api_inventory_text")):
        overrides["api_inventory_file"] = _write_text(
            cfg_dir, "inventory", ev["api_inventory_text"], ".json"
        )
    if ev.get("no_auto_evidence"):
        overrides["auto_evidence"] = False
    if ev.get("no_history"):
        overrides["auto_history"] = False

    # ---- Security validators (guided forms) ------------------------------- #
    validators = options.get("validators") or {}
    if validators and not security_enabled:
        raise OptionsError(
            "Security-validator configs require a security level (Standard or "
            "Advanced) and cannot run in discovery-only mode."
        )
    hosts = [target_host] + [h for h in extra_hosts if h]
    hosts = list(dict.fromkeys(h for h in hosts if h))

    if validators.get("bola"):
        overrides["bola_config_file"] = _write(
            cfg_dir, "bola", _build_bola(validators["bola"], hosts, secrets)
        )
    if validators.get("auth"):
        overrides["auth_validation_config_file"] = _write(
            cfg_dir, "auth_validation", _build_auth(validators["auth"], secrets)
        )
    if validators.get("parameter"):
        overrides["parameter_validation_config_file"] = _write(
            cfg_dir, "parameter_validation", _build_parameter(validators["parameter"])
        )
        overrides["enable_active_testing"] = True  # mass-assignment mutates
    if validators.get("injection"):
        overrides["injection_validation_config_file"] = _write(
            cfg_dir, "injection_validation", _build_injection(validators["injection"])
        )
    if validators.get("access"):
        overrides["access_validation_config_file"] = _write(
            cfg_dir, "access_validation", _build_access(validators["access"], secrets)
        )

    if extra_hosts and security_enabled:
        overrides["security_authorized_hosts_extra"] = extra_hosts

    return overrides, secrets.env


def _write_text(cfg_dir: Path, name: str, text: str, suffix: str) -> str:
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / f"{name}{suffix}"
    path.write_text(str(text), encoding="utf-8")
    return str(path)
