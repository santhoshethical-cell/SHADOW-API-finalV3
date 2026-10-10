"""
Mode A programmatic session acquisition (API login).

Given a researcher-supplied login description, obtain a session token from the
target's own authentication endpoint and inject it into the scanner's shared
auth fields, so every phase (static fetches, the Playwright crawl, and the
Phase 3 validators) runs authenticated. Nothing about any specific target is
hard-coded: the login URL, credential fields, token location, and injection
target all come from the config. Credentials are supplied through environment
variables referenced as ``${ENV_VAR}`` so secrets never live in the file and
are never logged.

Login config schema (JSON or YAML)::

    url: http://host/api/login        # required
    method: POST                      # default POST
    body_type: json                   # json (default) | form
    body:                             # request body; values may use ${ENV}
      username: "${APP_USER}"
      password: "${APP_PASS}"
    headers: {}                       # optional extra request headers
    token_extract:
      from: json                      # json (default) | header | cookie
      path: $.token                   # json: dotted path; header/cookie: name
    inject:
      as: header                      # header (default) | cookie
      name: Authorization             # header name or cookie name
      template: "Bearer {token}"      # {token} placeholder; default "{token}"
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx

from shadow_api_scanner.core.config import ScanConfig

logger = logging.getLogger("shadow_api_scanner")

_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class LoginConfigError(ValueError):
    """The login configuration is missing or malformed."""


class LoginError(RuntimeError):
    """The login request did not yield a usable session token."""


@dataclass
class SessionContext:
    """The acquired session and how it is attached to later requests."""

    inject_as: str  # "header" | "cookie"
    name: str
    value: str
    token: str


class SessionManager:
    """Acquire an authenticated session from a target's login endpoint."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def apply(self, result: Any = None) -> Optional[SessionContext]:
        """Run login if configured, inject the session, and report it.

        Returns the :class:`SessionContext`, or ``None`` when no login
        configuration was supplied.
        """
        if not self.config.login_config_file:
            return None

        spec = self._load(self.config.login_config_file)
        mode = str(spec.get("mode", "api")).lower()
        if mode == "browser":
            context = await self._browser_login(spec)
        else:
            context = await self._login(spec)
        if context is not None:
            self._inject(context)
            logger.info(
                "  Authenticated session acquired; token injected as %s '%s'.",
                context.inject_as,
                context.name,
            )
        else:
            logger.info(
                "  Authenticated browser session captured to storage state."
            )
        if result is not None and hasattr(result, "warnings"):
            if context is not None:
                note = (
                    f"Authenticated session acquired via login endpoint; "
                    f"attached as {context.inject_as} '{context.name}'."
                )
            else:
                note = (
                    "Authenticated browser session captured to storage state "
                    "for the dynamic crawl."
                )
            if note not in result.warnings:
                result.warnings.append(note)
        return context

    # -- Config loading ----------------------------------------------------

    def _load(self, path_str: str) -> dict:
        path = Path(path_str)
        if not path.is_file():
            raise LoginConfigError(f"Login config not found: {path_str}")
        raw = path.read_text(encoding="utf-8")
        spec: Any
        try:
            spec = json.loads(raw)
        except json.JSONDecodeError:
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover
                raise LoginConfigError(
                    "Login config is not valid JSON and PyYAML is "
                    "unavailable to parse YAML."
                ) from exc
            spec = yaml.safe_load(raw)
        if not isinstance(spec, dict):
            raise LoginConfigError(
                "Login config must be a JSON/YAML object."
            )
        is_browser = str(spec.get("mode", "api")).lower() == "browser"
        if not spec.get("url") and not (is_browser and spec.get("login_url")):
            raise LoginConfigError(
                "Login config requires a 'url' (or 'login_url' in browser mode)."
            )
        return spec

    def _resolve_env(self, value: Any) -> Any:
        """Substitute ${ENV_VAR} references from the environment."""
        if isinstance(value, str):
            def replace(match: "re.Match[str]") -> str:
                name = match.group(1)
                if name not in os.environ:
                    raise LoginConfigError(
                        f"Login config references ${{{name}}} but that "
                        "environment variable is not set."
                    )
                return os.environ[name]

            return _ENV_PLACEHOLDER.sub(replace, value)
        if isinstance(value, dict):
            return {k: self._resolve_env(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._resolve_env(v) for v in value]
        return value

    # -- Login -------------------------------------------------------------

    async def _login(self, spec: dict) -> SessionContext:
        method = str(spec.get("method", "POST")).upper()
        url = spec["url"]
        body_type = str(spec.get("body_type", "json")).lower()
        body = self._resolve_env(spec.get("body"))
        headers = self._resolve_env(spec.get("headers", {})) or {}

        request_kwargs: dict[str, Any] = {"headers": headers}
        if body is not None:
            if body_type == "form":
                request_kwargs["data"] = body
            else:
                request_kwargs["json"] = body

        logger.info(
            "  Authenticating: %s %s",
            method,
            httpx.URL(url).copy_with(query=None, fragment=None),
        )
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout),
                follow_redirects=True,
                max_redirects=self.config.max_redirects,
                verify=self.config.verify_tls,
            ) as client:
                response = await client.request(method, url, **request_kwargs)
        except httpx.HTTPError as exc:
            raise LoginError(f"Login request failed: {exc}") from exc

        if response.status_code >= 400:
            raise LoginError(
                f"Login endpoint returned HTTP {response.status_code}; "
                "check credentials and the login URL."
            )

        token = self._extract_token(spec, response)
        if not token:
            raise LoginError(
                "Login succeeded but no token was found at the configured "
                "location; check 'token_extract'."
            )
        return self._build_context(spec, token)

    # -- Browser login (Mode B) -------------------------------------------

    async def _browser_login(self, spec: dict) -> Optional[SessionContext]:
        """Drive a real browser through a login form, capture the session.

        Fills the declared form fields (credentials via ${ENV}), submits, then
        saves the authenticated Playwright storage state (cookies +
        localStorage) so the Phase 2 crawl runs logged in. If a token location
        is declared, the token is also extracted for the HTTP-only phases.

        Browser login config schema::

            mode: browser
            login_url: http://host/login          # or 'url'
            fields:                               # selector -> value (${ENV})
              "input[name=email]": "${APP_USER}"
              "input[name=password]": "${APP_PASS}"
            submit: "button[type=submit]"         # optional click selector
            wait_for: networkidle                 # load|domcontentloaded|
                                                  # networkidle|<css-selector>
            token_extract:                        # optional (HTTP phases)
              from: local_storage                 # local_storage | cookie
              key: token
            inject:                               # optional
              as: header
              name: Authorization
              template: "Bearer {token}"
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover
            raise LoginError(
                "Browser login requires Playwright; run './run.sh setup'."
            ) from exc

        login_url = spec.get("login_url") or spec.get("url")
        fields = self._resolve_env(spec.get("fields") or {})
        submit = spec.get("submit")
        wait_for = str(spec.get("wait_for", "networkidle"))
        load_states = {"load", "domcontentloaded", "networkidle"}

        logger.info("  Authenticating via browser login: %s", login_url)
        storage: dict = {}
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=self.config.browser_headless
                )
                context = await browser.new_context(
                    ignore_https_errors=not self.config.verify_tls
                )
                page = await context.new_page()
                await page.goto(login_url, wait_until="domcontentloaded",
                                timeout=self.config.browser_timeout * 1000)
                for selector, value in fields.items():
                    await page.fill(selector, str(value),
                                    timeout=15000)
                if submit:
                    await page.click(submit, timeout=15000)
                try:
                    if wait_for in load_states:
                        await page.wait_for_load_state(wait_for, timeout=15000)
                    elif wait_for:
                        await page.wait_for_selector(wait_for, timeout=15000)
                except Exception:  # best-effort settle; capture anyway
                    pass
                storage = await context.storage_state()
                await browser.close()
        except LoginError:
            raise
        except Exception as exc:
            raise LoginError(f"Browser login failed: {exc}") from exc

        # Persist the storage state for the Phase 2 crawl.
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        state_path = out_dir / "login_storage_state.json"
        state_path.write_text(json.dumps(storage), encoding="utf-8")
        self.config.browser_storage_state = str(state_path)

        # If a token location is declared, surface it for the HTTP phases too.
        token = self._extract_browser_token(spec, storage)
        if token:
            return self._build_context(spec, token)
        # Otherwise fall back to replaying captured cookies as a Cookie header,
        # so the non-browser phases are authenticated as well.
        cookie_header = self._cookies_to_header(storage, login_url)
        if cookie_header and not self.config.cookie:
            self.config.cookie = cookie_header
        return None

    @staticmethod
    def _extract_browser_token(spec: dict, storage: dict) -> Optional[str]:
        extract = spec.get("token_extract") or {}
        source = str(extract.get("from", "")).lower()
        key = extract.get("key") or extract.get("path") or extract.get("name")
        if not source or not key:
            return None
        if source in ("local_storage", "localstorage"):
            for origin in storage.get("origins", []):
                for item in origin.get("localStorage", []):
                    if item.get("name") == key:
                        return item.get("value")
            return None
        if source == "cookie":
            for cookie in storage.get("cookies", []):
                if cookie.get("name") == key:
                    return cookie.get("value")
        return None

    @staticmethod
    def _cookies_to_header(storage: dict, url: str) -> str:
        host = httpx.URL(url).host if url else ""
        pairs = []
        for cookie in storage.get("cookies", []):
            domain = (cookie.get("domain") or "").lstrip(".")
            if not domain or not host or domain in host or host in domain:
                pairs.append(f"{cookie.get('name')}={cookie.get('value')}")
        return "; ".join(pairs)

    def _extract_token(
        self, spec: dict, response: httpx.Response
    ) -> Optional[str]:
        extract = spec.get("token_extract") or {}
        source = str(extract.get("from", "json")).lower()

        if source == "header":
            name = extract.get("path") or extract.get("name")
            if not name:
                raise LoginConfigError(
                    "token_extract.from=header requires the header name in "
                    "'path' (or 'name')."
                )
            return response.headers.get(name)

        if source == "cookie":
            name = extract.get("path") or extract.get("name")
            if not name:
                raise LoginConfigError(
                    "token_extract.from=cookie requires the cookie name in "
                    "'path' (or 'name')."
                )
            return response.cookies.get(name)

        # Default: JSON body via a dotted path such as "$.data.token".
        path = extract.get("path", "token")
        try:
            payload = response.json()
        except ValueError as exc:
            raise LoginError(
                "Login response is not JSON but token_extract.from=json was "
                "requested."
            ) from exc
        return self._walk_json_path(payload, path)

    @staticmethod
    def _walk_json_path(payload: Any, path: str) -> Optional[str]:
        cursor = payload
        cleaned = path[2:] if path.startswith("$.") else path.lstrip("$")
        for segment in filter(None, cleaned.split(".")):
            if isinstance(cursor, dict):
                cursor = cursor.get(segment)
            elif isinstance(cursor, list) and segment.isdigit():
                index = int(segment)
                cursor = cursor[index] if index < len(cursor) else None
            else:
                return None
            if cursor is None:
                return None
        return None if isinstance(cursor, (dict, list)) else str(cursor)

    def _build_context(self, spec: dict, token: str) -> SessionContext:
        inject = spec.get("inject") or {}
        inject_as = str(inject.get("as", "header")).lower()
        if inject_as not in ("header", "cookie"):
            raise LoginConfigError(
                "inject.as must be 'header' or 'cookie'."
            )
        default_name = "Authorization" if inject_as == "header" else "session"
        name = inject.get("name", default_name)
        template = inject.get("template", "{token}")
        value = template.format(token=token)
        return SessionContext(
            inject_as=inject_as,
            name=name,
            value=value,
            token=token,
        )

    # -- Injection ---------------------------------------------------------

    def _inject(self, context: SessionContext) -> None:
        if context.inject_as == "header":
            self.config.auth_header = context.name
            self.config.auth_token = context.value
            return
        # cookie: append without clobbering any pre-existing cookie value.
        pair = f"{context.name}={context.value}"
        existing = self.config.cookie
        self.config.cookie = pair if not existing else f"{existing}; {pair}"
