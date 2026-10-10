"""
Mouse-driven, cyber-themed Terminal UI (Textual).

A full-screen, clickable front-end over the full option set. Every control is
mouse-operable (dropdowns, switches, buttons, collapsible sections) and the
theme is a neon "cyber" palette. Falls back to the Rich menu TUI when Textual
is not installed.

Shares the settings model and config builder with :mod:`shadow_api_scanner.tui`.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.tui import _build_config, _normalize_target, _Settings

try:  # Textual is an optional dependency; the Rich menu is the fallback.
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, VerticalScroll
    from textual.widgets import (
        Button,
        Collapsible,
        Footer,
        Header,
        Input,
        Label,
        Select,
        Static,
        Switch,
    )
    TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without Textual
    TEXTUAL_AVAILABLE = False


CYBER_BANNER = (
    "  ░▒▓  SHADOW / UNMANAGED API SCANNER  ▓▒░\n"
    "        interactive · cyber console"
)


if TEXTUAL_AVAILABLE:

    class ScanBuilderApp(App):
        """Clickable, cyber-themed scan builder."""

        TITLE = "Shadow API Scanner"
        SUB_TITLE = "cyber console"

        CSS = """
        Screen {
            background: #05080d;
            color: #9ff7e6;
        }
        #banner {
            content-align: center middle;
            color: #00ffd5;
            text-style: bold;
            background: #05080d;
            border: round #00ffd5;
            padding: 0 1;
            margin: 0 1;
        }
        .section {
            border: round #123;
            background: #070b12;
            margin: 0 1;
        }
        Collapsible {
            border: round #0aa;
            background: #070b12;
            margin: 0 1;
        }
        Collapsible > .collapsible--title {
            color: #00ffd5;
            text-style: bold;
        }
        Label { color: #57c7ff; }
        .hint { color: #3d6a7a; text-style: italic; }
        Input {
            background: #0a121c;
            color: #b8ffe9;
            border: tall #0e3a44;
        }
        Input:focus { border: tall #00ffd5; }
        Select { background: #0a121c; }
        Select:focus > SelectCurrent { border: tall #00ffd5; }
        Switch { background: #0a121c; }
        Switch.-on > .switch--slider { color: #00ff9f; }
        .row { height: auto; padding: 0 1; }
        .row Label { width: 30; padding: 1 1 0 0; }
        .row Input { width: 1fr; }
        #actions { height: auto; padding: 1 1; align: center middle; }
        #run { background: #00b386; color: #001a12; text-style: bold; }
        #run:hover { background: #00ffbf; }
        #quit { background: #7a1030; color: #ffd6e2; text-style: bold; }
        #quit:hover { background: #ff2e6e; }
        #status { color: #ff5d5d; padding: 0 2; height: auto; }
        """

        BINDINGS = [
            ("ctrl+r", "run_scan", "Run"),
            ("ctrl+q", "quit_app", "Quit"),
        ]

        def __init__(self, settings: _Settings):
            super().__init__()
            self._settings = settings
            self._result: Optional[ScanConfig] = None

        # -- layout --------------------------------------------------------

        def compose(self) -> ComposeResult:
            s = self._settings
            yield Header(show_clock=True)
            yield Static(CYBER_BANNER, id="banner")
            with VerticalScroll():
                # Target & mode
                with Collapsible(title="◈ Target & scan mode",
                                 collapsed=False):
                    yield from self._text_row(
                        "Target URL", "target", s.target_url,
                        "http(s)://host:port/")
                    yield Label("Scan mode")
                    yield Select(
                        [("Discovery only (no active tests)", "discovery"),
                         ("Full (discovery + Phase 3)", "full")],
                        value="discovery" if s.discovery_only else "full",
                        id="mode", allow_blank=False)

                with Collapsible(title="◈ Baseline & evidence "
                                       "(classify shadow vs documented)"):
                    yield from self._text_row("OpenAPI spec (path/URL)",
                                              "openapi_spec", s.openapi_spec)
                    yield from self._text_row("API inventory",
                                              "api_inventory", s.api_inventory)
                    yield from self._text_row("HAR file(s), comma-sep",
                                              "har", ",".join(s.har_files))
                    yield from self._text_row(
                        "Traffic log(s), comma-sep", "traffic_log",
                        ",".join(s.traffic_log_files))
                    yield from self._text_row("Compare baseline JSON",
                                              "compare_baseline",
                                              s.compare_baseline)
                    yield from self._text_row("Save baseline JSON",
                                              "save_baseline", s.save_baseline)
                    yield from self._text_row("Ground-truth JSON",
                                              "ground_truth", s.ground_truth)

                with Collapsible(title="◈ Authentication"):
                    yield from self._text_row("Auth token / bearer value",
                                              "auth_token", s.auth_token)
                    yield from self._text_row("Auth header name",
                                              "auth_header", s.auth_header)
                    yield from self._text_row("Cookie value", "cookie",
                                              s.cookie)
                    yield from self._text_row("Login config (JSON/YAML)",
                                              "login_config", s.login_config)
                    yield from self._text_row("Browser storage-state JSON",
                                              "storage_state", s.storage_state)

                with Collapsible(title="◈ Security testing (Phase 3)"):
                    yield from self._text_row(
                        "Authorized host(s), comma-sep", "authorized_hosts",
                        ",".join(s.authorized_hosts))
                    yield from self._switch_row("Allow active exploit testing",
                                                "active_testing",
                                                s.active_testing)
                    yield from self._text_row("BOLA config", "bola_config",
                                              s.bola_config)
                    yield from self._text_row("Broken-auth config",
                                              "auth_validation_config",
                                              s.auth_validation_config)
                    yield from self._text_row("Parameter config",
                                              "parameter_validation_config",
                                              s.parameter_validation_config)
                    yield from self._text_row("Injection config",
                                              "injection_validation_config",
                                              s.injection_validation_config)
                    yield from self._text_row("Access config",
                                              "access_validation_config",
                                              s.access_validation_config)
                    yield from self._text_row(
                        "Sensitive-field regex(es), comma-sep",
                        "sensitive_field_patterns",
                        ",".join(s.sensitive_field_patterns))

                with Collapsible(title="◈ Browser (Phase 2)"):
                    yield from self._switch_row("Run browser crawl",
                                                "run_browser", not s.no_browser)
                    yield from self._switch_row("Headed (show window)",
                                                "headed", s.headed)
                    yield from self._text_row("Browser timeout (s)",
                                              "browser_timeout",
                                              str(s.browser_timeout))

                with Collapsible(title="◈ Advanced / performance"):
                    yield from self._text_row("Discovery concurrency",
                                              "discovery_concurrency",
                                              str(s.discovery_concurrency))
                    yield from self._text_row("Request timeout (s)",
                                              "request_timeout",
                                              str(s.request_timeout))
                    yield from self._text_row("Security request delay (s)",
                                              "request_delay",
                                              str(s.request_delay))
                    yield from self._text_row("Phase 3 request budget",
                                              "max_security_requests",
                                              str(s.max_security_requests))
                    yield from self._text_row("Max response bytes (Phase 3)",
                                              "max_security_response_bytes",
                                              str(s.max_security_response_bytes))
                    yield from self._text_row("Max redirects", "max_redirects",
                                              str(s.max_redirects))
                    yield from self._switch_row("Verify TLS certificates",
                                                "verify_tls", not s.insecure)
                    yield from self._switch_row("Auto-discover local evidence",
                                                "auto_evidence",
                                                not s.no_auto_evidence)
                    yield from self._switch_row("Keep target history",
                                                "auto_history",
                                                not s.no_history)

                with Collapsible(title="◈ Output"):
                    yield from self._text_row("Output directory", "output",
                                              s.output)
                    yield from self._text_row("Formats (json,html)", "formats",
                                              s.formats)
                    yield from self._switch_row("Verbose logging", "verbose",
                                                s.verbose)

                yield Static("", id="status")
                with Horizontal(id="actions"):
                    yield Button("▶  RUN SCAN", id="run")
                    yield Button("✕  QUIT", id="quit")
            yield Footer()

        # -- row builders --------------------------------------------------

        def _text_row(self, label, wid, value, placeholder=""):
            with Horizontal(classes="row"):
                yield Label(label)
                yield Input(value=value or "", placeholder=placeholder,
                            id=f"in_{wid}")

        def _switch_row(self, label, wid, value):
            with Horizontal(classes="row"):
                yield Label(label)
                yield Switch(value=value, id=f"sw_{wid}")

        # -- helpers -------------------------------------------------------

        def _text(self, wid: str) -> str:
            return self.query_one(f"#in_{wid}", Input).value.strip()

        def _switch(self, wid: str) -> bool:
            return self.query_one(f"#sw_{wid}", Switch).value

        def _list(self, wid: str) -> list[str]:
            return [i.strip() for i in self._text(wid).split(",") if i.strip()]

        def _int(self, wid: str, default: int) -> int:
            try:
                return int(self._text(wid))
            except ValueError:
                return default

        def _float(self, wid: str, default: float) -> float:
            try:
                return float(self._text(wid))
            except ValueError:
                return default

        def _collect(self) -> Optional[_Settings]:
            target = _normalize_target(self._text("target"))
            if not target:
                self.query_one("#status", Static).update(
                    "⚠  Enter a valid http(s) target URL with a hostname.")
                return None
            s = self._settings
            s.target_url = target
            s.discovery_only = (
                self.query_one("#mode", Select).value == "discovery")
            s.openapi_spec = self._text("openapi_spec")
            s.api_inventory = self._text("api_inventory")
            s.har_files = self._list("har")
            s.traffic_log_files = self._list("traffic_log")
            s.compare_baseline = self._text("compare_baseline")
            s.save_baseline = self._text("save_baseline")
            s.ground_truth = self._text("ground_truth")
            s.auth_token = self._text("auth_token")
            s.auth_header = self._text("auth_header") or "Authorization"
            s.cookie = self._text("cookie")
            s.login_config = self._text("login_config")
            s.storage_state = self._text("storage_state")
            s.authorized_hosts = self._list("authorized_hosts")
            s.active_testing = self._switch("active_testing")
            s.bola_config = self._text("bola_config")
            s.auth_validation_config = self._text("auth_validation_config")
            s.parameter_validation_config = self._text(
                "parameter_validation_config")
            s.injection_validation_config = self._text(
                "injection_validation_config")
            s.access_validation_config = self._text("access_validation_config")
            s.sensitive_field_patterns = self._list("sensitive_field_patterns")
            s.no_browser = not self._switch("run_browser")
            s.headed = self._switch("headed")
            s.browser_timeout = self._int("browser_timeout", s.browser_timeout)
            s.discovery_concurrency = self._int(
                "discovery_concurrency", s.discovery_concurrency)
            s.request_timeout = self._float("request_timeout",
                                            s.request_timeout)
            s.request_delay = self._float("request_delay", s.request_delay)
            s.max_security_requests = self._int(
                "max_security_requests", s.max_security_requests)
            s.max_security_response_bytes = self._int(
                "max_security_response_bytes", s.max_security_response_bytes)
            s.max_redirects = self._int("max_redirects", s.max_redirects)
            s.insecure = not self._switch("verify_tls")
            s.no_auto_evidence = not self._switch("auto_evidence")
            s.no_history = not self._switch("auto_history")
            s.output = self._text("output") or "reports"
            fmts = [f.strip().lower()
                    for f in self._text("formats").split(",") if f.strip()]
            if not fmts or set(fmts) - {"json", "html"}:
                self.query_one("#status", Static).update(
                    "⚠  Formats must be a subset of json,html.")
                return None
            s.formats = ",".join(fmts)
            s.verbose = self._switch("verbose")
            return s

        # -- events --------------------------------------------------------

        def on_button_pressed(self, event: "Button.Pressed") -> None:
            if event.button.id == "quit":
                self.exit(None)
            elif event.button.id == "run":
                self.action_run_scan()

        def action_run_scan(self) -> None:
            collected = self._collect()
            if collected is None:
                return
            # In Full mode, scope Phase 3 to the target's own host by default
            # when no explicit authorized host was entered.
            if not collected.discovery_only and not collected.authorized_hosts:
                host = urlparse(collected.target_url).hostname
                if host:
                    collected.authorized_hosts = [host]
            self.exit(_build_config(collected))

        def action_quit_app(self) -> None:
            self.exit(None)


def launch_cyber_tui(initial_target: str = "") -> Optional[ScanConfig]:
    """Run the Textual cyber TUI; fall back to the Rich menu if unavailable."""
    if not TEXTUAL_AVAILABLE:
        from shadow_api_scanner.tui import launch_tui
        return launch_tui(initial_target)

    settings = _Settings()
    normalized = _normalize_target(initial_target) if initial_target else None
    if normalized:
        settings.target_url = normalized
    return ScanBuilderApp(settings).run()
