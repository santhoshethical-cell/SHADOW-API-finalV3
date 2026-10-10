"""
Interactive Terminal User Interface (TUI).

A menu-driven front-end over the full option set, so an end user can build
and launch a scan without memorising command-line flags. Reuses the same
Rich console and produces a ready-to-run :class:`ScanConfig`.

Launch it with ``shadow-scan --tui`` or by running ``shadow-scan`` with no
target URL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, FloatPrompt, IntPrompt, Prompt
from rich.table import Table

from shadow_api_scanner.core.config import ScanConfig

console = Console()

BANNER = r"""[bold magenta]
 ____  _               _                  _    ____ ___
/ ___|| |__   __ _  __| | _____      __  / \  |  _ \_ _|
\___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / / _ \ | |_) | |
 ___) | | | | (_| | (_| | (_) \ V  V / / ___ \|  __/| |
|____/|_| |_|\__,_|\__,_|\___/ \_/\_/ /_/   \_\_|  |___|
   [cyan]Shadow / Unmanaged API Scanner — Interactive Mode[/cyan]
[/bold magenta]"""


@dataclass
class _Settings:
    """Mutable working copy of every option the TUI can set."""

    target_url: str = ""
    # mode
    discovery_only: bool = True
    # baseline & evidence
    openapi_spec: str = ""
    api_inventory: str = ""
    har_files: list[str] = field(default_factory=list)
    traffic_log_files: list[str] = field(default_factory=list)
    save_baseline: str = ""
    compare_baseline: str = ""
    ground_truth: str = ""
    # authentication
    auth_token: str = ""
    auth_header: str = "Authorization"
    cookie: str = ""
    login_config: str = ""
    storage_state: str = ""
    # security testing (Phase 3)
    authorized_hosts: list[str] = field(default_factory=list)
    active_testing: bool = False
    bola_config: str = ""
    auth_validation_config: str = ""
    parameter_validation_config: str = ""
    injection_validation_config: str = ""
    access_validation_config: str = ""
    sensitive_field_patterns: list[str] = field(default_factory=list)
    rate_limit_requests: int = 5
    rate_limit_delay: float = 0.25
    rate_limit_concurrency: int = 1
    rate_limit_timeout: float = 5.0
    # browser (Phase 2)
    no_browser: bool = False
    headed: bool = False
    browser_timeout: int = 60
    interaction_wait: int = 0
    # advanced / performance
    discovery_concurrency: int = 10
    request_timeout: float = 15.0
    request_delay: float = 0.5
    max_security_requests: int = 250
    max_security_response_bytes: int = 1024 * 1024
    max_redirects: int = 5
    insecure: bool = False
    no_auto_evidence: bool = False
    no_history: bool = False
    # output
    output: str = "reports"
    formats: str = "json,html"
    verbose: bool = False


# -- helpers ---------------------------------------------------------------

def _normalize_target(value: str) -> Optional[str]:
    """Return a normalized HTTP(S) URL, or None if invalid."""
    candidate = value.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if not _HOSTNAME_RE.match(parsed.hostname):
        return None
    return candidate


def _ask_optional(label: str, current: str) -> str:
    """Prompt for an optional string; blank keeps/clears the value."""
    value = Prompt.ask(f"  {label} [dim](blank = none)[/dim]",
                       default=current, show_default=bool(current))
    return value.strip()


def _ask_list(label: str, current: list[str]) -> list[str]:
    """Prompt for a comma-separated list."""
    shown = ", ".join(current)
    value = Prompt.ask(
        f"  {label} [dim](comma-separated, blank = none)[/dim]",
        default=shown, show_default=bool(shown),
    )
    return [item.strip() for item in value.split(",") if item.strip()]


def _yn(value: bool) -> str:
    return "[green]yes[/green]" if value else "[dim]no[/dim]"


def _val(value: str) -> str:
    return value if value else "[dim]—[/dim]"


# -- section editors -------------------------------------------------------

def _edit_target_mode(s: _Settings) -> None:
    console.print("\n[bold]Target & scan mode[/bold]")
    while True:
        raw = Prompt.ask("  Target URL", default=s.target_url,
                         show_default=bool(s.target_url))
        normalized = _normalize_target(raw)
        if normalized:
            s.target_url = normalized
            break
        console.print("  [red]Enter a valid http(s) URL with a hostname.[/red]")
    console.print(
        "  Scan mode:  [cyan]1[/cyan] Discovery only (no active security "
        "tests)   [cyan]2[/cyan] Full (discovery + Phase 3 security testing)"
    )
    choice = Prompt.ask("  Choose", choices=["1", "2"],
                        default="1" if s.discovery_only else "2")
    s.discovery_only = choice == "1"
    if not s.discovery_only and not s.authorized_hosts:
        host = urlparse(s.target_url).hostname or ""
        if host and Confirm.ask(
            f"  Phase 3 needs an authorized host. Authorize '{host}'?",
            default=True,
        ):
            s.authorized_hosts = [host]


def _edit_baseline(s: _Settings) -> None:
    console.print("\n[bold]Baseline & evidence[/bold] "
                  "[dim](all optional — used to classify shadow vs documented)"
                  "[/dim]")
    s.openapi_spec = _ask_optional("OpenAPI/Swagger spec (path or URL)",
                                   s.openapi_spec)
    s.api_inventory = _ask_optional("Approved API inventory (JSON/YAML/CSV)",
                                    s.api_inventory)
    s.har_files = _ask_list("HAR traffic file(s)", s.har_files)
    s.traffic_log_files = _ask_list("Gateway/proxy traffic log(s)",
                                    s.traffic_log_files)
    s.compare_baseline = _ask_optional("Compare against saved baseline JSON",
                                       s.compare_baseline)
    s.save_baseline = _ask_optional("Save endpoint baseline to JSON",
                                    s.save_baseline)
    s.ground_truth = _ask_optional("Labeled ground-truth JSON (metrics)",
                                   s.ground_truth)


def _edit_auth(s: _Settings) -> None:
    console.print("\n[bold]Authentication[/bold] "
                  "[dim](for targets that require a login)[/dim]")
    console.print(
        "  [cyan]1[/cyan] None   [cyan]2[/cyan] Bearer/token header   "
        "[cyan]3[/cyan] Cookie   [cyan]4[/cyan] Programmatic login "
        "(--login-config)   [cyan]5[/cyan] Browser storage-state"
    )
    choice = Prompt.ask("  Method", choices=["1", "2", "3", "4", "5"],
                        default="1")
    # clear all first so switching methods is clean
    s.auth_token = s.cookie = s.login_config = s.storage_state = ""
    if choice == "2":
        s.auth_header = Prompt.ask("  Header name", default=s.auth_header)
        s.auth_token = _ask_optional("Header value (e.g. 'Bearer eyJ...')",
                                     s.auth_token)
    elif choice == "3":
        s.cookie = _ask_optional("Cookie header value", s.cookie)
    elif choice == "4":
        console.print("  [dim]Login config declares the login URL, body "
                      "(creds via ${ENV_VAR}), token location and "
                      "injection.[/dim]")
        s.login_config = _ask_optional("Login config file (JSON/YAML)",
                                       s.login_config)
    elif choice == "5":
        s.storage_state = _ask_optional("Playwright storage-state JSON",
                                        s.storage_state)


def _edit_security(s: _Settings) -> None:
    console.print("\n[bold]Security testing (Phase 3)[/bold]")
    if s.discovery_only:
        console.print("  [yellow]Scan mode is Discovery only — Phase 3 will "
                      "be skipped. Switch to Full mode to use these.[/yellow]")
    s.authorized_hosts = _ask_list(
        "Authorized host(s) [dim](required for Phase 3)[/dim]",
        s.authorized_hosts,
    )
    s.active_testing = Confirm.ask(
        "  Allow active, state-changing exploit validation?",
        default=s.active_testing,
    )
    console.print("  [dim]Controlled validator configs (blank to skip each):"
                  "[/dim]")
    s.bola_config = _ask_optional("BOLA two-identity config", s.bola_config)
    s.auth_validation_config = _ask_optional("Broken-auth config",
                                             s.auth_validation_config)
    s.parameter_validation_config = _ask_optional(
        "Parameter-mutation config", s.parameter_validation_config)
    s.injection_validation_config = _ask_optional(
        "Safe-injection config", s.injection_validation_config)
    s.access_validation_config = _ask_optional(
        "Session/access config", s.access_validation_config)
    s.sensitive_field_patterns = _ask_list(
        "Extra sensitive-field regex(es)", s.sensitive_field_patterns)
    if Confirm.ask("  Tune rate-limit probe parameters?", default=False):
        s.rate_limit_requests = IntPrompt.ask(
            "  Max requests per probe (2-10)", default=s.rate_limit_requests)
        s.rate_limit_delay = FloatPrompt.ask(
            "  Delay between batches (s)", default=s.rate_limit_delay)
        s.rate_limit_concurrency = IntPrompt.ask(
            "  Probe concurrency (1-3)", default=s.rate_limit_concurrency)
        s.rate_limit_timeout = FloatPrompt.ask(
            "  Per-request timeout (s)", default=s.rate_limit_timeout)


def _edit_browser(s: _Settings) -> None:
    console.print("\n[bold]Browser (Phase 2 dynamic monitoring)[/bold]")
    s.no_browser = not Confirm.ask(
        "  Run the browser crawl (Phase 2 dynamic capture)?",
        default=not s.no_browser,
    )
    if not s.no_browser:
        s.headed = Confirm.ask("  Show the browser window (headed)?",
                               default=s.headed)
        s.browser_timeout = IntPrompt.ask("  Browser timeout (seconds)",
                                          default=s.browser_timeout)
        if s.headed:
            s.interaction_wait = IntPrompt.ask(
                "  Seconds for manual actions in the headed browser",
                default=s.interaction_wait)


def _edit_advanced(s: _Settings) -> None:
    console.print("\n[bold]Advanced / performance[/bold]")
    s.discovery_concurrency = IntPrompt.ask(
        "  Discovery concurrency (1-20)", default=s.discovery_concurrency)
    s.request_timeout = FloatPrompt.ask(
        "  Per-request timeout (s)", default=s.request_timeout)
    s.request_delay = FloatPrompt.ask(
        "  Delay between security requests (s)", default=s.request_delay)
    s.max_security_requests = IntPrompt.ask(
        "  Phase 3 global request budget", default=s.max_security_requests)
    s.max_security_response_bytes = IntPrompt.ask(
        "  Max response bytes retained (Phase 3)",
        default=s.max_security_response_bytes)
    s.max_redirects = IntPrompt.ask("  Max redirects followed",
                                    default=s.max_redirects)
    s.insecure = not Confirm.ask("  Verify TLS certificates?",
                                 default=not s.insecure)
    s.no_auto_evidence = not Confirm.ask(
        "  Auto-discover local evidence (HAR/inventory in cwd)?",
        default=not s.no_auto_evidence)
    s.no_history = not Confirm.ask(
        "  Keep per-target inventory history?", default=not s.no_history)


def _edit_output(s: _Settings) -> None:
    console.print("\n[bold]Output[/bold]")
    s.output = Prompt.ask("  Output directory", default=s.output)
    while True:
        fmts = Prompt.ask("  Report formats", default=s.formats)
        chosen = [f.strip().lower() for f in fmts.split(",") if f.strip()]
        if chosen and set(chosen) <= {"json", "html"}:
            s.formats = ",".join(chosen)
            break
        console.print("  [red]Formats must be a subset of json,html.[/red]")
    s.verbose = Confirm.ask("  Verbose logging?", default=s.verbose)


# -- summary + build -------------------------------------------------------

def _summary(s: _Settings) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    table.add_row("Target", _val(s.target_url))
    table.add_row("Mode", "Discovery only" if s.discovery_only
                  else "Full (discovery + Phase 3)")
    baseline = s.openapi_spec or (", ".join(s.har_files)) or s.api_inventory
    table.add_row("Baseline/evidence", _val(baseline))
    auth = ("login-config" if s.login_config else
            "token" if s.auth_token else
            "cookie" if s.cookie else
            "storage-state" if s.storage_state else "")
    table.add_row("Auth", _val(auth))
    if not s.discovery_only:
        table.add_row("Authorized hosts", _val(", ".join(s.authorized_hosts)))
        table.add_row("Active testing", _yn(s.active_testing))
    table.add_row("Browser (Phase 2)", _yn(not s.no_browser)
                  + ("  [dim](headed)[/dim]" if s.headed else ""))
    table.add_row("TLS verify", _yn(not s.insecure))
    table.add_row("Output", f"{s.output}  [dim]({s.formats})[/dim]")
    return table


def _build_config(s: _Settings) -> ScanConfig:
    spec_url = spec_file = None
    if s.openapi_spec:
        if s.openapi_spec.startswith(("http://", "https://")):
            spec_url = s.openapi_spec
        else:
            spec_file = s.openapi_spec
    config = ScanConfig(
        target_url=s.target_url,
        output_dir=s.output,
        openapi_spec_url=spec_url,
        openapi_spec_file=spec_file,
        browser_headless=not s.headed,
        browser_timeout=s.browser_timeout,
        interaction_wait=s.interaction_wait,
        browser_storage_state=s.storage_state or None,
        max_discovery_concurrency=s.discovery_concurrency,
        request_timeout=s.request_timeout,
        rate_limit_delay=s.request_delay,
        max_security_requests=s.max_security_requests,
        max_security_response_bytes=s.max_security_response_bytes,
        max_redirects=s.max_redirects,
        verify_tls=not s.insecure,
        enable_security_testing=not s.discovery_only,
        enable_active_testing=s.active_testing,
        login_config_file=s.login_config or None,
        bola_config_file=s.bola_config or None,
        auth_validation_config_file=s.auth_validation_config or None,
        parameter_validation_config_file=s.parameter_validation_config or None,
        injection_validation_config_file=s.injection_validation_config or None,
        access_validation_config_file=s.access_validation_config or None,
        security_authorized_hosts=list(s.authorized_hosts),
        sensitive_field_patterns=list(s.sensitive_field_patterns),
        rate_limit_probe_requests=s.rate_limit_requests,
        rate_limit_probe_delay=s.rate_limit_delay,
        rate_limit_probe_concurrency=s.rate_limit_concurrency,
        rate_limit_probe_timeout=s.rate_limit_timeout,
        report_formats=[f.strip().lower() for f in s.formats.split(",")],
        verbose=s.verbose,
        auth_token=s.auth_token or None,
        auth_header=s.auth_header,
        cookie=s.cookie or None,
        har_files=list(s.har_files),
        traffic_log_files=list(s.traffic_log_files),
        api_inventory_file=s.api_inventory or None,
        save_baseline=s.save_baseline or None,
        compare_baseline=s.compare_baseline or None,
        auto_evidence=not s.no_auto_evidence,
        auto_history=not s.no_history,
        ground_truth_file=s.ground_truth or None,
    )
    if s.no_browser:
        config.browser_timeout = 0
        config.wait_after_load = 0
    return config


# -- entry point -----------------------------------------------------------

def launch_tui(initial_target: str = "") -> Optional[ScanConfig]:
    """Run the interactive menu. Returns a ScanConfig to run, or None."""
    settings = _Settings()
    normalized = _normalize_target(initial_target) if initial_target else None
    if normalized:
        settings.target_url = normalized

    console.print(BANNER)
    console.print(
        "[dim]Only scan targets you own or are explicitly authorized to "
        "test.[/dim]\n"
    )

    sections = {
        "1": ("Target & scan mode", _edit_target_mode),
        "2": ("Baseline & evidence", _edit_baseline),
        "3": ("Authentication", _edit_auth),
        "4": ("Security testing (Phase 3)", _edit_security),
        "5": ("Browser (Phase 2)", _edit_browser),
        "6": ("Advanced / performance", _edit_advanced),
        "7": ("Output", _edit_output),
    }

    if not settings.target_url:
        _edit_target_mode(settings)

    while True:
        console.print(Panel(_summary(settings), title="Current scan",
                            border_style="blue"))
        menu = "  ".join(f"[cyan]{k}[/cyan] {name}"
                         for k, (name, _) in sections.items())
        console.print(menu)
        console.print("  [green]R[/green] Run scan    "
                      "[red]Q[/red] Quit")
        choice = Prompt.ask("Select", default="R").strip().lower()
        if choice == "q":
            console.print("[dim]Cancelled.[/dim]")
            return None
        if choice == "r":
            if not settings.target_url:
                console.print("[red]Set a target URL first (option 1).[/red]")
                continue
            # In Full mode, scope Phase 3 to the target's own host by default
            # when no explicit authorized host was entered.
            if not settings.discovery_only and not settings.authorized_hosts:
                host = urlparse(settings.target_url).hostname
                if host:
                    settings.authorized_hosts = [host]
            if Confirm.ask("Start the scan now?", default=True):
                return _build_config(settings)
            continue
        if choice in sections:
            sections[choice][1](settings)
        else:
            console.print("[red]Pick a menu option.[/red]")
