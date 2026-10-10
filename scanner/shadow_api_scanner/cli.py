"""
Shadow API Scanner - CLI Entry Point

Parses command-line arguments and orchestrates the four-phase scan pipeline.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shadow_api_scanner import __version__
from shadow_api_scanner.auth import (
    LoginConfigError,
    LoginError,
    SessionManager,
)
from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import (
    DocumentationStatus,
    ScanResult,
    SHADOW_UNMANAGED_API_LABEL,
)
from shadow_api_scanner.evaluation import AccuracyEvaluator
from shadow_api_scanner.phase1.static_analyzer import StaticAnalyzer
from shadow_api_scanner.phase1.path_explorer import PathExplorer
from shadow_api_scanner.phase1.template_resolver import (
    contains_template_expression,
)
from shadow_api_scanner.phase2.baseline import BaselineManager
from shadow_api_scanner.phase2.evidence_finder import EvidenceFinder
from shadow_api_scanner.phase2.route_clusterer import RouteClusterer
from shadow_api_scanner.phase2.shadow_detector import ShadowDetector
from shadow_api_scanner.phase2.traffic_importer import TrafficImporter
from shadow_api_scanner.phase3.security_tester import SecurityTester
from shadow_api_scanner.phase4.risk_scorer import RiskScorer
from shadow_api_scanner.phase4.report_generator import ReportGenerator
from shadow_api_scanner.utils.helpers import setup_logging

console = Console()

BANNER = rf"""
[bold magenta]
 ____  _               _                  _    ____ ___
/ ___|| |__   __ _  __| | _____      __  / \  |  _ \_ _|
\___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / / _ \ | |_) | |
 ___) | | | | (_| | (_| | (_) \ V  V / / ___ \|  __/| |
|____/|_| |_|\__,_|\__,_|\___/ \_/\_/ /_/   \_\_|  |___|
    [cyan]Scanner v{__version__} - Shadow / Unmanaged API Security Testing[/cyan]
[/bold magenta]"""


async def run_scan(config: ScanConfig) -> ScanResult:
    """Execute the full four-phase scan pipeline."""
    logger = setup_logging(config.verbose)

    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold] {config.target_url}\n"
        f"[bold]Output:[/bold] {config.output_dir}\n"
        f"[bold]Headless:[/bold] {config.browser_headless}\n"
        f"[bold]Security testing:[/bold] {config.enable_security_testing}\n"
        f"[bold]Authorized hosts:[/bold] "
        f"{', '.join(config.security_authorized_hosts) or 'none'}\n"
        f"[bold]Active mutations:[/bold] {config.enable_active_testing}",
        title=" Scan Configuration",
        border_style="blue",
    ))

    result = ScanResult(target_url=config.target_url)

    try:
        # Phase 0: acquire an authenticated session if a login config was
        # supplied, so every later phase runs authenticated.
        if config.login_config_file:
            try:
                await SessionManager(config).apply(result)
            except (LoginConfigError, LoginError) as exc:
                logger.error("Authentication failed: %s", exc)
                result.warnings.append(f"Authentication failed: {exc}")
                raise

        # Zero-configuration evidence discovery and per-target history.
        automatic = EvidenceFinder(config).discover()
        if not config.har_files:
            config.har_files = automatic.har_files
        if not config.traffic_log_files:
            config.traffic_log_files = automatic.traffic_log_files
        if not config.api_inventory_file:
            config.api_inventory_file = automatic.api_inventory_file
        if not config.compare_baseline:
            config.compare_baseline = automatic.compare_baseline
        if not config.save_baseline:
            config.save_baseline = automatic.save_baseline

        result.evidence_sources = list(automatic.sources)
        result.baseline_history_file = config.save_baseline
        if automatic.sources:
            logger.info("  Automatic evidence selected:")
            for source in automatic.sources:
                logger.info(f"    {source}")
        if config.save_baseline and not config.compare_baseline:
            logger.info(
                "  No previous target history found; this scan will create it."
            )

        # -- Phase 1: Static JS Analysis --
        analyzer = StaticAnalyzer(config)
        static_endpoints = await analyzer.run(result)

        # -- Phase 1.25: Imported Traffic Inventory --
        traffic_importer = TrafficImporter(config)
        imported_endpoints = traffic_importer.import_har_files(
            config.har_files
        )
        imported_endpoints.extend(
            traffic_importer.import_log_files(config.traffic_log_files)
        )
        if imported_endpoints:
            static_endpoints.extend(imported_endpoints)
            result.imported_traffic_requests = len(imported_endpoints)

        # -- Phase 1.5: API Path Hierarchy Exploration --
        # For any endpoints found (static + spec), explore parent paths
        # to discover hidden docs, API roots, and admin panels.
        explorer = PathExplorer(config)
        exploration_seeds = RouteClusterer().cluster(static_endpoints)
        hierarchy_endpoints, hierarchy_discoveries = await explorer.explore(
            exploration_seeds
        )
        if hierarchy_endpoints:
            logger.info(
                f"  Path exploration found "
                f"{len(hierarchy_endpoints)} new endpoints"
            )
            static_endpoints.extend(hierarchy_endpoints)
            result.warnings.extend(
                f"Path hierarchy discovery: {d['type']} at {d['url']}"
                for d in hierarchy_discoveries
            )

        # -- Phase 2: Dynamic Monitoring + Shadow Detection --
        detector = ShadowDetector(config)
        all_endpoints = await detector.run(static_endpoints, result)

        # -- Phase 2.5: Explore paths from newly discovered endpoints --
        # Also explore parent paths of endpoints from OpenAPI spec and
        # dynamic traffic capture.
        new_ep_for_exploration = [
            ep for ep in all_endpoints if ep not in static_endpoints
        ]
        if new_ep_for_exploration:
            more_endpoints, more_discoveries = await explorer.explore(
                new_ep_for_exploration
            )
            if more_endpoints:
                appended_count = 0
                candidate_count_before = len(result.candidate_endpoints)
                classified_more = detector.classify_additional(
                    more_endpoints,
                    result,
                )
                for ep in classified_more:
                    if ep not in all_endpoints:
                        all_endpoints.append(ep)
                        result.all_endpoints.append(ep)
                        appended_count += 1
                        if ep.is_shadow:
                            result.shadow_endpoints.append(ep)
                candidate_count_added = (
                    len(result.candidate_endpoints)
                    - candidate_count_before
                )
                if appended_count or candidate_count_added:
                    result.raw_endpoints_discovered += (
                        appended_count + candidate_count_added
                    )
                if appended_count:
                    all_endpoints = RouteClusterer().cluster(all_endpoints)
                    result.all_endpoints = all_endpoints
                    result.shadow_endpoints = [
                        ep for ep in all_endpoints if ep.is_shadow
                    ]
                    result.documented_endpoints = [
                        ep for ep in all_endpoints
                        if ep.documentation_status
                        == DocumentationStatus.DOCUMENTED
                    ]

        # -- Phase 3: Security Testing --
        # Keep validation on first-party HTTP(S) operations. The exact
        # authorization list is enforced again by SecurityTester and by the
        # shared HTTP client, including every redirect.
        target_host = urlparse(config.target_url).hostname
        test_targets = [
            ep for ep in all_endpoints
            if (
                not contains_template_expression(ep.url)
                and urlparse(ep.url).scheme in ("http", "https")
                and urlparse(ep.url).hostname
                and (
                    urlparse(ep.url).hostname == target_host
                    or urlparse(ep.url).hostname.endswith(
                        '.' + (target_host or '')
                    )
                )
            )
        ]
        skipped_templates = sum(
            1 for endpoint in all_endpoints
            if contains_template_expression(endpoint.url)
        )
        if skipped_templates:
            logger.warning(
                "Skipping active tests for %s unresolved endpoint template(s).",
                skipped_templates,
            )

        scope_error = config.security_scope_error()
        if not config.enable_security_testing:
            logger.info("Discovery-only mode enabled; skipping Phase 3.")
        elif scope_error:
            message = (
                "Security validation skipped: "
                f"{scope_error}. Use --authorized-host for an explicitly "
                "approved lab target."
            )
            logger.warning(message)
            result.warnings.append(message)
        elif test_targets:
            tester = SecurityTester(config)
            await tester.run(test_targets, result)
        else:
            logger.info("No endpoints to test - skipping Phase 3.")

        # -- Phase 4: Risk Scoring & Reporting --
        scorer = RiskScorer()
        scorer.score(result)

        if config.ground_truth_file:
            try:
                result.accuracy_metrics = AccuracyEvaluator(
                    config.target_url
                ).evaluate_file(
                    config.ground_truth_file,
                    result.all_endpoints,
                    result.api_classification_for,
                )
            except (OSError, ValueError, json.JSONDecodeError) as error:
                warning = f"Accuracy evaluation failed: {error}"
                result.warnings.append(warning)
                logger.warning(warning)

        if config.compare_baseline:
            result.inventory_diff = BaselineManager.compare(
                result, config.compare_baseline
            )

        if config.save_baseline:
            saved_path = BaselineManager.save(result, config.save_baseline)
            result.inventory_diff.setdefault("saved_baseline", saved_path)

        reporter = ReportGenerator(config)
        report_files = reporter.generate(result)

        # -- Final Summary --
        _print_summary(result, report_files)
        return result

    except KeyboardInterrupt:
        console.print("\n[yellow] Scan interrupted by user.[/yellow]")
        result.errors.append("Scan interrupted by user")
        result.fatal_error = "Scan interrupted by user"
        result.finalize()
        return result
    except Exception as e:
        safe_error = f"{type(e).__name__}: scan aborted"
        console.print("\n[red]Fatal scan error; see verbose logs.[/red]")
        logger.exception("Fatal scan error")
        result.errors.append(safe_error)
        result.fatal_error = safe_error
        result.finalize()
        return result


def _print_summary(result: ScanResult, report_files: dict[str, str]):
    """Print a rich summary table to the console."""
    console.print()

    # Summary table
    table = Table(title="Scan Summary", show_header=True, border_style="bright_blue")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")

    risk_color = {
        "Critical": "bold red", "High": "bold yellow",
        "Medium": "yellow", "Low": "green", "Info": "blue",
    }.get(result.overall_risk_level.value, "white")

    table.add_row("Target URL", result.target_url)
    table.add_row("JS Files Analyzed", str(result.js_files_analyzed))
    table.add_row(
        "Templates Resolved", str(result.template_endpoints_resolved)
    )
    table.add_row("Imported Traffic", str(result.imported_traffic_requests))
    if result.baseline_sources:
        table.add_row("Baseline Sources", ", ".join(result.baseline_sources))
    else:
        table.add_row("Authoritative Baseline", "[yellow]Not found[/yellow]")
    if result.evidence_sources:
        table.add_row("Auto Evidence Files", str(len(result.evidence_sources)))
    table.add_row("API Operations", str(len(result.all_endpoints)))
    table.add_row(
        "Method Candidates",
        str(len(result.candidate_endpoints)),
    )
    table.add_row(
        "Security-Discovered Ops",
        str(result.security_operations_discovered),
    )
    table.add_row(
        "Endpoint Observations",
        str(
            result.raw_endpoints_discovered
            or sum(endpoint.observed_count for endpoint in result.all_endpoints)
        ),
    )
    api_counts = result.api_classification_counts()
    table.add_row(
        "Shadow / Unmanaged APIs",
        f"[red]{api_counts[SHADOW_UNMANAGED_API_LABEL]}[/red]",
    )
    table.add_row(
        "Unverified API References",
        f"[blue]{api_counts['Unknown API']}[/blue]",
    )
    table.add_row("Documented APIs", str(len(result.documented_endpoints)))
    unified = result.unified_findings()
    discovery_findings = unified["discovery"]
    security_findings = unified["security"]
    table.add_row(
        "Runtime-only / Static-only",
        f"{len(discovery_findings['runtime_only_api'])} / "
        f"{len(discovery_findings['static_only_api'])}",
    )
    table.add_row(
        "Undocumented Parameters",
        str(len(discovery_findings["undocumented_parameter"])),
    )
    security_counts = [
        f"{name.replace('_', ' ')}={len(findings)}"
        for name, findings in security_findings.items()
        if findings
    ]
    table.add_row(
        "Validated Security Findings",
        ", ".join(security_counts) if security_counts else "0",
    )
    if result.accuracy_metrics:
        for label, key in (
            ("Discovery Precision", "discovery_precision"),
            ("Discovery Recall", "discovery_recall"),
            ("Discovery F1", "discovery_f1"),
            ("Shadow / Unmanaged Precision", "shadow_precision"),
            ("Shadow / Unmanaged Recall", "shadow_recall"),
            ("Shadow / Unmanaged F1", "shadow_f1"),
            ("Documentation Macro F1", "documentation_macro_f1"),
            (
                "API Classification Macro F1",
                "api_classification_macro_f1",
            ),
        ):
            value = result.accuracy_metrics.get(key)
            table.add_row(
                label,
                "N/A" if value is None else f"{value:.1%}",
            )
    table.add_row("Vulnerabilities", f"[yellow]{len(result.vulnerabilities)}[/yellow]")
    table.add_row("Overall Risk", f"[{risk_color}]{result.overall_risk_level.value} ({result.overall_risk_score:.1f}/10)[/{risk_color}]")
    table.add_row("Critical", f"[red]{result.critical_count}[/red]")
    table.add_row("High", f"[yellow]{result.high_count}[/yellow]")
    table.add_row("Medium", str(result.medium_count))
    table.add_row("Low", str(result.low_count))

    if result.inventory_diff.get("summary"):
        diff = result.inventory_diff["summary"]
        table.add_row(
            "Inventory Diff",
            f"+{diff.get('added', 0)} / -{diff.get('removed', 0)} endpoints",
        )

    for fmt, path in report_files.items():
        table.add_row(f"Report ({fmt.upper()})", path)

    console.print(table)
    console.print()


def _validated_target_url(value: str) -> str:
    """Return a normalized HTTP(S) target or raise a Click input error."""
    candidate = value.strip()
    if not candidate:
        raise click.BadParameter(
            "target URL cannot be empty",
            param_hint="TARGET_URL",
        )
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise click.BadParameter(
            "target must be an HTTP or HTTPS URL with a hostname",
            param_hint="TARGET_URL",
        )
    if parsed.username is not None or parsed.password is not None:
        raise click.BadParameter(
            "URL-embedded credentials are not accepted; use scoped headers",
            param_hint="TARGET_URL",
        )
    return candidate


@click.command()
@click.version_option(__version__, prog_name="shadow-scan")
@click.argument("target_url", required=False)
@click.option("--tui", "use_tui", is_flag=True,
              help="Launch the interactive Terminal UI (all options, "
                   "menu-driven). Also opens when no target URL is given.")
@click.option("--output", "-o", default="reports", help="Output directory for reports")
@click.option("--openapi-spec", default=None, help="Path or URL to OpenAPI spec file")
@click.option(
    "--auth-token",
    default=None,
    envvar="SHADOW_API_AUTH_TOKEN",
    show_envvar=True,
    help="Authorization value; prefer the environment variable over CLI text",
)
@click.option("--auth-header", default="Authorization", help="Auth header name")
@click.option(
    "--cookie",
    default=None,
    envvar="SHADOW_API_COOKIE",
    show_envvar=True,
    help="Cookie header value; prefer the environment variable over CLI text",
)
@click.option("--har", "har_files", multiple=True, help="Import observed traffic from HAR file")
@click.option("--traffic-log", "traffic_log_files", multiple=True, help="Import observed traffic from gateway/proxy/access log file")
@click.option("--api-inventory", default=None, help="Approved API inventory JSON/YAML/CSV for shadow comparison")
@click.option("--save-baseline", default=None, help="Save endpoint inventory baseline JSON")
@click.option("--compare-baseline", default=None, help="Compare endpoint inventory with baseline JSON")
@click.option("--no-auto-evidence", is_flag=True, help="Disable automatic local evidence discovery")
@click.option("--no-history", is_flag=True, help="Disable automatic per-target inventory history")
@click.option("--no-browser", is_flag=True, help="Skip Phase 2 dynamic monitoring")
@click.option("--discovery-concurrency", default=10,
              type=click.IntRange(min=1, max=20),
              help="Concurrency cap for static and specification discovery")
@click.option("--discovery-only", is_flag=True,
              help="Discover and classify APIs without Phase 3 security tests")
@click.option("--active-testing", is_flag=True,
              help="Allow authorized state-changing exploit validation")
@click.option("--authorized-host", "authorized_hosts", multiple=True,
              help="Exact host authorized for security validation; repeatable")
@click.option("--login-config", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Login config (JSON/YAML); acquires a session before "
                   "Phase 1. Mode A (default): API login. Mode B "
                   "(mode: browser): Playwright form login -> storage state. "
                   "Credentials via ${ENV_VAR}.")
@click.option("--bola-config", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Controlled two-identity BOLA configuration JSON/YAML")
@click.option("--auth-validation-config", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Controlled broken-auth configuration JSON/YAML")
@click.option("--parameter-validation-config", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Controlled parameter-mutation configuration JSON/YAML")
@click.option("--injection-validation-config", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Controlled safe-injection configuration JSON/YAML")
@click.option("--access-validation-config", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Controlled session/access configuration JSON/YAML")
@click.option("--sensitive-field-pattern", "sensitive_field_patterns",
              multiple=True,
              help="Additional sensitive JSON field/path regex; repeatable")
@click.option("--rate-limit-requests", default=5,
              type=click.IntRange(min=2, max=10),
              help="Hard request ceiling per bounded rate assessment")
@click.option("--rate-limit-delay", default=0.25,
              type=click.FloatRange(min=0.05, max=5.0),
              help="Delay in seconds between bounded probe batches")
@click.option("--rate-limit-concurrency", default=1,
              type=click.IntRange(min=1, max=3),
              help="Concurrency cap for bounded rate probes")
@click.option("--rate-limit-timeout", default=5.0,
              type=click.FloatRange(min=0.1, max=30.0),
              help="Per-request timeout for bounded rate probes")
@click.option("--request-timeout", default=15.0,
              type=click.FloatRange(min=0.1, max=120.0),
              help="Timeout in seconds for each non-browser HTTP request")
@click.option("--request-delay", default=0.5,
              type=click.FloatRange(min=0.0, max=10.0),
              help="Minimum delay between ordinary security requests")
@click.option("--max-security-requests", default=250,
              type=click.IntRange(min=1, max=1000),
              help="Global network-attempt budget for Phase 3")
@click.option("--max-security-response-bytes", default=1024 * 1024,
              type=click.IntRange(min=1024, max=10 * 1024 * 1024),
              help="Maximum response bytes retained by Phase 3 per request")
@click.option("--max-redirects", default=5,
              type=click.IntRange(min=0, max=10),
              help="Maximum redirects followed by scanner HTTP clients")
@click.option("--insecure", is_flag=True,
              help="Disable TLS certificate verification for authorized labs")
@click.option("--headed", is_flag=True, help="Show browser window (not headless)")
@click.option("--timeout", default=60, help="Browser timeout in seconds")
@click.option("--interaction-wait", default=0, type=click.IntRange(min=0),
              help="Seconds for manual actions in a headed browser")
@click.option("--storage-state", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Playwright storage-state JSON for authenticated crawling")
@click.option("--max-response-bytes", default=65536,
              type=click.IntRange(min=1024, max=10 * 1024 * 1024),
              help="Maximum JSON response bytes retained per runtime API")
@click.option("--ground-truth", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Labeled endpoint JSON for precision and recall metrics")
@click.option("--format", "formats", default="json,html", help="Report formats (json,html)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def main(
    target_url, use_tui, output, openapi_spec, auth_token, auth_header, cookie,
    har_files, traffic_log_files, api_inventory, save_baseline, compare_baseline,
    no_auto_evidence, no_history, no_browser, discovery_concurrency,
    discovery_only,
    active_testing, authorized_hosts, login_config, bola_config,
    auth_validation_config,
    parameter_validation_config, injection_validation_config,
    access_validation_config,
    sensitive_field_patterns, rate_limit_requests,
    rate_limit_delay, rate_limit_concurrency, rate_limit_timeout,
    request_timeout, request_delay, max_security_requests,
    max_security_response_bytes, max_redirects, insecure, headed,
    timeout, interaction_wait,
    storage_state, max_response_bytes, ground_truth, formats,
    verbose,
):
    """
    Detect and test Shadow / Unmanaged APIs in Single-Page Applications.

    TARGET_URL: The authorized SPA or lab URL to scan.

    Run with no TARGET_URL (or --tui) to open the interactive Terminal UI.
    """
    if use_tui or not target_url:
        from shadow_api_scanner.tui_app import launch_cyber_tui

        tui_config = launch_cyber_tui(target_url or "")
        if tui_config is None:
            return
        result = asyncio.run(run_scan(tui_config))
        if result.fatal_error:
            raise click.ClickException("scan failed; review the logged error")
        return

    target_url = _validated_target_url(target_url)
    report_formats = [item.strip().lower() for item in formats.split(",")]
    invalid_formats = sorted(set(report_formats) - {"json", "html"})
    if invalid_formats or not report_formats:
        raise click.BadParameter(
            "formats must be a comma-separated subset of json,html",
            param_hint="--format",
        )

    # Build config
    spec_url = None
    spec_file = None
    if openapi_spec:
        if openapi_spec.startswith(("http://", "https://")):
            spec_url = openapi_spec
        else:
            spec_file = openapi_spec

    config = ScanConfig(
        target_url=target_url,
        output_dir=output,
        openapi_spec_url=spec_url,
        openapi_spec_file=spec_file,
        browser_headless=not headed,
        browser_timeout=timeout,
        interaction_wait=interaction_wait,
        browser_storage_state=storage_state,
        browser_max_response_bytes=max_response_bytes,
        max_discovery_concurrency=discovery_concurrency,
        request_timeout=request_timeout,
        rate_limit_delay=request_delay,
        max_security_requests=max_security_requests,
        max_security_response_bytes=max_security_response_bytes,
        max_redirects=max_redirects,
        verify_tls=not insecure,
        enable_security_testing=not discovery_only,
        enable_active_testing=active_testing,
        login_config_file=login_config,
        bola_config_file=bola_config,
        auth_validation_config_file=auth_validation_config,
        parameter_validation_config_file=parameter_validation_config,
        injection_validation_config_file=injection_validation_config,
        access_validation_config_file=access_validation_config,
        security_authorized_hosts=list(authorized_hosts),
        sensitive_field_patterns=list(sensitive_field_patterns),
        rate_limit_probe_requests=rate_limit_requests,
        rate_limit_probe_delay=rate_limit_delay,
        rate_limit_probe_concurrency=rate_limit_concurrency,
        rate_limit_probe_timeout=rate_limit_timeout,
        report_formats=report_formats,
        verbose=verbose,
        auth_token=auth_token,
        auth_header=auth_header,
        cookie=cookie,
        har_files=list(har_files),
        traffic_log_files=list(traffic_log_files),
        api_inventory_file=api_inventory,
        save_baseline=save_baseline,
        compare_baseline=compare_baseline,
        auto_evidence=not no_auto_evidence,
        auto_history=not no_history,
        ground_truth_file=ground_truth,
    )

    # If --no-browser, skip Phase 2 by setting timeout to 0
    if no_browser:
        config.browser_timeout = 0
        config.wait_after_load = 0

    result = asyncio.run(run_scan(config))
    if result.fatal_error:
        raise click.ClickException("scan failed; review the logged error")


if __name__ == "__main__":
    main()
