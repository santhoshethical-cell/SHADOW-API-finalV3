"""
Phase 1: Static Analyzer Orchestrator

Coordinates the JS crawling and parsing to produce
the baseline API inventory from static analysis.
"""

from __future__ import annotations

import logging
from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, ScanResult
from shadow_api_scanner.phase1.crawler import JSCrawler
from shadow_api_scanner.phase1.js_parser import JSParser
from shadow_api_scanner.phase1.template_resolver import TemplateEndpointResolver

logger = logging.getLogger("shadow_api_scanner")


class StaticAnalyzer:
    """
    Phase 1 orchestrator: static JavaScript analysis.

    1. Crawl and download JS files
    2. Parse each file for API endpoints
    3. Deduplicate and return baseline inventory
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.parser = JSParser(config.target_url)

    async def run(self, result: ScanResult) -> list[APIEndpoint]:
        """
        Execute Phase 1 static analysis.

        Args:
            result: ScanResult to populate with findings

        Returns:
            List of discovered API endpoints
        """
        logger.info("=" * 60)
        logger.info("PHASE 1: Static JavaScript Analysis")
        logger.info("=" * 60)

        # Step 1: Crawl JS files
        crawler = JSCrawler(self.config)
        js_files = await crawler.crawl()
        result.js_files_analyzed = len(js_files)
        result.warnings.extend(
            warning for warning in crawler.errors
            if warning not in result.warnings
        )

        if not js_files:
            logger.warning("No JavaScript files found. Phase 1 yielded no results.")
            return []

        # Step 2: Parse each JS file
        all_endpoints: list[APIEndpoint] = []
        for js_file in js_files:
            try:
                endpoints = self.parser.parse(js_file.content, js_file.url)
                all_endpoints.extend(endpoints)
            except Exception as e:
                logger.warning(f"  Error parsing {js_file.url}: {e}")
                result.warnings.append(f"Parse error in {js_file.url}: {e}")

        # Step 3: Resolve template values from links, query parameters, and forms.
        resolver = TemplateEndpointResolver(
            self.config.target_url,
            max_expansions=self.config.max_template_expansions,
        )
        concrete_endpoints = resolver.resolve(all_endpoints, crawler.initial_html)
        result.template_endpoints_resolved = resolver.resolved_count
        result.unresolved_template_endpoints = resolver.unresolved_count
        if resolver.unresolved_count:
            warning = (
                f"{resolver.unresolved_count} endpoint template(s) could not be "
                "resolved from page context and will not be actively tested."
            )
            result.warnings.append(warning)
            logger.warning("  %s", warning)

        # Step 4: Deduplicate
        unique_endpoints = self._deduplicate(concrete_endpoints)

        # Step 5: Log results
        logger.info(f"\nPhase 1 Results:")
        logger.info(f"  JS files analyzed: {len(js_files)}")
        logger.info(f"  Raw endpoints found: {len(all_endpoints)}")
        logger.info(f"  Template endpoints resolved: {resolver.resolved_count}")
        logger.info(f"  Unresolved templates: {resolver.unresolved_count}")
        logger.info(f"  Unique endpoints: {len(unique_endpoints)}")
        if self.parser.base_urls_discovered:
            logger.info(f"  Base URLs: {self.parser.base_urls_discovered}")
        if self.parser.secrets_found:
            logger.warning(
                f"   Exposed secrets: {len(self.parser.secrets_found)} found!"
            )
        if self.parser.graphql_operations:
            logger.info(
                f"  GraphQL operations: {self.parser.graphql_operations[:10]}"
            )

        for ep in unique_endpoints:
            logger.info(f"    {ep.method:6s} {ep.url}")

        result.static_endpoints = unique_endpoints
        return unique_endpoints

    def _deduplicate(self, endpoints: list[APIEndpoint]) -> list[APIEndpoint]:
        """Remove duplicate endpoints, keeping the highest-confidence version."""
        seen: dict[tuple[str, str], APIEndpoint] = {}
        for ep in endpoints:
            key = (ep.normalized_url, ep.method)
            if key not in seen or ep.confidence > seen[key].confidence:
                seen[key] = ep
        return list(seen.values())
