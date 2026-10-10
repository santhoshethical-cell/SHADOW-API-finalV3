"""
Phase 1: API Path Hierarchy Explorer

Explores parent paths of discovered API endpoints by progressively
stripping path segments to find hidden documentation, root API listings,
and admin panels.

Also parses discovered HTML/JSON documentation pages to extract
additional API endpoints, and brute-forces common REST resource paths
(e.g., /api/checkout, /api/cart, /api/users).

Example:
    /api/user/wiener -> /api/user -> /api -> discovers API docs!
    HTML docs page -> parse for /api/checkout, /api/products links
    Brute-force -> probe /api/cart, /api/orders, /api/checkout

This technique mimics the manual API reconnaissance approach used in
real-world penetration testing.
"""

from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, EndpointSource

logger = logging.getLogger("shadow_api_scanner")

# Content indicators that suggest an interesting discovery
INTERESTING_INDICATORS = {
    "api_docs": [
        "openapi", "swagger", "api-docs", "paths", "endpoints",
        "documentation", "api reference", "api specification",
    ],
    "api_listing": [
        "routes", "available", "methods", "resources",
        "\"get\"", "\"post\"", "\"put\"", "\"delete\"", "\"patch\"",
    ],
    "admin_panel": [
        "admin", "dashboard", "management", "configuration",
        "settings", "control panel",
    ],
    "debug_info": [
        "debug", "trace", "stack", "environment", "version",
        "server info", "phpinfo",
    ],
    "error_leak": [
        "internal server error", "traceback", "exception",
        "stack trace", "syntax error",
    ],
}

# Common REST API resource names to brute-force under /api
COMMON_API_RESOURCES = [
    "users", "user", "accounts", "account",
    "products", "product", "items", "item",
    "orders", "order", "checkout", "cart", "basket",
    "payments", "payment", "transactions",
    "login", "logout", "register", "auth", "token",
    "profile", "settings", "config", "preferences",
    "search", "upload", "download", "export", "import",
    "notifications", "messages", "comments", "reviews",
    "categories", "tags", "posts", "articles",
    "admin", "dashboard", "stats", "analytics",
    "health", "status", "info", "version", "ping",
    "webhook", "callback", "events",
    "files", "images", "media", "assets",
    "roles", "permissions", "groups",
    "sessions", "tokens", "keys",
    "coupons", "discounts", "promotions",
    "inventory", "stock", "shipping",
]

# Sensitive/undocumented suffixes probed under every discovered base path.
# These are the classic shadow endpoints a client never references.
SENSITIVE_SUFFIXES = [
    "_debug", "debug", "admin", "internal", "actuator", "actuator/health",
    "swagger.json", "openapi.json", "api-docs", ".env", "config", "backup",
    "metrics", "trace", "console",
]


class PathExplorer:
    """
    Explore parent paths of API endpoints to discover hidden resources.

    Capabilities:
    1. Strip path segments to walk up the API hierarchy
    2. Parse discovered HTML/JSON docs to extract endpoint URLs
    3. Brute-force common REST resource paths under /api
    4. Probe with OPTIONS to discover allowed HTTP methods
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._explored: set[str] = set()
        self._discoveries: list[dict] = []
        self._discovered_api_roots: set[str] = set()

    async def explore(
        self, endpoints: list[APIEndpoint]
    ) -> tuple[list[APIEndpoint], list[dict]]:
        """
        Explore parent paths of all discovered endpoints.

        Args:
            endpoints: List of known API endpoints to explore from

        Returns:
            Tuple of (newly discovered endpoints, discovery details)
        """
        logger.info("  Exploring API path hierarchy...")

        new_endpoints: list[APIEndpoint] = []
        target_origin = self._get_origin(self.config.target_url)

        # Collect unique API base paths to explore
        paths_to_explore: set[str] = set()
        for ep in endpoints:
            ep_origin = self._get_origin(ep.url)
            # Only explore same-origin endpoints
            if ep_origin == target_origin:
                paths_to_explore.add(ep.url)
                parent_paths = self._get_parent_paths(ep.url)
                paths_to_explore.update(parent_paths)

        # Also add common API root paths
        common_roots = ["/api", "/api/v1", "/api/v2", "/rest", "/graphql"]
        for root in common_roots:
            full_url = urljoin(self.config.target_url, root)
            paths_to_explore.add(full_url)

        # Probe a small set of sensitive/undocumented suffixes under each
        # discovered base path and the origin root — these are classic shadow
        # endpoints (debug dumps, admin panels, exposed specs, env files) that
        # never appear in a client's JS or an OpenAPI spec. Bounded to the
        # shortest unique base paths (API roots are short) so the request budget
        # stays reasonable on large targets.
        bases = {
            b.split("?")[0].rstrip("/") or urljoin(self.config.target_url, "/")
            for b in paths_to_explore
            if "{" not in b  # skip unresolved templates
        }
        bases.add(urljoin(self.config.target_url, "/").rstrip("/"))
        for base in sorted(bases, key=len)[:12]:
            for suffix in SENSITIVE_SUFFIXES:
                paths_to_explore.add(base + "/" + suffix)

        if not paths_to_explore:
            logger.info("    No parent paths to explore.")
            return new_endpoints, self._discoveries

        logger.info(f"    Probing {len(paths_to_explore)} parent paths...")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.request_timeout),
            follow_redirects=True,
            max_redirects=self.config.max_redirects,
            verify=self.config.verify_tls,
            headers=self.config.get_headers(),
        ) as client:
            # Step 1: Explore parent paths
            for url in sorted(paths_to_explore):
                if url in self._explored:
                    continue
                self._explored.add(url)

                result = await self._probe(client, "GET", url)
                if result:
                    new_endpoints.append(result["endpoint"])
                    self._discoveries.append(result)

                    # If we found an API root, remember it for brute-forcing
                    parsed = urlparse(url)
                    if parsed.path.rstrip("/") in ("/api", "/api/v1",
                                                    "/api/v2", "/rest"):
                        self._discovered_api_roots.add(url.rstrip("/"))

                options_result = await self._probe_options(client, url)
                if options_result:
                    self._discoveries.append(options_result)
                    for method in options_result.get("allowed_methods", []):
                        if method in {"GET", "HEAD", "OPTIONS"}:
                            continue
                        new_endpoints.append(
                            self._allowed_method_endpoint(
                                url,
                                method,
                                options_result["allowed_methods"],
                            )
                        )

            # Step 2: Parse HTML/JSON doc pages for endpoint URLs
            docs_endpoints = self._extract_endpoints_from_discoveries()
            for ep in docs_endpoints:
                if ep.url not in self._explored:
                    self._explored.add(ep.url)
                    probe_result = await self._probe(client, "GET", ep.url)
                    if probe_result:
                        new_endpoints.append(probe_result["endpoint"])
                        self._discoveries.append(probe_result)
                    else:
                        # Even if the probe doesn't classify it as
                        # "interesting", it may still be a valid endpoint
                        # that responds (e.g. 400 requiring session)
                        alt = await self._probe_any_response(client, ep.url)
                        if alt:
                            new_endpoints.append(alt["endpoint"])
                            self._discoveries.append(alt)

            # Step 3: Brute-force common REST paths under discovered API roots
            if not self._discovered_api_roots:
                # Default to /api if none found
                api_root = urljoin(
                    self.config.target_url, "/api"
                ).rstrip("/")
                self._discovered_api_roots.add(api_root)

            brute_eps = await self._brute_force_api_paths(client)
            new_endpoints.extend(brute_eps)

        logger.info(
            f"    Path exploration complete: "
            f"{len(new_endpoints)} new endpoints, "
            f"{len(self._discoveries)} discoveries"
        )
        for disc in self._discoveries:
            logger.info(
                f"      {disc.get('type', 'unknown'):15s} "
                f"{disc.get('method', 'GET'):6s} {disc.get('url', '')}"
            )

        return new_endpoints, self._discoveries

    async def _probe(
        self, client: httpx.AsyncClient, method: str, url: str
    ) -> Optional[dict]:
        """Probe a URL and analyze the response."""
        try:
            resp = await client.request(method, url)

            # Skip obvious 404s and error responses
            if resp.status_code in (404, 405, 500, 502, 503):
                return None

            body = resp.text[:5000].lower() if resp.text else ""
            content_type = resp.headers.get("content-type", "").lower()

            # Analyze what we found
            discovery_type = self._classify_response(
                resp.status_code, body, content_type
            )

            if discovery_type:
                logger.info(
                    f"    [{discovery_type}] {method} {url} -> "
                    f"HTTP {resp.status_code}"
                )

                endpoint = APIEndpoint(
                    url=url,
                    method=method,
                    source=EndpointSource.PATH_EXPLORATION,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp.text[:5000] if resp.text else None,
                    confidence=0.9,
                )

                return {
                    "type": discovery_type,
                    "url": url,
                    "method": method,
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "body_preview": resp.text[:5000] if resp.text else "",
                    "endpoint": endpoint,
                }

        except Exception as e:
            logger.debug(f"    Probe failed for {url}: {e}")

        return None

    async def _probe_any_response(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[dict]:
        """
        Probe a URL and accept any non-404 response as a valid endpoint.

        Used for endpoints extracted from docs that might require
        authentication (return 400/401) but still confirm the path exists.
        """
        try:
            resp = await client.request("GET", url)

            # 400 "No session" or 401/403 means the endpoint exists
            # but needs auth - still a valuable discovery
            if resp.status_code in (400, 401, 403):
                body = resp.text[:2000] if resp.text else ""
                logger.info(
                    f"    [requires_auth] GET {url} -> "
                    f"HTTP {resp.status_code}"
                )

                endpoint = APIEndpoint(
                    url=url,
                    method="GET",
                    source=EndpointSource.PATH_EXPLORATION,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=body,
                    confidence=0.8,
                )

                discovery = {
                    "type": "requires_auth",
                    "url": url,
                    "method": "GET",
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get(
                        "content-type", ""
                    ).lower(),
                    "body_preview": body,
                    "endpoint": endpoint,
                }

                return discovery

            # A 200 JSON response is always interesting
            if resp.status_code == 200:
                content_type = resp.headers.get(
                    "content-type", ""
                ).lower()
                if "json" in content_type:
                    endpoint = APIEndpoint(
                        url=url,
                        method="GET",
                        source=EndpointSource.PATH_EXPLORATION,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=(resp.text[:5000]
                                       if resp.text else None),
                        confidence=0.9,
                    )
                    logger.info(
                        f"    [api_response] GET {url} -> "
                        f"HTTP {resp.status_code}"
                    )
                    return {
                        "type": "api_response",
                        "url": url,
                        "method": "GET",
                        "status_code": resp.status_code,
                        "content_type": content_type,
                        "body_preview": resp.text[:5000] if resp.text else "",
                        "endpoint": endpoint,
                    }

        except Exception as e:
            logger.debug(f"    Probe failed for {url}: {e}")

        return None

    async def _probe_options(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[dict]:
        """Probe with OPTIONS to discover allowed HTTP methods."""
        try:
            resp = await client.request("OPTIONS", url)
            allow = resp.headers.get("allow", "")
            # Many real servers answer OPTIONS with 405 (Method Not Allowed)
            # yet still return an authoritative Allow header. Honour the header
            # whenever it is present, not only on 200/204.
            if allow and resp.status_code in (200, 204, 405):
                methods = [m.strip().upper() for m in allow.split(",")]
                interesting_methods = {"DELETE", "PUT", "PATCH"}
                if interesting_methods.intersection(methods):
                    logger.info(
                        f"    OPTIONS {url} -> "
                        f"Allowed: {', '.join(methods)}"
                    )
                    return {
                        "type": "allowed_methods",
                        "url": url,
                        "method": "OPTIONS",
                        "status_code": resp.status_code,
                        "allowed_methods": methods,
                    }
        except Exception:
            pass
        return None

    @staticmethod
    def _allowed_method_endpoint(
        url: str,
        method: str,
        allowed_methods: list[str],
    ) -> APIEndpoint:
        """Represent server-declared method support without faking a response."""
        return APIEndpoint(
            url=url,
            method=method,
            source=EndpointSource.PATH_EXPLORATION,
            response_headers={"allow": ", ".join(allowed_methods)},
            operation_evidence=["allowed"],
            confidence=0.75,
        )

    def _extract_endpoints_from_discoveries(self) -> list[APIEndpoint]:
        """
        Parse discovered HTML/JSON documentation pages to extract
        API endpoint URLs mentioned in the content.

        Looks for:
        - href="/api/checkout" patterns in HTML
        - URL patterns like /api/products, /api/users in JSON/text
        - Route definitions in interactive API docs
        """
        extracted: list[APIEndpoint] = []
        seen_urls: set[str] = set()

        target_origin = self._get_origin(self.config.target_url)

        for disc in self._discoveries:
            body = disc.get("body_preview", "")
            if not body:
                continue

            # Pattern 1: href="/api/..." or action="/api/..."
            for m in re.finditer(
                r'(?:href|action|url|endpoint)\s*[=:]\s*["\']'
                r'(/api[^"\'#\s]*)["\']',
                body, re.IGNORECASE
            ):
                path = m.group(1)
                full = urljoin(self.config.target_url, path)
                if full not in seen_urls:
                    seen_urls.add(full)
                    extracted.append(APIEndpoint(
                        url=full, method="GET",
                        source=EndpointSource.PATH_EXPLORATION,
                        confidence=0.85,
                    ))

            # Pattern 2: /api/resource paths in JSON or text
            for m in re.finditer(
                r'["\s](/api/[a-zA-Z0-9_/-]+)',
                body
            ):
                path = m.group(1).rstrip("/")
                # Skip if it looks like a file extension
                if re.search(r'\.\w{2,4}$', path):
                    continue
                full = urljoin(self.config.target_url, path)
                if full not in seen_urls:
                    seen_urls.add(full)
                    extracted.append(APIEndpoint(
                        url=full, method="GET",
                        source=EndpointSource.PATH_EXPLORATION,
                        confidence=0.75,
                    ))

            # Pattern 3: REST paths like /checkout, /products in
            # HTML forms/links on doc pages
            for m in re.finditer(
                r'(?:href|action)\s*=\s*["\']'
                r'(/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*)["\']',
                body, re.IGNORECASE
            ):
                path = m.group(1)
                # Only include paths that look like API routes
                if any(seg in path.lower() for seg in [
                    "checkout", "cart", "order", "user",
                    "product", "api", "account", "payment",
                ]):
                    full = urljoin(self.config.target_url, path)
                    if full not in seen_urls:
                        seen_urls.add(full)
                        extracted.append(APIEndpoint(
                            url=full, method="GET",
                            source=EndpointSource.PATH_EXPLORATION,
                            confidence=0.7,
                        ))

        if extracted:
            logger.info(
                f"    Extracted {len(extracted)} endpoints "
                f"from documentation pages"
            )

        return extracted

    async def _brute_force_api_paths(
        self, client: httpx.AsyncClient
    ) -> list[APIEndpoint]:
        """
        Brute-force common REST API resource paths under discovered
        API roots (e.g., /api/checkout, /api/cart, /api/users).
        """
        new_endpoints: list[APIEndpoint] = []

        for api_root in self._discovered_api_roots:
            logger.info(
                f"    Brute-forcing common paths under {api_root}..."
            )
            found_count = 0

            for resource in COMMON_API_RESOURCES:
                url = f"{api_root}/{resource}"
                if url in self._explored:
                    continue
                self._explored.add(url)

                try:
                    resp = await client.request("GET", url)

                    if resp.status_code == 404:
                        continue

                    content_type = resp.headers.get(
                        "content-type", ""
                    ).lower()
                    body = resp.text[:2000] if resp.text else ""

                    # Accept responses that look like APIs. Some SPAs return
                    # index.html with HTTP 200 for unknown paths, especially
                    # when the request accepts text/html; treating those as
                    # endpoints creates a large false-positive inventory.
                    if not self._is_api_like_response(resp, body):
                        continue

                    # Accept: 200/201 JSON (OK), 400 (needs params/session),
                    # 401/403 (needs auth) - all confirm path exists.
                    if resp.status_code in (200, 201, 400, 401, 403):
                        ep_type = "api_response"
                        if resp.status_code in (400, 401, 403):
                            ep_type = "requires_auth"

                        logger.info(
                            f"    [{ep_type}] GET {url} -> "
                            f"HTTP {resp.status_code}"
                        )

                        endpoint = APIEndpoint(
                            url=url,
                            method="GET",
                            source=EndpointSource.PATH_EXPLORATION,
                            status_code=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body=body,
                            confidence=0.85
                            if resp.status_code == 200 else 0.7,
                        )
                        new_endpoints.append(endpoint)
                        self._discoveries.append({
                            "type": ep_type,
                            "url": url,
                            "method": "GET",
                            "status_code": resp.status_code,
                            "content_type": content_type,
                            "body_preview": body,
                            "endpoint": endpoint,
                        })
                        found_count += 1

                except Exception:
                    continue

            if found_count:
                logger.info(
                    f"    Brute-force found {found_count} "
                    f"endpoints under {api_root}"
                )

        return new_endpoints

    def _classify_response(
        self, status_code: int, body: str, content_type: str
    ) -> Optional[str]:
        """Classify what kind of discovery a response represents."""
        if status_code not in (200, 201, 301, 302):
            return None

        # JSON responses are almost always interesting from API paths
        is_json = "json" in content_type

        # Check for API documentation
        if is_json or "html" in content_type:
            for indicator in INTERESTING_INDICATORS["api_docs"]:
                if indicator in body:
                    return "api_documentation"

        # Check for API listing / route enumeration
        if is_json:
            for indicator in INTERESTING_INDICATORS["api_listing"]:
                if indicator in body:
                    return "api_listing"

        # Check for admin/debug content
        for indicator in INTERESTING_INDICATORS["admin_panel"]:
            if indicator in body:
                return "admin_panel"

        for indicator in INTERESTING_INDICATORS["debug_info"]:
            if indicator in body:
                return "debug_info"

        # Check for error information leakage
        for indicator in INTERESTING_INDICATORS["error_leak"]:
            if indicator in body:
                return "error_leak"

        # A 200 JSON response from an API path is always noteworthy
        if is_json and status_code == 200 and len(body) > 10:
            return "api_response"

        return None

    @staticmethod
    def _is_api_like_response(resp: httpx.Response, body: str) -> bool:
        """Return True when a brute-force response is likely a real API."""
        status_code = resp.status_code
        content_type = resp.headers.get("content-type", "").lower()

        if status_code in (404, 405, 500, 502, 503):
            return False

        if "json" in content_type:
            return status_code in (200, 201, 400, 401, 403)

        # Auth failures from API gateways are sometimes empty or plain text.
        if status_code in (401, 403):
            return "html" not in content_type

        if "html" in content_type:
            html_markers = (
                "<!doctype html",
                "<html",
                'id="root"',
                'id="app"',
                "/static/js/",
            )
            if any(marker in body.lower() for marker in html_markers):
                return False

        return False

    def _get_parent_paths(self, url: str) -> list[str]:
        """
        Generate all parent paths by stripping segments.

        /api/user/wiener -> [/api/user, /api]
        """
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        origin = f"{parsed.scheme}://{parsed.netloc}"

        parents = []
        segments = path.split("/")

        # Strip segments from the right, one at a time
        for i in range(len(segments) - 1, 0, -1):
            parent_path = "/".join(segments[:i])
            if parent_path and parent_path != "/":
                parents.append(f"{origin}{parent_path}")

        return parents

    def _get_origin(self, url: str) -> str:
        """Extract origin (scheme + host + port) from a URL."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return origin.lower()
