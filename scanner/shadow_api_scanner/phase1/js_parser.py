"""
Phase 1: JavaScript Parser

Extracts API endpoints, base URLs, tokens, and request patterns
from JavaScript source code using regex-based pattern matching.
"""

from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from shadow_api_scanner.core.models import APIEndpoint, EndpointSource, EndpointType
from shadow_api_scanner.utils.helpers import is_api_url

logger = logging.getLogger("shadow_api_scanner")


# --------------------------------------------------------------
# Regex patterns for API endpoint extraction
# --------------------------------------------------------------

# Matches fetch(), axios, httpx, $http calls
FETCH_PATTERNS = [
    # fetch("url") or fetch('url')
    re.compile(r"""fetch\s*\(\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
    # fetch(baseUrl + "/path") - capture the string literal part
    re.compile(r"""fetch\s*\([^)]*["'`](/[^"'`\s]{2,})["'`]""", re.I),
    # axios.get/post/put/delete("url")
    re.compile(
        r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["'`](https?://[^"'`\s]+)["'`]""",
        re.I,
    ),
    re.compile(
        r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["'`](/[^"'`\s]{2,})["'`]""",
        re.I,
    ),
    # axios({ url: "..." })
    re.compile(r"""url\s*:\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
    re.compile(r"""url\s*:\s*["'`](/api[^"'`\s]*)["'`]""", re.I),
    # XMLHttpRequest.open("METHOD", "url")
    re.compile(
        r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`](https?://[^"'`\s]+)["'`]""",
        re.I,
    ),
    re.compile(
        r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`](/[^"'`\s]{2,})["'`]""",
        re.I,
    ),
]

TEMPLATE_FETCH_PATTERNS = [
    re.compile(r"""fetch\s*\(\s*`([^`]*\$\{[^`]+)`""", re.I),
]

# HTTP method extraction from various patterns
METHOD_PATTERNS = [
    re.compile(r"""method\s*:\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]""", re.I),
    re.compile(r"""\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]""", re.I),
    re.compile(r"""axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(""", re.I),
    re.compile(r"""\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]""", re.I),
]

# Full URL patterns (absolute URLs in strings)
URL_PATTERNS = [
    re.compile(r"""["'`](https?://[a-zA-Z0-9._-]+(?::\d+)?/[^"'`\s]{2,})["'`]"""),
]

# Relative API path patterns
API_PATH_PATTERNS = [
    re.compile(r"""["'`](/api/v?\d*/[^"'`\s]{2,})["'`]"""),
    re.compile(r"""["'`](/api/[^"'`\s]{2,})["'`]"""),
    re.compile(r"""["'`](/v[1-4]/[^"'`\s]{2,})["'`]"""),
    re.compile(r"""["'`](/graphql[^"'`\s]*)["'`]"""),
    re.compile(r"""["'`](/rest/[^"'`\s]{2,})["'`]"""),
]

# Base URL patterns
BASE_URL_PATTERNS = [
    re.compile(r"""(?:baseURL|base_url|baseUrl|BASE_URL|apiUrl|API_URL|apiBase)\s*[:=]\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
    re.compile(r"""(?:API_BASE|BACKEND_URL|SERVER_URL|API_ENDPOINT)\s*[:=]\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
]

# WebSocket patterns
WEBSOCKET_PATTERNS = [
    re.compile(r"""["'`](wss?://[^"'`\s]+)["'`]"""),
    re.compile(r"""new\s+WebSocket\s*\(\s*["'`](wss?://[^"'`\s]+)["'`]"""),
]

# GraphQL operation patterns
GRAPHQL_PATTERNS = [
    re.compile(r"""(?:query|mutation|subscription)\s+(\w+)\s*[({]""", re.I),
    re.compile(r"""gql\s*`\s*(?:query|mutation|subscription)\s+(\w+)""", re.I),
]

# A route-map value is treated as an API path when it is either absolute
# (begins with "/") or a bare API-style relative path such as "api/...",
# "rest/...", "graphql", or "v2/...". This is the generic signal used to
# recognise a minified route-constant object without knowing its variable
# name or the application it comes from.
ROUTE_MAP_PATH_VALUE = re.compile(
    r"^/?(?:api|rest|graphql|v\d+)(?:/|$)", re.I
)

# A prefix constant is a bare, relative path segment ending in "/" assigned to
# a short identifier, e.g. P="serviceA/". Minified SPA bundles frequently
# concatenate such a prefix with a route-map entry (P+ROUTES.LOGIN) to build the
# final path; discovering both lets the resolver reconstruct the real URL
# without hard-coding any application's service names.
PREFIX_CONSTANT_PATTERN = re.compile(
    r"""([A-Za-z_$][\w$]*)\s*=\s*["']([A-Za-z0-9_-]+/)["']"""
)

# API key / token patterns
SECRET_PATTERNS = [
    re.compile(r"""(?:api[_-]?key|apikey|api_token|access_token|secret_key|auth_token|bearer)\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]""", re.I),
    re.compile(r"""["'`]((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,})["'`]"""),  # Stripe-like
    re.compile(r"""["'`](AIza[A-Za-z0-9_-]{35})["'`]"""),  # Google API key
    re.compile(r"""["'`](ghp_[A-Za-z0-9]{36})["'`]"""),  # GitHub PAT
    re.compile(r"""["'`](AKIA[0-9A-Z]{16})["'`]"""),  # AWS key
]

# Route definition patterns (React Router, Vue Router, Angular)
ROUTE_PATTERNS = [
    re.compile(r"""path\s*:\s*["'`](/[^"'`\s]*)["'`]"""),
    re.compile(r"""<Route\s+[^>]*path\s*=\s*["'`](/[^"'`\s]*)["'`]""", re.I),
    re.compile(r"""navigate\s*\(\s*["'`](/[^"'`\s]*)["'`]""", re.I),
]


class JSParser:
    """
    Parse JavaScript source code to extract API-related information.

    Extracts:
      - API endpoints (REST, GraphQL, WebSocket)
      - Base URLs and route patterns
      - Exposed API keys/tokens
      - HTTP methods and request configurations
    """

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_urls_discovered: list[str] = []
        self.secrets_found: list[dict] = []
        self.graphql_operations: list[str] = []

    def parse(self, js_content: str, source_url: str = "") -> list[APIEndpoint]:
        """
        Parse a JavaScript file and extract all API endpoints.

        Args:
            js_content: Raw JavaScript source code
            source_url: URL where this JS file was loaded from

        Returns:
            List of discovered APIEndpoint objects
        """
        endpoints: list[APIEndpoint] = []
        seen_operations: set[tuple[str, str]] = set()

        # 1. Extract base URLs
        self._extract_base_urls(js_content)

        # 2. Extract secrets
        self._extract_secrets(js_content, source_url)

        # 3. Extract fetch/axios/XHR endpoints
        for pattern in FETCH_PATTERNS:
            for match in pattern.finditer(js_content):
                url = match.group(1)
                full_url = self._resolve(url)
                if full_url:
                    method = self._detect_method_near(js_content, match.start())
                    operation = (method, full_url)
                    if operation in seen_operations:
                        continue
                    seen_operations.add(operation)
                    endpoints.append(
                        APIEndpoint(
                            url=full_url,
                            method=method,
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.REST,
                        )
                    )

        for pattern in TEMPLATE_FETCH_PATTERNS:
            for match in pattern.finditer(js_content):
                full_url = self._resolve_template_url(match.group(1))
                if not full_url:
                    continue
                method = self._detect_method_near(
                    js_content, match.start()
                )
                operation = (method, full_url)
                if operation in seen_operations:
                    continue
                seen_operations.add(operation)
                endpoints.append(
                    APIEndpoint(
                        url=full_url,
                        method=method,
                        source=EndpointSource.STATIC_JS,
                        js_file_source=source_url,
                        endpoint_type=EndpointType.REST,
                        confidence=0.85,
                    )
                )

        # 4. Extract absolute URLs
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(js_content):
                url = match.group(1)
                operation = ("GET", url)
                if (
                    is_api_url(url)
                    and not self._url_already_seen(
                        seen_operations,
                        url,
                    )
                ):
                    seen_operations.add(operation)
                    endpoints.append(
                        APIEndpoint(
                            url=url,
                            method="GET",
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.REST,
                            confidence=0.7,
                        )
                    )

        # 5. Extract relative API paths
        for pattern in API_PATH_PATTERNS:
            for match in pattern.finditer(js_content):
                path = match.group(1)
                full_url = self._resolve(path)
                operation = ("GET", full_url or "")
                if (
                    full_url
                    and not self._url_already_seen(
                        seen_operations,
                        full_url,
                    )
                ):
                    seen_operations.add(operation)
                    endpoints.append(
                        APIEndpoint(
                            url=full_url,
                            method="GET",
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.REST,
                            confidence=0.8,
                        )
                    )

        # 5.5. Extract minified route maps such as:
        # P="serviceA/",Q="serviceB/",ROUTES={BUY_PRODUCT:"api/shop/orders"}
        for full_url, method, route_pattern in self._extract_route_constant_endpoints(
            js_content
        ):
            operation = (method, full_url)
            if full_url and operation not in seen_operations:
                seen_operations.add(operation)
                endpoints.append(
                    APIEndpoint(
                        url=full_url,
                        method=method,
                        source=EndpointSource.STATIC_JS,
                        js_file_source=source_url,
                        endpoint_type=EndpointType.REST,
                        confidence=0.85,
                        route_pattern=route_pattern,
                    )
                )

        # 6. Extract WebSocket endpoints
        for pattern in WEBSOCKET_PATTERNS:
            for match in pattern.finditer(js_content):
                ws_url = match.group(1)
                operation = ("WEBSOCKET", ws_url)
                if operation not in seen_operations:
                    seen_operations.add(operation)
                    endpoints.append(
                        APIEndpoint(
                            url=ws_url,
                            method="WEBSOCKET",
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.WEBSOCKET,
                        )
                    )

        # 7. Extract GraphQL operations
        for pattern in GRAPHQL_PATTERNS:
            for match in pattern.finditer(js_content):
                op_name = match.group(1)
                if op_name not in self.graphql_operations:
                    self.graphql_operations.append(op_name)

        # If we found GraphQL operations but no GraphQL endpoint, add default
        if self.graphql_operations:
            gql_url = self._resolve("/graphql")
            operation = ("POST", gql_url or "")
            if gql_url and operation not in seen_operations:
                endpoints.append(
                    APIEndpoint(
                        url=gql_url,
                        method="POST",
                        source=EndpointSource.STATIC_JS,
                        js_file_source=source_url,
                        endpoint_type=EndpointType.GRAPHQL,
                    )
                )

        return endpoints

    def _extract_route_constant_endpoints(
        self, js_content: str
    ) -> list[tuple[str, str, Optional[str]]]:
        """Extract endpoints from bundled route-constant objects.

        Fully generic: no variable name, service name, or method is
        hard-coded to any particular application. The resolver

        1. finds every object literal that maps constant-style keys to
           API-looking path strings (the route map),
        2. finds bare prefix constants such as ``P="serviceA/"``, and
        3. reads ``prefix+map.KEY`` concatenations from the bundle to learn
           which prefix each route belongs to.

        A route referenced by such a concatenation is emitted with its
        resolved prefix; a route that is never concatenated is emitted with
        its path as written. This reconstructs microservice-style routing
        from the bundle itself rather than from prior knowledge of the app.
        """
        route_maps = self._find_route_maps(js_content)
        if not route_maps:
            return []

        prefixes = {
            ident: value
            for ident, value in PREFIX_CONSTANT_PATTERN.findall(js_content)
        }
        # map_ident -> { KEY -> prefix_value } learned from concatenations.
        key_prefix = self._find_route_prefix_usages(
            js_content, set(route_maps), prefixes
        )

        endpoints: list[tuple[str, str, Optional[str]]] = []
        for map_ident, entries in route_maps.items():
            per_key_prefix = key_prefix.get(map_ident, {})
            for name, path in entries:
                prefix = per_key_prefix.get(name, "")
                concrete_path = self._concretize_template_path(path)
                pattern_path = re.sub(
                    r"<([A-Za-z_$][A-Za-z0-9_$]*)>",
                    r"{\1}",
                    concrete_path,
                )
                # Any remaining <placeholder> becomes a probeable "1".
                concrete_path = re.sub(
                    r"<[A-Za-z_$][A-Za-z0-9_$]*>", "1", concrete_path
                )
                full_url = urljoin(self.base_url, prefix + concrete_path)
                full_pattern = urljoin(self.base_url, prefix + pattern_path)
                endpoints.append((
                    full_url,
                    self._infer_method_from_name(name),
                    full_pattern if full_pattern != full_url else None,
                ))

        return endpoints

    @staticmethod
    def _find_route_maps(
        js_content: str,
    ) -> dict[str, list[tuple[str, str]]]:
        """Locate object literals that map constant keys to API paths.

        Returns ``{identifier: [(KEY, path), ...]}`` for every ``X={...}``
        whose body holds at least two API-looking path values.
        """
        maps: dict[str, list[tuple[str, str]]] = {}
        for obj in re.finditer(
            r"([A-Za-z_$][\w$]*)\s*=\s*\{([^{}]+)\}", js_content
        ):
            ident, body = obj.group(1), obj.group(2)
            entries = [
                (name, path)
                for name, path in re.findall(
                    r"""([A-Za-z_$][\w$]*)\s*:\s*["']([^"']+)["']""", body
                )
                if ROUTE_MAP_PATH_VALUE.match(path)
            ]
            if len(entries) >= 2:
                maps[ident] = entries
        return maps

    @staticmethod
    def _find_route_prefix_usages(
        js_content: str,
        map_idents: set[str],
        prefixes: dict[str, str],
    ) -> dict[str, dict[str, str]]:
        """Read ``prefix+map.KEY`` concatenations to bind routes to prefixes."""
        usages: dict[str, dict[str, str]] = {}
        pattern = re.compile(
            r"""([A-Za-z_$][\w$]*)\s*\+\s*([A-Za-z_$][\w$]*)"""
            r"""\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["']([^"']+)["']\s*\])"""
        )
        for pfx_ident, map_ident, dot_key, br_key in pattern.findall(
            js_content
        ):
            if map_ident not in map_idents or pfx_ident not in prefixes:
                continue
            key = dot_key or br_key
            usages.setdefault(map_ident, {})[key] = prefixes[pfx_ident]
        return usages

    @staticmethod
    def _infer_method_from_name(name: str) -> str:
        """Infer the primary HTTP method from a route constant name."""
        if name.startswith(("GET_", "DOWNLOAD_", "FETCH_", "LIST_", "VIEW_")):
            return "GET"
        if name.startswith(("CHANGE_", "UPDATE_")):
            return "PUT"
        if name.startswith(("DELETE_", "REMOVE_")):
            return "DELETE"
        return "POST"

    def _resolve(self, url: str) -> Optional[str]:
        """Resolve a URL against discovered base URLs or the target URL."""
        if "${" in url:
            return self._resolve_template_url(url)
        if url.startswith(("http://", "https://", "ws://", "wss://")):
            return url
        if url.startswith("/"):
            # Try discovered base URLs first
            for base in self.base_urls_discovered:
                return urljoin(base, url)
            return urljoin(self.base_url, url)
        return None

    def _resolve_template_url(self, url: str) -> Optional[str]:
        """Preserve JS expressions for page-context resolution later."""
        if url.startswith("//"):
            return f"{urlparse(self.base_url).scheme}:{url}"
        if url.startswith("/"):
            return urljoin(self.base_url, url)
        if url.startswith(("http://", "https://", "ws://", "wss://", "${")):
            return url
        return None

    def _concretize_template_path(self, path: str) -> str:
        """Replace route-map placeholders that have no page runtime context."""
        parsed_base = urlparse(self.base_url)
        base_host = parsed_base.netloc
        replacements = {
            "${url.host}": base_host,
            "${location.host}": base_host,
            "${window.location.host}": base_host,
            "${location.origin}": f"{parsed_base.scheme}://{base_host}",
            "${window.location.origin}": f"{parsed_base.scheme}://{base_host}",
            "${id}": "1",
        }
        for placeholder, value in replacements.items():
            path = path.replace(placeholder, value)
        return path

    def _extract_base_urls(self, js_content: str):
        """Extract base URL definitions from JS."""
        for pattern in BASE_URL_PATTERNS:
            for match in pattern.finditer(js_content):
                base = match.group(1).rstrip("/")
                if base not in self.base_urls_discovered:
                    self.base_urls_discovered.append(base)
                    logger.debug(f"    Base URL discovered: {base}")

    def _extract_secrets(self, js_content: str, source_url: str):
        """Extract exposed API keys/tokens from JS."""
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(js_content):
                secret = match.group(1)
                if self._looks_like_symbolic_constant(secret):
                    continue
                self.secrets_found.append({
                    "value": secret,
                    "source": source_url,
                    "pattern": pattern.pattern[:50],
                })
                logger.warning(f"     Exposed secret found in {source_url}: {secret[:8]}...")

    @staticmethod
    def _looks_like_symbolic_constant(value: str) -> bool:
        """Reject action names and enum constants captured as secret values."""
        return (
            "_" in value
            and bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", value))
        )

    def _detect_method_near(self, content: str, pos: int) -> str:
        """Try to detect the HTTP method used near a URL reference."""
        fetch_start = (
            pos
            if content[pos:pos + 5].lower() == "fetch"
            else content.rfind(
                "fetch",
                max(0, pos - 80),
                pos + 1,
            )
        )
        if fetch_start >= 0:
            statement_end = content.find(";", pos)
            if statement_end < 0 or statement_end > fetch_start + 1000:
                statement_end = min(len(content), fetch_start + 1000)
            else:
                statement_end += 1
            fetch_context = content[fetch_start:statement_end]
            method_match = re.search(
                r"""\bmethod\s*:\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]""",
                fetch_context,
                re.IGNORECASE,
            )
            if method_match:
                return method_match.group(1).upper()
            return "GET"

        # Look around the URL for axios, XHR, and request configuration.
        start = max(0, pos - 200)
        context = content[start:pos + 300]

        for pattern in METHOD_PATTERNS:
            m = pattern.search(context)
            if m:
                return m.group(1).upper()

        # Default heuristic: if the context has "body" or "data", likely POST
        if re.search(r"\bbody\b|\bdata\b|\bpayload\b", context, re.I):
            return "POST"

        return "GET"

    @staticmethod
    def _url_already_seen(
        operations: set[tuple[str, str]],
        url: str,
    ) -> bool:
        return any(
            existing_url == url
            for _, existing_url in operations
        )
