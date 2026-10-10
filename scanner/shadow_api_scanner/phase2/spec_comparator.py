"""
Phase 2: OpenAPI/Swagger Specification Comparator

Downloads and parses OpenAPI/Swagger specs (if available) to
determine which endpoints are documented vs. shadow.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, EndpointSource

logger = logging.getLogger("shadow_api_scanner")

# Common paths where OpenAPI specs are published
COMMON_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api-docs/",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api",                       # Common root for interactive docs
    "/api/",
    "/api/docs",
    "/api/schema",
    "/api/spec",
    "/.well-known/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v1/docs",
    "/api/v2/docs",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/",
    "/Swagger/",
    "/swagger-resources",
    "/docs",
    "/redoc",
]


class SpecComparator:
    """
    Discover and parse OpenAPI/Swagger specs to build a documented API inventory.

    Compares endpoints against the spec for Shadow / Unmanaged classification.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.spec_data: Optional[dict] = None
        self.documented_paths: set[str] = set()
        self.documented_route_urls: dict[str, str] = {}
        self.spec_source_url: Optional[str] = None

    async def discover_and_parse(self) -> list[APIEndpoint]:
        """
        Attempt to find and parse an OpenAPI specification.

        Returns:
            List of documented APIEndpoint objects.
        """
        logger.info("  Searching for OpenAPI/Swagger specification...")

        spec_content = None

        # Try user-provided spec first
        if self.config.openapi_spec_file:
            try:
                spec_content = Path(self.config.openapi_spec_file).read_text(
                    encoding="utf-8-sig"
                )
                logger.info(f"  Loaded spec from file: {self.config.openapi_spec_file}")
            except Exception as e:
                logger.warning(f"  Failed to load spec file: {e}")

        if not spec_content and self.config.openapi_spec_url:
            spec_content = await self._fetch_spec(self.config.openapi_spec_url)
            if spec_content:
                self.spec_source_url = self.config.openapi_spec_url

        # Auto-discover spec
        if not spec_content:
            semaphore = asyncio.Semaphore(self.config.max_discovery_concurrency)
            async with httpx.AsyncClient(
                timeout=10,
                follow_redirects=True,
                max_redirects=self.config.max_redirects,
                verify=self.config.verify_tls,
                headers=self.config.get_headers(),
            ) as client:
                async def fetch_candidate(path: str) -> tuple[str, Optional[str]]:
                    url = urljoin(self.config.target_url, path)
                    try:
                        async with semaphore:
                            resp = await client.get(url)
                        if resp.status_code == 200:
                            return url, resp.text
                    except Exception:
                        pass
                    return url, None

                candidates = await asyncio.gather(*[
                    fetch_candidate(path) for path in COMMON_SPEC_PATHS
                ])
                for url, candidate_content in candidates:
                    if (
                        candidate_content
                        and self._looks_like_spec(candidate_content)
                    ):
                        spec_content = candidate_content
                        self.spec_source_url = url
                        logger.info(f"  Found OpenAPI spec at: {url}")
                        break

                if not spec_content:
                    for url, candidate_content in candidates:
                        if not candidate_content:
                            continue
                        discovered = await self._discover_swagger_ui_spec(
                            client,
                            url,
                            candidate_content,
                        )
                        if discovered:
                            self.spec_source_url, spec_content = discovered
                            logger.info(
                                "  Found OpenAPI spec through Swagger UI: "
                                f"{self.spec_source_url}"
                            )
                            break

        if not spec_content:
            logger.info("  No OpenAPI specification found.")
            return []

        # Parse the spec
        return self._parse_spec(spec_content)

    async def _fetch_spec(self, url: str) -> Optional[str]:
        """Fetch spec from URL."""
        try:
            async with httpx.AsyncClient(
                timeout=15,
                follow_redirects=True,
                max_redirects=self.config.max_redirects,
                verify=self.config.verify_tls,
                headers=self.config.get_headers(),
            ) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text
        except Exception as e:
            logger.warning(f"  Failed to fetch spec from {url}: {e}")
        return None

    async def _discover_swagger_ui_spec(
        self,
        client: httpx.AsyncClient,
        page_url: str,
        content: str,
    ) -> Optional[tuple[str, str]]:
        """Extract inline or referenced specs from Swagger UI bootstrap code."""
        if not self._looks_like_swagger_ui(content):
            return None

        direct = await self._spec_from_swagger_bootstrap(
            client,
            page_url,
            content,
        )
        if direct:
            return direct

        for script_source in self._swagger_script_sources(content):
            script_url = urljoin(page_url, script_source)
            if not self._same_origin(page_url, script_url):
                continue
            try:
                response = await client.get(script_url)
            except Exception:
                continue
            if response.status_code != 200:
                continue

            discovered = await self._spec_from_swagger_bootstrap(
                client,
                script_url,
                response.text,
            )
            if discovered:
                return discovered

        return None

    async def _spec_from_swagger_bootstrap(
        self,
        client: httpx.AsyncClient,
        source_url: str,
        content: str,
    ) -> Optional[tuple[str, str]]:
        embedded = self._extract_embedded_spec(content)
        if embedded:
            return source_url, embedded

        for reference in self._extract_spec_references(content):
            spec_url = urljoin(source_url, reference)
            if not self._same_origin(source_url, spec_url):
                continue
            try:
                response = await client.get(spec_url)
            except Exception:
                continue
            if (
                response.status_code == 200
                and self._looks_like_spec(response.text)
            ):
                return spec_url, response.text

        return None

    @staticmethod
    def _looks_like_swagger_ui(content: str) -> bool:
        lowered = content[:100000].lower()
        return any(marker in lowered for marker in (
            "swagger-ui",
            "swaggeruibundle",
            "swaggerdoc",
        ))

    @staticmethod
    def _swagger_script_sources(content: str) -> list[str]:
        sources = re.findall(
            r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]",
            content,
            re.IGNORECASE,
        )
        return list(dict.fromkeys(
            source
            for source in sources
            if any(marker in source.lower() for marker in (
                "swagger",
                "openapi",
                "api-doc",
            ))
        ))

    def _extract_embedded_spec(self, content: str) -> Optional[str]:
        decoder = json.JSONDecoder()
        property_pattern = re.compile(
            r"(?:[\"'](?:swaggerDoc|spec)[\"']|\b(?:swaggerDoc|spec))"
            r"\s*:\s*",
        )
        for match in property_pattern.finditer(content):
            candidate = content[match.end():].lstrip()
            if not candidate.startswith("{"):
                continue
            try:
                document, _ = decoder.raw_decode(candidate)
            except json.JSONDecodeError:
                continue
            if self._is_spec_document(document):
                return json.dumps(document)
        return None

    @staticmethod
    def _extract_spec_references(content: str) -> list[str]:
        references = re.findall(
            r"(?:[\"']url[\"']|\burl)\s*:\s*[\"']([^\"']+)[\"']",
            content,
        )
        return list(dict.fromkeys(
            reference
            for reference in references
            if reference and not reference.lower().startswith(
                ("data:", "javascript:")
            )
        ))

    @staticmethod
    def _same_origin(first_url: str, second_url: str) -> bool:
        first = urlparse(first_url)
        second = urlparse(second_url)
        return (
            first.scheme.lower(),
            first.netloc.lower(),
        ) == (
            second.scheme.lower(),
            second.netloc.lower(),
        )

    def _looks_like_spec(self, content: str) -> bool:
        """Return True only for structurally valid OpenAPI/Swagger content."""
        return self._decode_spec(content) is not None

    def _decode_spec(self, content: str) -> Optional[dict]:
        try:
            spec = json.loads(content.lstrip("\ufeff"))
        except json.JSONDecodeError:
            try:
                import yaml  # type: ignore
                spec = yaml.safe_load(content)
            except Exception:
                return None

        return spec if self._is_spec_document(spec) else None

    @staticmethod
    def _is_spec_document(value: object) -> bool:
        return (
            isinstance(value, dict)
            and isinstance(value.get("paths"), dict)
            and bool(value.get("openapi") or value.get("swagger"))
        )

    def _parse_spec(self, content: str) -> list[APIEndpoint]:
        """Parse OpenAPI JSON spec into endpoint list."""
        spec = self._decode_spec(content)
        if spec is None:
            logger.warning("  Failed to parse specification content")
            return []

        self.spec_data = spec
        endpoints = []

        # Determine base URL from spec
        base_url = self.config.target_url
        if "servers" in spec:
            servers = spec["servers"]
            if servers and "url" in servers[0]:
                server_url = servers[0]["url"]
                if server_url.startswith("http"):
                    base_url = self._server_url_for_target(server_url)
                elif self.spec_source_url:
                    base_url = urljoin(self.spec_source_url, server_url)
                elif server_url.startswith("/"):
                    base_url = urljoin(self.config.target_url, server_url)

        # Extract paths
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                    full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                    resolved_path = urlparse(full_url).path
                    route_key = f"{method.upper()}:{resolved_path}"
                    self.documented_paths.add(route_key)
                    self.documented_route_urls[route_key] = full_url
                    endpoints.append(
                        APIEndpoint(
                            url=full_url,
                            method=method.upper(),
                            source=EndpointSource.OPENAPI_SPEC,
                            parameter_evidence=self._parameter_evidence(
                                methods,
                                details,
                            ),
                        )
                    )

        logger.info(f"  Parsed {len(endpoints)} documented endpoints from spec")
        return endpoints

    @staticmethod
    def _parameter_evidence(
        path_item: dict,
        operation: object,
    ) -> dict[str, list[str]]:
        """Extract documented parameter names without retaining examples."""
        details = operation if isinstance(operation, dict) else {}
        evidence: dict[str, list[str]] = {"openapi_operation": ["present"]}
        parameters = []
        for candidate in (
            path_item.get("parameters", []),
            details.get("parameters", []),
        ):
            if isinstance(candidate, list):
                parameters.extend(candidate)
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = str(parameter.get("name", "")).strip()
            location = str(parameter.get("in", "")).lower()
            if name and location in {"path", "query", "header", "cookie"}:
                key = f"openapi_{location}"
                evidence.setdefault(key, []).append(name)

        request_body = details.get("requestBody", {})
        if isinstance(request_body, dict):
            content = request_body.get("content", {})
            if isinstance(content, dict):
                for media in content.values():
                    if not isinstance(media, dict):
                        continue
                    schema = media.get("schema", {})
                    if not isinstance(schema, dict):
                        continue
                    properties = schema.get("properties", {})
                    if isinstance(properties, dict):
                        evidence.setdefault("openapi_body", []).extend(
                            str(name) for name in properties
                        )
        return {
            source: list(dict.fromkeys(names))
            for source, names in evidence.items()
        }

    def _server_url_for_target(self, server_url: str) -> str:
        """Apply the documented server path to the deployment being scanned."""
        server = urlparse(server_url)
        target = urlparse(self.config.target_url)
        if (
            server.scheme.lower(),
            server.netloc.lower(),
        ) == (
            target.scheme.lower(),
            target.netloc.lower(),
        ):
            return server_url

        return urlunparse((
            target.scheme,
            target.netloc,
            server.path or "/",
            server.params,
            server.query,
            "",
        ))

    def is_documentation_endpoint(self, endpoint: APIEndpoint) -> bool:
        """Check if an endpoint is the docs/spec root rather than app API."""
        parsed = urlparse(endpoint.url)
        path = parsed.path.rstrip("/").lower() or "/"
        docs_paths = {
            "/api",
            "/api/docs",
            "/api/openapi.json",
            "/api/swagger.json",
            "/openapi.json",
            "/swagger.json",
            "/docs",
            "/redoc",
            "/swagger",
            "/swagger-ui.html",
            "/swagger-ui",
        }
        if path in docs_paths:
            return True

        body = (endpoint.response_body or "")[:5000].lower()
        content_type = endpoint.response_headers.get(
            "content-type",
            endpoint.response_headers.get("Content-Type", ""),
        ).lower()
        return (
            "json" in content_type
            and "openapi" in body
            and "paths" in body
        )

    def is_documented(self, endpoint: APIEndpoint) -> bool:
        """Check if an endpoint exists in the documented spec."""
        return self.matching_route_pattern(endpoint) is not None

    def matching_route_pattern(
        self,
        endpoint: APIEndpoint,
    ) -> Optional[str]:
        """Return the most specific documented route matching an operation."""
        if not self.documented_paths:
            return None

        path = urlparse(endpoint.url).path
        method = endpoint.method.upper()

        key = f"{method}:{path}"
        if key in self.documented_paths:
            return self.documented_route_urls.get(key, endpoint.url)

        normalized_path = path.rstrip("/") or "/"
        exact_candidates = [
            doc_key
            for doc_key in self.documented_paths
            if (
                doc_key.split(":", 1)[0] == method
                and (doc_key.split(":", 1)[1].rstrip("/") or "/")
                == normalized_path
            )
        ]
        if exact_candidates:
            exact_key = exact_candidates[0]
            return self.documented_route_urls.get(exact_key)

        parameterized_matches = []
        for doc_key in self.documented_paths:
            doc_method, doc_path = doc_key.split(":", 1)
            if doc_method != method:
                continue
            if (
                self._paths_match(doc_path, path)
                and not self._reserved_literal_parameter_match(
                    doc_path,
                    path,
                )
            ):
                parameterized_matches.append((doc_key, doc_path))

        if not parameterized_matches:
            return None

        best_key, _ = max(
            parameterized_matches,
            key=lambda item: self._route_specificity(item[1]),
        )
        return self.documented_route_urls.get(best_key)

    @staticmethod
    def _reserved_literal_parameter_match(
        pattern: str,
        actual: str,
    ) -> bool:
        """Keep reserved literal routes distinct from parameterized families."""
        pattern_segments = [
            segment for segment in pattern.strip("/").split("/") if segment
        ]
        actual_segments = [
            segment for segment in actual.strip("/").split("/") if segment
        ]
        if len(pattern_segments) != len(actual_segments):
            return False

        return any(
            expected.startswith("{")
            and expected.endswith("}")
            and value.startswith(("_", "."))
            for expected, value in zip(pattern_segments, actual_segments)
        )

    @staticmethod
    def _route_specificity(path: str) -> tuple[int, int]:
        """Prefer routes with more literal segments and greater depth."""
        segments = [
            segment for segment in path.strip("/").split("/") if segment
        ]
        literal_count = sum(
            1 for segment in segments
            if not (segment.startswith("{") and segment.endswith("}"))
        )
        return literal_count, len(segments)

    def is_documented_path_family(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint is a parent of a documented parameterized path."""
        if not self.documented_paths:
            return False

        path = urlparse(endpoint.url).path.rstrip("/")
        if not path:
            return False

        for doc_key in self.documented_paths:
            doc_method, doc_path = doc_key.split(":", 1)
            if doc_method != endpoint.method:
                continue

            doc_path = doc_path.rstrip("/")
            if not doc_path.startswith(path + "/"):
                continue

            remainder = doc_path[len(path):].strip("/")
            if "/" not in remainder and remainder.startswith("{"):
                return True

        return False

    def _paths_match(self, pattern: str, actual: str) -> bool:
        """Check if a parameterized path pattern matches an actual path."""
        import re
        # Convert {param} to regex
        regex_pattern = re.sub(r"\{[^}]+\}", r"[^/]+", pattern)
        regex_pattern = "^" + regex_pattern.rstrip("/") + "/?$"
        return bool(re.match(regex_pattern, actual))
