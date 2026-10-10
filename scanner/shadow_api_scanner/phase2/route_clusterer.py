"""Collapse concrete API observations into conservative logical route groups."""

from __future__ import annotations

import re
from dataclasses import replace
from urllib.parse import parse_qsl, urlparse, urlunparse

from shadow_api_scanner.core.models import (
    APIEndpoint,
    DocumentationStatus,
    EndpointSource,
)


PLACEHOLDER_SEGMENT = re.compile(
    r"^(?:\{[^/{}]+\}|:[A-Za-z_$][\w$]*)$"
)
INTEGER_SEGMENT = re.compile(r"^-?\d+$")
UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
OPAQUE_SEGMENT = re.compile(r"^(?:[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,})$")
NULLISH_SEGMENT = re.compile(
    r"^(?:null|undefined|none|nan)$",
    re.IGNORECASE,
)
STATIC_ACTION_SEGMENTS = {
    "add",
    "all",
    "auth",
    "callback",
    "change",
    "check",
    "create",
    "delete",
    "download",
    "edit",
    "flag",
    "get",
    "health",
    "list",
    "login",
    "logout",
    "new",
    "profile",
    "recent",
    "register",
    "remove",
    "reset",
    "return",
    "scores",
    "search",
    "signup",
    "status",
    "submit",
    "unlock",
    "update",
    "upload",
    "validate",
    "verify",
}


class RouteClusterer:
    """Group repeated concrete URLs while retaining a testable representative."""

    def cluster(self, endpoints: list[APIEndpoint]) -> list[APIEndpoint]:
        if not endpoints:
            return []

        endpoints = self._infer_literal_route_patterns(endpoints)
        endpoints = self._propagate_known_route_patterns(endpoints)
        groups: dict[tuple, list[APIEndpoint]] = {}
        for endpoint in endpoints:
            groups.setdefault(self._fingerprint(endpoint), []).append(endpoint)

        clustered: list[APIEndpoint] = []
        for group in groups.values():
            clustered.append(self._collapse_group(group))
        return clustered

    def _infer_literal_route_patterns(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[APIEndpoint]:
        """Infer one identifier segment from repeated runtime observations."""
        candidates: dict[tuple, list[int]] = {}
        runtime_sources = {
            EndpointSource.DYNAMIC_TRAFFIC,
            EndpointSource.TRAFFIC_IMPORT,
            EndpointSource.PATH_EXPLORATION,
        }

        for index, endpoint in enumerate(endpoints):
            if (
                endpoint.route_pattern
                or endpoint.source not in runtime_sources
                or self._contains_placeholder(endpoint.url)
            ):
                continue
            parsed = urlparse(endpoint.url)
            segments = self._segments(parsed.path)
            if len(segments) < 2:
                continue
            key = (
                endpoint.method.upper(),
                endpoint.endpoint_type.value,
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                len(segments),
                endpoint.documentation_status.value,
                endpoint.is_shadow,
                endpoint.owner,
                endpoint.lifecycle,
            )
            candidates.setdefault(key, []).append(index)

        updated = list(endpoints)
        for indexes in candidates.values():
            if len(indexes) < 3:
                continue
            segment_rows = [
                self._segments(urlparse(endpoints[index].url).path)
                for index in indexes
            ]
            varying_positions = [
                position
                for position in range(len(segment_rows[0]))
                if len({
                    row[position]
                    for row in segment_rows
                }) > 1
            ]
            if len(varying_positions) != 1:
                continue

            position = varying_positions[0]
            values = {
                row[position]
                for row in segment_rows
            }
            if not self._identifier_values(values):
                continue

            pattern_segments = list(segment_rows[0])
            pattern_segments[position] = self._inferred_placeholder(
                pattern_segments,
                position,
            )
            first_parsed = urlparse(endpoints[indexes[0]].url)
            route_pattern = urlunparse((
                first_parsed.scheme,
                first_parsed.netloc,
                "/" + "/".join(pattern_segments),
                "",
                "",
                "",
            ))
            for index in indexes:
                updated[index] = replace(
                    endpoints[index],
                    route_pattern=route_pattern,
                )

        return updated

    def _propagate_known_route_patterns(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[APIEndpoint]:
        """Reuse an observed route family for other methods on that family."""
        patterns: dict[tuple, list[str]] = {}
        route_family_patterns: dict[tuple, list[str]] = {}
        for endpoint in endpoints:
            known_pattern = endpoint.route_pattern or (
                endpoint.url
                if self._contains_placeholder(endpoint.url)
                else None
            )
            if not known_pattern:
                continue
            parsed = urlparse(known_pattern)
            key = (
                endpoint.endpoint_type.value,
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                endpoint.documentation_status.value,
                endpoint.is_shadow,
            )
            patterns.setdefault(key, []).append(known_pattern)
            family_key = (
                endpoint.endpoint_type.value,
                parsed.scheme.lower(),
                parsed.netloc.lower(),
            )
            route_family_patterns.setdefault(
                family_key,
                [],
            ).append(known_pattern)

        updated = list(endpoints)
        for index, endpoint in enumerate(endpoints):
            if endpoint.route_pattern or self._contains_placeholder(endpoint.url):
                continue
            parsed = urlparse(endpoint.url)
            key = (
                endpoint.endpoint_type.value,
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                endpoint.documentation_status.value,
                endpoint.is_shadow,
            )
            matches = [
                pattern
                for pattern in patterns.get(key, [])
                if self._route_pattern_matches(pattern, endpoint.url)
            ]
            if (
                not matches
                and endpoint.is_shadow
                and "allowed" in endpoint.operation_evidence
            ):
                family_key = (
                    endpoint.endpoint_type.value,
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                )
                matches = [
                    pattern
                    for pattern in route_family_patterns.get(family_key, [])
                    if self._route_pattern_matches(
                        pattern,
                        endpoint.url,
                        allow_action_values=True,
                    )
                ]
            if matches:
                updated[index] = replace(
                    endpoint,
                    route_pattern=max(matches, key=self._pattern_specificity),
                )

        return updated

    def _route_pattern_matches(
        self,
        pattern: str,
        concrete_url: str,
        allow_action_values: bool = False,
    ) -> bool:
        pattern_segments = self._segments(urlparse(pattern).path)
        concrete_segments = self._segments(urlparse(concrete_url).path)
        if len(pattern_segments) != len(concrete_segments):
            return False

        for expected, actual in zip(pattern_segments, concrete_segments):
            if PLACEHOLDER_SEGMENT.fullmatch(expected):
                if (
                    not actual
                    or (
                        not allow_action_values
                        and (
                            actual.lower() in STATIC_ACTION_SEGMENTS
                            or actual.startswith(("_", "."))
                        )
                    )
                ):
                    return False
                continue
            if expected != actual:
                return False
        return True

    def _pattern_specificity(self, pattern: str) -> tuple[int, int]:
        segments = self._segments(urlparse(pattern).path)
        static_segments = sum(
            1
            for segment in segments
            if not PLACEHOLDER_SEGMENT.fullmatch(segment)
        )
        return static_segments, len(segments)

    @staticmethod
    def _identifier_values(values: set[str]) -> bool:
        if len(values) < 3:
            return False
        for value in values:
            lowered = value.lower()
            if (
                lowered in STATIC_ACTION_SEGMENTS
                or not re.fullmatch(r"[A-Za-z0-9_.@-]+", value)
            ):
                return False
        return True

    def _inferred_placeholder(
        self,
        segments: list[str],
        position: int,
    ) -> str:
        resource = self._singular(
            segments[position - 1] if position else "id"
        )
        if resource == "user":
            return "{username}"
        if resource == "email":
            return "{email}"
        return "{" + (
            "id" if resource == "id" else f"{resource}Id"
        ) + "}"

    def _collapse_group(self, group: list[APIEndpoint]) -> APIEndpoint:
        representative = max(group, key=self._representative_score)
        documentation_endpoint = max(
            group,
            key=lambda endpoint: {
                DocumentationStatus.UNKNOWN: 0,
                DocumentationStatus.SHADOW: 1,
                DocumentationStatus.DOCUMENTED: 2,
            }[endpoint.documentation_status],
        )
        observed_urls = self._observed_urls(group)
        observed_sources = list(dict.fromkeys(
            source
            for endpoint in group
            for source in (
                endpoint.observed_sources
                or [endpoint.source.value]
            )
        ))
        route_pattern = self._route_pattern(group, representative)

        if (
            len(group) == 1
            and not representative.route_pattern
            and not self._contains_placeholder(representative.url)
            and not urlparse(representative.url).query
        ):
            route_pattern = None

        return replace(
            representative,
            route_pattern=route_pattern,
            documentation_status=(
                documentation_endpoint.documentation_status
            ),
            is_shadow=(
                documentation_endpoint.documentation_status
                == DocumentationStatus.SHADOW
            ),
            documentation_reason=(
                documentation_endpoint.documentation_reason
            ),
            observed_urls=observed_urls,
            observed_sources=observed_sources,
            operation_evidence=list(dict.fromkeys(
                evidence
                for endpoint in group
                for evidence in endpoint.operation_evidence
            )),
            parameter_evidence=self._merge_parameter_evidence(group),
            confidence=max(endpoint.confidence for endpoint in group),
            owner=representative.owner or self._first_value(group, "owner"),
            lifecycle=(
                representative.lifecycle
                or self._first_value(group, "lifecycle")
            ),
            inventory_source=(
                representative.inventory_source
                or self._first_value(group, "inventory_source")
            ),
        )

    @staticmethod
    def _merge_parameter_evidence(
        endpoints: list[APIEndpoint],
    ) -> dict[str, list[str]]:
        merged: dict[str, list[str]] = {}
        for endpoint in endpoints:
            for source, names in endpoint.parameter_evidence.items():
                merged[source] = list(dict.fromkeys(
                    merged.get(source, []) + list(names)
                ))
        return merged

    def _fingerprint(self, endpoint: APIEndpoint) -> tuple:
        parsed = urlparse(endpoint.route_pattern or endpoint.url)
        path_signature = tuple(
            self._segment_signature(segment)
            for segment in self._segments(parsed.path)
        )
        return (
            endpoint.method.upper(),
            endpoint.endpoint_type.value,
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path_signature,
            endpoint.owner,
            endpoint.lifecycle,
        )

    def _route_pattern(
        self,
        group: list[APIEndpoint],
        representative: APIEndpoint,
    ) -> str | None:
        existing = next(
            (
                endpoint.route_pattern or endpoint.url
                for endpoint in group
                if (
                    endpoint.route_pattern
                    or self._contains_placeholder(endpoint.url)
                )
            ),
            None,
        )
        source_url = existing or representative.url
        parsed = urlparse(source_url)
        path_segments = self._segments(parsed.path)

        concrete_paths = [
            self._segments(urlparse(url).path)
            for url in self._observed_urls(group)
        ]
        if not concrete_paths:
            concrete_paths = [path_segments]

        changed = bool(existing) or bool(parsed.query)
        used_names: set[str] = set()
        for index, segment in enumerate(path_segments):
            values = {
                segments[index]
                for segments in concrete_paths
                if len(segments) == len(path_segments)
            }
            if (
                self._is_dynamic_segment(segment)
                and (
                    len(values) > 1
                    or PLACEHOLDER_SEGMENT.fullmatch(segment)
                )
            ):
                path_segments[index] = self._placeholder_name(
                    path_segments, index, used_names
                )
                changed = True

        if not changed:
            return None

        path = "/" + "/".join(path_segments)
        if parsed.path.endswith("/") and path != "/":
            path += "/"
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            "",
            "",
        ))

    @staticmethod
    def _representative_score(endpoint: APIEndpoint) -> tuple:
        source_priority = {
            EndpointSource.DYNAMIC_TRAFFIC: 5,
            EndpointSource.TRAFFIC_IMPORT: 4,
            EndpointSource.PATH_EXPLORATION: 3,
            EndpointSource.STATIC_JS: 2,
            EndpointSource.API_INVENTORY: 2,
            EndpointSource.OPENAPI_SPEC: 1,
            EndpointSource.SECURITY_VALIDATION: 1,
            EndpointSource.MANUAL: 0,
        }
        return (
            not RouteClusterer._contains_nullish(endpoint.url),
            endpoint.status_code is not None,
            bool(endpoint.response_body),
            source_priority.get(endpoint.source, 0),
            endpoint.confidence,
        )

    def _observed_urls(self, group: list[APIEndpoint]) -> list[str]:
        urls: list[str] = []
        for endpoint in group:
            candidates = endpoint.observed_urls or [endpoint.url]
            for candidate in candidates:
                if self._contains_placeholder(candidate):
                    continue
                if candidate not in urls:
                    urls.append(candidate)
        if not urls:
            urls.append(group[0].url)
        return urls

    @staticmethod
    def _segments(path: str) -> list[str]:
        return [segment for segment in path.strip("/").split("/") if segment]

    @staticmethod
    def _segment_signature(segment: str) -> str:
        return "*" if RouteClusterer._is_dynamic_segment(segment) else segment.lower()

    @staticmethod
    def _is_dynamic_segment(segment: str) -> bool:
        return bool(
            PLACEHOLDER_SEGMENT.fullmatch(segment)
            or INTEGER_SEGMENT.fullmatch(segment)
            or UUID_SEGMENT.fullmatch(segment)
            or OPAQUE_SEGMENT.fullmatch(segment)
            or NULLISH_SEGMENT.fullmatch(segment)
        )

    @staticmethod
    def _contains_placeholder(url: str) -> bool:
        parsed = urlparse(url)
        return any(
            PLACEHOLDER_SEGMENT.fullmatch(segment)
            for segment in RouteClusterer._segments(parsed.path)
        ) or any(
            PLACEHOLDER_SEGMENT.fullmatch(value)
            for _, value in parse_qsl(
                parsed.query, keep_blank_values=True
            )
        )

    @staticmethod
    def _contains_nullish(url: str) -> bool:
        return any(
            NULLISH_SEGMENT.fullmatch(segment)
            for segment in RouteClusterer._segments(urlparse(url).path)
        )

    def _placeholder_name(
        self,
        segments: list[str],
        index: int,
        used_names: set[str],
    ) -> str:
        segment = segments[index]
        if PLACEHOLDER_SEGMENT.fullmatch(segment):
            raw_name = segment.strip("{}:")
            return "{" + self._safe_parameter_name(raw_name, used_names) + "}"

        resource = segments[index - 1] if index else "id"
        resource = self._singular(resource)
        raw_name = "id" if resource == "id" else f"{resource}Id"
        return "{" + self._safe_parameter_name(raw_name, used_names) + "}"

    @staticmethod
    def _safe_parameter_name(name: str, used_names: set[str]) -> str:
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
            candidate = name[:1].lower() + name[1:]
        else:
            parts = [
                part for part in re.split(r"[^A-Za-z0-9]+", name) if part
            ]
            candidate = parts[0].lower() + "".join(
                part[:1].upper() + part[1:] for part in parts[1:]
            ) if parts else "id"
        if not candidate:
            candidate = "id"
        if candidate[:1].isdigit():
            candidate = "id"

        base = candidate
        suffix = 2
        while candidate in used_names:
            candidate = f"{base}{suffix}"
            suffix += 1
        used_names.add(candidate)
        return candidate

    @staticmethod
    def _singular(resource: str) -> str:
        clean = re.sub(r"[^A-Za-z0-9]+", " ", resource).strip()
        if not clean:
            return "id"
        words = clean.split()
        value = words[0].lower() + "".join(
            word[:1].upper() + word[1:] for word in words[1:]
        )
        if value.endswith("ies") and len(value) > 3:
            return value[:-3] + "y"
        if value.endswith("sses"):
            return value[:-2]
        if value.endswith("s") and not value.endswith("ss"):
            return value[:-1]
        return value

    @staticmethod
    def _first_value(
        endpoints: list[APIEndpoint],
        attribute: str,
    ):
        return next(
            (
                getattr(endpoint, attribute)
                for endpoint in endpoints
                if getattr(endpoint, attribute)
            ),
            None,
        )
