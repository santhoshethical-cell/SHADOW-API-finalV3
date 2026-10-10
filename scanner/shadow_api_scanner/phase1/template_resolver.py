"""Resolve JavaScript URL templates using values observed in page HTML."""

from __future__ import annotations

import itertools
import re
import uuid
from dataclasses import replace
from urllib.parse import parse_qs, quote, urljoin, urlparse

from bs4 import BeautifulSoup

from shadow_api_scanner.core.models import APIEndpoint


TEMPLATE_EXPRESSION = re.compile(r"\$\{([^{}]+)\}")
IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")
ENCODE_CALL = re.compile(
    r"^(encodeURIComponent|encodeURI)\(\s*([A-Za-z_$][\w$]*)\s*\)$"
)

HOST_EXPRESSIONS = {
    "url.host",
    "location.host",
    "window.location.host",
    "document.location.host",
}
ORIGIN_EXPRESSIONS = {
    "url.origin",
    "location.origin",
    "window.location.origin",
    "document.location.origin",
}


def contains_template_expression(url: str) -> bool:
    """Return whether a URL still contains an unresolved JS template."""
    return bool(TEMPLATE_EXPRESSION.search(url))


class TemplateEndpointResolver:
    """Expand endpoint templates from links, forms, and page URL context."""

    def __init__(self, base_url: str, max_expansions: int = 25):
        self.base_url = base_url
        self.max_expansions = max(1, max_expansions)
        self.resolved_count = 0
        self.unresolved_count = 0

    def resolve(
        self,
        endpoints: list[APIEndpoint],
        html: str,
    ) -> list[APIEndpoint]:
        """Replace resolvable templates with concrete endpoint copies."""
        context_values = self.extract_context_values(html)
        resolved: list[APIEndpoint] = []

        for endpoint in endpoints:
            if not contains_template_expression(endpoint.url):
                resolved.append(endpoint)
                continue

            expansions = self.expand_endpoint(endpoint, context_values)
            if expansions:
                self.resolved_count += len(expansions)
                resolved.extend(expansions)
            else:
                endpoint.confidence = min(endpoint.confidence, 0.35)
                resolved.append(endpoint)
                self.unresolved_count += 1

        return resolved

    def extract_context_values(self, html: str) -> dict[str, list[str]]:
        """Collect variable values from same-origin links and form controls."""
        values: dict[str, list[str]] = {}
        if not html:
            return values

        soup = BeautifulSoup(html, "lxml")
        page_origin = self._origin(self.base_url)

        for tag in soup.find_all(href=True):
            self._collect_url_values(
                urljoin(self.base_url, tag.get("href", "")),
                page_origin,
                values,
            )

        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                self._collect_url_values(
                    urljoin(self.base_url, action),
                    page_origin,
                    values,
                )

            for control in form.find_all(["input", "textarea", "select"]):
                name = control.get("name")
                if not name:
                    continue
                if control.name == "select":
                    for option in control.find_all("option"):
                        self._add_value(values, name, option.get("value", option.text))
                else:
                    self._add_value(values, name, control.get("value", ""))

        return values

    def expand_endpoint(
        self,
        endpoint: APIEndpoint,
        context_values: dict[str, list[str]],
    ) -> list[APIEndpoint]:
        expressions = list(dict.fromkeys(TEMPLATE_EXPRESSION.findall(endpoint.url)))
        if not expressions:
            return [endpoint]

        options: list[list[str]] = []
        for expression in expressions:
            expression_values = self._resolve_expression(expression, context_values)
            if not expression_values:
                return []
            options.append(expression_values)

        expanded: list[APIEndpoint] = []
        for combination in itertools.islice(
            itertools.product(*options), self.max_expansions
        ):
            concrete_url = endpoint.url
            for expression, value in zip(expressions, combination):
                concrete_url = concrete_url.replace(f"${{{expression}}}", value)
            if contains_template_expression(concrete_url):
                continue
            expanded.append(replace(
                endpoint,
                url=concrete_url,
                id=str(uuid.uuid4())[:8],
                confidence=max(endpoint.confidence, 0.9),
            ))
        return expanded

    def _resolve_expression(
        self,
        expression: str,
        context_values: dict[str, list[str]],
    ) -> list[str]:
        expression = expression.strip()
        parsed_base = urlparse(self.base_url)

        if expression in HOST_EXPRESSIONS:
            return [parsed_base.netloc]
        if expression in ORIGIN_EXPRESSIONS:
            return [f"{parsed_base.scheme}://{parsed_base.netloc}"]

        encode_match = ENCODE_CALL.fullmatch(expression)
        if encode_match:
            function_name, variable_name = encode_match.groups()
            safe = "" if function_name == "encodeURIComponent" else "/:?&=#"
            return [
                quote(value, safe=safe)
                for value in self._lookup_values(context_values, variable_name)
            ]

        if IDENTIFIER.fullmatch(expression):
            return self._lookup_values(context_values, expression)
        return []

    def _collect_url_values(
        self,
        url: str,
        expected_origin: str,
        values: dict[str, list[str]],
    ) -> None:
        if self._origin(url) != expected_origin:
            return
        for name, candidates in parse_qs(
            urlparse(url).query, keep_blank_values=True
        ).items():
            for candidate in candidates:
                self._add_value(values, name, candidate)

    def _add_value(
        self,
        values: dict[str, list[str]],
        name: str,
        value: object,
    ) -> None:
        text = str(value).strip()
        if not text:
            return
        bucket = values.setdefault(name, [])
        if text not in bucket and len(bucket) < self.max_expansions:
            bucket.append(text)

    def _lookup_values(
        self,
        values: dict[str, list[str]],
        name: str,
    ) -> list[str]:
        if name in values:
            return values[name]
        lowered_name = name.lower()
        for key, candidates in values.items():
            if key.lower() == lowered_name:
                return candidates
        return []

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
