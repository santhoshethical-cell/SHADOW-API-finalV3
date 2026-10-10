"""
Authoritative API inventory support.

Loads approved API routes from JSON, YAML, or CSV files so Shadow / Unmanaged
classification is not limited to OpenAPI/Swagger availability.
"""

from __future__ import annotations

import csv
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, EndpointSource

logger = logging.getLogger("shadow_api_scanner")


@dataclass
class InventoryEntry:
    """Approved API route from an external inventory source."""

    method: str
    url: str
    path: str
    owner: Optional[str] = None
    lifecycle: Optional[str] = None
    source: Optional[str] = None


class APIInventory:
    """Load and match approved API inventory records."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.entries: list[InventoryEntry] = []
        self.documented_paths: set[str] = set()
        self.source_path: Optional[str] = None

    def load(self) -> list[APIEndpoint]:
        """Load the configured API inventory file."""
        if not self.config.api_inventory_file:
            return []

        path = Path(self.config.api_inventory_file)
        self.source_path = str(path)
        if not path.exists():
            logger.warning(f"  API inventory file not found: {path}")
            return []

        try:
            records = self._read_records(path)
        except Exception as exc:
            logger.warning(f"  Failed to parse API inventory {path}: {exc}")
            return []

        endpoints: list[APIEndpoint] = []
        for record in records:
            entry = self._entry_from_record(record)
            if not entry:
                continue

            self.entries.append(entry)
            self.documented_paths.add(f"{entry.method}:{entry.path.rstrip('/')}")
            endpoints.append(
                APIEndpoint(
                    url=entry.url,
                    method=entry.method,
                    source=EndpointSource.API_INVENTORY,
                    owner=entry.owner,
                    lifecycle=entry.lifecycle,
                    inventory_source=str(path),
                    confidence=1.0,
                )
            )

        if endpoints:
            logger.info(
                f"  Loaded {len(endpoints)} approved API route(s) "
                f"from inventory: {path}"
            )

        return endpoints

    def match(self, endpoint: APIEndpoint) -> Optional[InventoryEntry]:
        """Return the inventory entry matching an endpoint, if any."""
        path = urlparse(endpoint.url).path
        method = endpoint.method.upper()
        for entry in self.entries:
            if entry.method != method:
                continue
            if self._paths_match(entry.path, path):
                return entry
        return None

    def is_documented(self, endpoint: APIEndpoint) -> bool:
        """Check whether an endpoint is in the approved inventory."""
        return self.match(endpoint) is not None

    def is_documented_path_family(self, endpoint: APIEndpoint) -> bool:
        """Check whether an endpoint is a parent of an approved route."""
        path = urlparse(endpoint.url).path.rstrip("/")
        method = endpoint.method.upper()
        if not path:
            return False

        for entry in self.entries:
            if entry.method != method:
                continue
            approved = entry.path.rstrip("/")
            if not approved.startswith(path + "/"):
                continue
            remainder = approved[len(path):].strip("/")
            if "/" not in remainder and (
                remainder.startswith("{") or remainder.startswith(":")
            ):
                return True
        return False

    def enrich(self, endpoint: APIEndpoint) -> None:
        """Copy owner/lifecycle metadata from the matching inventory entry."""
        entry = self.match(endpoint)
        if not entry:
            return
        endpoint.owner = entry.owner
        endpoint.lifecycle = entry.lifecycle
        endpoint.inventory_source = entry.source or self.source_path

    def _read_records(self, path: Path) -> list[dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as handle:
                return [dict(row) for row in csv.DictReader(handle)]

        with path.open("r", encoding="utf-8") as handle:
            text = handle.read()

        if suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore
            except Exception as exc:
                raise ValueError("PyYAML is required for YAML inventory files") from exc
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)

        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("apis", "endpoints", "routes", "inventory"):
                value = data.get(key)
                if isinstance(value, list):
                    return [r for r in value if isinstance(r, dict)]
        return []

    def _entry_from_record(
        self, record: dict[str, Any]
    ) -> Optional[InventoryEntry]:
        method = str(record.get("method") or record.get("http_method") or "GET")
        method = method.upper()

        raw_url = (
            record.get("url")
            or record.get("endpoint")
            or record.get("route")
            or record.get("path")
        )
        if not raw_url:
            return None

        url = self._resolve_url(str(raw_url))
        path = urlparse(url).path
        if not path:
            return None

        owner = record.get("owner") or record.get("team") or record.get("service")
        lifecycle = record.get("lifecycle") or record.get("status")
        return InventoryEntry(
            method=method,
            url=url,
            path=path,
            owner=str(owner) if owner else None,
            lifecycle=str(lifecycle).lower() if lifecycle else None,
            source=self.source_path,
        )

    def _resolve_url(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            return value
        if not value.startswith("/"):
            value = "/" + value
        return urljoin(self.config.target_url.rstrip("/") + "/", value.lstrip("/"))

    @staticmethod
    def _paths_match(pattern: str, actual: str) -> bool:
        pattern = pattern.rstrip("/") or "/"
        actual = actual.rstrip("/") or "/"
        escaped = re.escape(pattern)
        escaped = re.sub(r"\\\{[^/]+?\\\}", r"[^/]+", escaped)
        escaped = re.sub(r"\\:[A-Za-z_][A-Za-z0-9_]*", r"[^/]+", escaped)
        escaped = escaped.replace(r"\*", r"[^/]+")
        return bool(re.match("^" + escaped + "/?$", actual))
