"""
Inventory baseline save/compare support.

Baselines let the scanner report Akto-style inventory drift:
new endpoints, removed endpoints, status changes, and method set changes.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from shadow_api_scanner.core.models import APIEndpoint, ScanResult
from shadow_api_scanner.utils.helpers import ensure_dir, normalize_url

logger = logging.getLogger("shadow_api_scanner")


class BaselineManager:
    """Save and compare API inventory baselines."""

    @staticmethod
    def save(result: ScanResult, path: str) -> str:
        baseline_path = Path(path)
        if baseline_path.parent:
            ensure_dir(str(baseline_path.parent))

        data = {
            "version": 3,
            "target_url": result.target_url,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": len(result.all_endpoints),
                "shadow": len(result.shadow_endpoints),
                "documented": len(result.documented_endpoints),
            },
            "endpoints": [
                BaselineManager._endpoint_record(ep)
                for ep in result.all_endpoints
            ],
        }

        with baseline_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"  Inventory baseline saved: {baseline_path}")
        return str(baseline_path)

    @staticmethod
    def compare(result: ScanResult, path: str) -> dict:
        baseline_path = Path(path)
        if not baseline_path.exists():
            logger.warning(f"  Baseline file not found: {path}")
            return {"error": f"Baseline file not found: {path}"}

        try:
            with baseline_path.open("r", encoding="utf-8") as f:
                previous = json.load(f)
        except Exception as exc:
            logger.warning(f"  Failed to parse baseline {path}: {exc}")
            return {"error": f"Failed to parse baseline: {exc}"}

        previous_records = BaselineManager._extract_records(previous)
        current_records = {
            BaselineManager._key(ep): BaselineManager._endpoint_record(ep)
            for ep in result.all_endpoints
        }

        previous_keys = set(previous_records)
        current_keys = set(current_records)

        added_keys = sorted(current_keys - previous_keys)
        removed_keys = sorted(previous_keys - current_keys)
        common_keys = previous_keys & current_keys

        status_changed = []
        source_changed = []
        for key in sorted(common_keys):
            old = previous_records[key]
            new = current_records[key]
            if old.get("documentation_status") != new.get("documentation_status"):
                status_changed.append({
                    "key": key,
                    "url": new["url"],
                    "method": new["method"],
                    "from": old.get("documentation_status"),
                    "to": new.get("documentation_status"),
                })
            if old.get("source") != new.get("source"):
                source_changed.append({
                    "key": key,
                    "url": new["url"],
                    "method": new["method"],
                    "from": old.get("source"),
                    "to": new.get("source"),
                })

        method_changes = BaselineManager._method_changes(
            previous_records, current_records
        )

        diff = {
            "baseline": str(baseline_path),
            "added": [current_records[key] for key in added_keys],
            "removed": [previous_records[key] for key in removed_keys],
            "status_changed": status_changed,
            "source_changed": source_changed,
            "method_changes": method_changes,
            "summary": {
                "added": len(added_keys),
                "removed": len(removed_keys),
                "status_changed": len(status_changed),
                "method_changes": len(method_changes),
            },
        }

        logger.info(
            "  Inventory diff: "
            f"+{len(added_keys)} / -{len(removed_keys)} endpoints, "
            f"{len(status_changed)} status change(s), "
            f"{len(method_changes)} method change(s)"
        )
        return diff

    @staticmethod
    def _endpoint_record(ep: APIEndpoint) -> dict:
        inventory_url = ep.inventory_url
        return {
            "key": BaselineManager._key(ep),
            "method": ep.method,
            "url": inventory_url,
            "representative_url": ep.url,
            "route_pattern": ep.route_pattern,
            "observed_count": ep.observed_count,
            "normalized_url": normalize_url(inventory_url),
            "path": urlparse(inventory_url).path or "/",
            "source": ep.source.value,
            "documentation_status": ep.documentation_status.value,
            "is_shadow": ep.is_shadow,
            "status_code": ep.status_code,
            "operation_evidence": ep.operation_evidence,
            "parent_endpoint_id": ep.parent_endpoint_id,
        }

    @staticmethod
    def _key(ep: APIEndpoint) -> str:
        return f"{ep.method}:{normalize_url(ep.inventory_url)}"

    @staticmethod
    def _extract_records(data: dict) -> dict[str, dict]:
        if "endpoints" in data and isinstance(data["endpoints"], list):
            records = data["endpoints"]
        elif isinstance(data.get("endpoints"), dict):
            records = data["endpoints"].get("all", [])
        else:
            records = []

        extracted: dict[str, dict] = {}
        for record in records:
            method = record.get("method", "GET")
            url = record.get("url")
            if not url:
                continue
            key = record.get("key") or f"{method}:{normalize_url(url)}"
            extracted[key] = {
                "key": key,
                "method": method,
                "url": url,
                "representative_url": record.get("representative_url", url),
                "route_pattern": record.get("route_pattern"),
                "observed_count": record.get("observed_count", 1),
                "normalized_url": record.get("normalized_url", normalize_url(url)),
                "path": record.get("path", urlparse(url).path or "/"),
                "source": record.get("source"),
                "documentation_status": record.get("documentation_status"),
                "is_shadow": record.get("is_shadow", False),
                "status_code": record.get("status_code"),
                "operation_evidence": record.get(
                    "operation_evidence", []
                ),
                "parent_endpoint_id": record.get("parent_endpoint_id"),
            }
        return extracted

    @staticmethod
    def _method_changes(
        previous: dict[str, dict], current: dict[str, dict]
    ) -> list[dict]:
        def by_path(records: dict[str, dict]) -> dict[str, set[str]]:
            grouped: dict[str, set[str]] = {}
            for record in records.values():
                grouped.setdefault(record["normalized_url"], set()).add(
                    record["method"]
                )
            return grouped

        old_paths = by_path(previous)
        new_paths = by_path(current)
        changes = []
        for path in sorted(set(old_paths) | set(new_paths)):
            old_methods = old_paths.get(path, set())
            new_methods = new_paths.get(path, set())
            added = sorted(new_methods - old_methods)
            removed = sorted(old_methods - new_methods)
            if added or removed:
                changes.append({
                    "normalized_url": path,
                    "added_methods": added,
                    "removed_methods": removed,
                })
        return changes
