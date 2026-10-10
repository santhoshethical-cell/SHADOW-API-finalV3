"""
Traffic import helpers.

Imports observed API calls from external traffic captures, starting with HAR.
This gives the scanner an Akto-style inventory source: real traffic first,
then OpenAPI comparison to classify undocumented endpoints.
"""

from __future__ import annotations

import csv
import json
import logging
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, EndpointSource, EndpointType
from shadow_api_scanner.utils.helpers import is_api_url, normalize_url

logger = logging.getLogger("shadow_api_scanner")


class TrafficImporter:
    """Import observed API endpoints from traffic capture files."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.target_host = urlparse(config.target_url).hostname or ""

    def import_har_files(self, paths: list[str]) -> list[APIEndpoint]:
        """Import API endpoints from one or more HAR files."""
        endpoints: list[APIEndpoint] = []
        seen: set[tuple[str, str]] = set()

        if not paths:
            return endpoints

        logger.info("=" * 60)
        logger.info("PHASE 1: Traffic Import")
        logger.info("=" * 60)

        for path in paths:
            imported = self._import_har(path, seen)
            endpoints.extend(imported)
            logger.info(f"  HAR {path}: imported {len(imported)} API request(s)")

        logger.info(f"  Total imported traffic endpoints: {len(endpoints)}")
        for ep in endpoints:
            logger.info(f"    {ep.method:6s} [{ep.status_code or '-'}] {ep.url}")

        return endpoints

    def import_log_files(self, paths: list[str]) -> list[APIEndpoint]:
        """Import API endpoints from gateway/proxy/access log files."""
        endpoints: list[APIEndpoint] = []
        seen: set[tuple[str, str]] = set()

        if not paths:
            return endpoints

        logger.info("=" * 60)
        logger.info("PHASE 1: Gateway/Proxy Log Import")
        logger.info("=" * 60)

        for path in paths:
            imported = self._import_log(path, seen)
            endpoints.extend(imported)
            logger.info(
                f"  Traffic log {path}: imported "
                f"{len(imported)} API request(s)"
            )

        logger.info(f"  Total imported log endpoints: {len(endpoints)}")
        for ep in endpoints:
            logger.info(f"    {ep.method:6s} [{ep.status_code or '-'}] {ep.url}")

        return endpoints

    def _import_har(
        self, path: str, seen: set[tuple[str, str]]
    ) -> list[APIEndpoint]:
        har_path = Path(path)
        if not har_path.exists():
            logger.warning(f"  HAR file not found: {path}")
            return []

        try:
            with har_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            logger.warning(f"  Failed to parse HAR {path}: {exc}")
            return []

        entries = data.get("log", {}).get("entries", [])
        endpoints: list[APIEndpoint] = []

        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            url = request.get("url", "")
            method = request.get("method", "GET").upper()
            if not url or not self._in_scope(url):
                continue
            if not self._looks_like_api(url, request, response):
                continue

            key = (normalize_url(url), method)
            if key in seen:
                continue
            seen.add(key)

            req_headers = self._headers_to_dict(request.get("headers", []))
            resp_headers = self._headers_to_dict(response.get("headers", []))
            content = response.get("content", {}) or {}
            body = content.get("text")

            endpoint_type = EndpointType.GRAPHQL if "graphql" in url.lower() else EndpointType.REST
            endpoints.append(APIEndpoint(
                url=url,
                method=method,
                source=EndpointSource.TRAFFIC_IMPORT,
                endpoint_type=endpoint_type,
                headers=req_headers,
                content_type=req_headers.get("content-type"),
                status_code=response.get("status") or None,
                response_headers=resp_headers,
                response_body=body[:5000] if isinstance(body, str) else None,
                response_size=response.get("bodySize"),
                confidence=0.95,
            ))

        return endpoints

    def _import_log(
        self, path: str, seen: set[tuple[str, str]]
    ) -> list[APIEndpoint]:
        log_path = Path(path)
        if not log_path.exists():
            logger.warning(f"  Traffic log file not found: {path}")
            return []

        suffix = log_path.suffix.lower()
        try:
            if suffix == ".csv":
                records = self._read_csv_log(log_path)
            elif suffix == ".json":
                records = self._read_json_log(log_path)
            else:
                records = self._read_jsonl_or_plain_log(log_path)
        except Exception as exc:
            logger.warning(f"  Failed to parse traffic log {path}: {exc}")
            return []

        endpoints: list[APIEndpoint] = []
        for record in records:
            endpoint = self._endpoint_from_log_record(record)
            if not endpoint:
                continue

            key = (normalize_url(endpoint.url), endpoint.method)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(endpoint)

        return endpoints

    def _read_csv_log(self, path: Path) -> list[dict]:
        with path.open("r", encoding="utf-8", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]

    def _read_json_log(self, path: Path) -> list[dict]:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("records", "requests", "logs", "entries"):
                value = data.get(key)
                if isinstance(value, list):
                    return [r for r in value if isinstance(r, dict)]
        return []

    def _read_jsonl_or_plain_log(self, path: Path) -> list[dict]:
        records: list[dict] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        records.append(parsed)
                        continue
                except json.JSONDecodeError:
                    pass

                record = self._parse_plain_access_log(line)
                if record:
                    records.append(record)
        return records

    @staticmethod
    def _parse_plain_access_log(line: str) -> dict | None:
        match = re.search(
            r'"(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+'
            r'(?P<path>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})',
            line,
            re.IGNORECASE,
        )
        if not match:
            return None
        return {
            "method": match.group("method").upper(),
            "path": match.group("path"),
            "status": int(match.group("status")),
        }

    def _endpoint_from_log_record(self, record: dict) -> APIEndpoint | None:
        method = str(
            record.get("method")
            or record.get("http_method")
            or record.get("requestMethod")
            or record.get("request_method")
            or "GET"
        ).upper()

        raw_url = (
            record.get("url")
            or record.get("request_url")
            or record.get("requestUrl")
            or record.get("uri")
            or record.get("path")
            or record.get("route")
        )
        if not raw_url:
            return None

        url = self._resolve_log_url(str(raw_url))
        if not self._in_scope(url) or not is_api_url(url):
            return None

        status = (
            record.get("status")
            or record.get("status_code")
            or record.get("responseStatus")
            or record.get("response_status")
        )
        try:
            status_code = int(status) if status not in (None, "") else None
        except (TypeError, ValueError):
            status_code = None

        endpoint_type = (
            EndpointType.GRAPHQL if "graphql" in url.lower()
            else EndpointType.REST
        )
        return APIEndpoint(
            url=url,
            method=method,
            source=EndpointSource.TRAFFIC_IMPORT,
            endpoint_type=endpoint_type,
            status_code=status_code,
            response_size=record.get("bytes") or record.get("body_bytes_sent"),
            confidence=0.95,
        )

    def _resolve_log_url(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            return value
        if not value.startswith("/"):
            value = "/" + value
        return urljoin(self.config.target_url.rstrip("/") + "/", value.lstrip("/"))

    def _in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        return host == self.target_host or host.endswith("." + self.target_host)

    @staticmethod
    def _headers_to_dict(headers: list[dict]) -> dict:
        result = {}
        for header in headers or []:
            name = str(header.get("name", "")).lower()
            if name:
                result[name] = header.get("value", "")
        return result

    def _looks_like_api(
        self, url: str, request: dict, response: dict
    ) -> bool:
        req_headers = self._headers_to_dict(request.get("headers", []))
        resp_headers = self._headers_to_dict(response.get("headers", []))
        content_type = (
            resp_headers.get("content-type", "")
            or req_headers.get("content-type", "")
            or response.get("content", {}).get("mimeType", "")
        ).lower()
        if "json" in content_type or "graphql" in content_type:
            return True

        method = str(request.get("method", "GET")).upper()
        path = urlparse(url).path.lower()
        if method in {"GET", "HEAD"}:
            static_extensions = (
                ".avif", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg",
                ".jpg", ".js", ".map", ".mjs", ".mp3", ".mp4", ".ogg",
                ".otf", ".pdf", ".png", ".svg", ".ttf", ".webm", ".webp",
                ".woff", ".woff2",
            )
            non_api_content_types = (
                "text/html",
                "text/css",
                "image/",
                "audio/",
                "video/",
                "font/",
                "javascript",
            )
            if (
                path.endswith(static_extensions)
                or any(
                    marker in content_type
                    for marker in non_api_content_types
                )
            ):
                return False

        return is_api_url(url)
