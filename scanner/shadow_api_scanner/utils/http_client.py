"""
Async HTTP client wrapper for Shadow API Scanner.

Provides a reusable httpx-based async client with retry logic,
rate limiting, and response capture for proof-of-concept generation.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.utils.redaction import (
    redact_body,
    redact_headers,
    redact_url,
)


SAFE_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_SECURITY_REQUESTS = 1000
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class RequestBudgetExceeded(RuntimeError):
    """Raised internally when the global security request cap is exhausted."""


class SecurityScopeViolation(RuntimeError):
    """Raised internally before an out-of-scope request or redirect is sent."""


@dataclass
class CapturedRequest:
    """Stores a request/response pair for PoC evidence."""
    method: str
    url: str
    headers: dict
    body: Optional[str]
    status_code: int
    response_headers: dict
    response_body: str
    response_time_ms: float
    timestamp: str = ""

    def format_request(self) -> str:
        """Format as a cURL-like request string."""
        lines = [f"{self.method} {redact_url(self.url)}"]
        for k, v in redact_headers(self.headers).items():
            lines.append(f"  {k}: {v}")
        if self.body:
            redacted_body = redact_body(self.body) or ""
            lines.append(f"  Body: {redacted_body[:500]}")
        return "\n".join(lines)

    def format_response(self) -> str:
        """Format response summary."""
        body_preview = redact_body(
            self.response_body[:1000]
        ) if self.response_body else ""
        return (
            f"HTTP {self.status_code} ({self.response_time_ms:.0f}ms)\n"
            f"  Retained-Body-Length: "
            f"{len(self.response_body) if self.response_body else 0}\n"
            f"  Body: {body_preview}"
        )


class AsyncHTTPClient:
    """
    Managed async HTTP client with rate limiting and retry logic.

    Usage:
        async with AsyncHTTPClient(config) as client:
            captured = await client.request("GET", url)
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limit_delay = config.rate_limit_delay
        self._last_request_time = 0.0
        self._request_count = 0
        self._rate_limit_lock = asyncio.Lock()
        self._request_count_lock = asyncio.Lock()
        self._validate_safety_bounds()

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.request_timeout),
            follow_redirects=True,
            max_redirects=self.config.max_redirects,
            verify=self.config.verify_tls,
            http2=True,
            event_hooks={"request": [self._before_network_request]},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    async def _enforce_rate_limit(self):
        """Enforce minimum delay between requests."""
        async with self._rate_limit_lock:
            if self._rate_limit_delay > 0:
                elapsed = time.monotonic() - self._last_request_time
                if elapsed < self._rate_limit_delay:
                    await asyncio.sleep(self._rate_limit_delay - elapsed)
            self._last_request_time = time.monotonic()

    async def _reserve_request(self) -> None:
        """Atomically reserve one network attempt from the global budget."""
        async with self._request_count_lock:
            if self._request_count >= self.config.max_security_requests:
                raise RequestBudgetExceeded(
                    "global security request budget exhausted"
                )
            self._request_count += 1

    async def _before_network_request(self, request: httpx.Request) -> None:
        """Enforce exact scope and budget for initial and redirected requests."""
        scope_error = self.config.security_scope_error(str(request.url))
        if scope_error:
            raise SecurityScopeViolation(scope_error)
        await self._reserve_request()

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json_body: Optional[Any] = None,
        data: Optional[str] = None,
        omit_headers: Optional[set[str]] = None,
        retries: int = 2,
        skip_rate_limit: bool = False,
    ) -> CapturedRequest:
        """
        Send an HTTP request and return a CapturedRequest with full details.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Additional headers to merge
            params: Query parameters
            json_body: JSON body (dict or list)
            data: Raw body string
            omit_headers: Header names to remove from configured defaults
            retries: Number of retry attempts
            skip_rate_limit: Skip rate limiting for this request

        Returns:
            CapturedRequest with request and response details.
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")

        if not skip_rate_limit:
            await self._enforce_rate_limit()

        merged_headers = dict(self.config.get_headers())
        omitted = {
            name.lower() for name in (omit_headers or set())
        }
        if omitted:
            merged_headers = {
                name: value
                for name, value in merged_headers.items()
                if name.lower() not in omitted
            }
        if "cookie" in omitted:
            # An explicit empty header overrides cookies persisted by httpx.
            merged_headers["Cookie"] = ""
        if headers:
            merged_headers.update(headers)

        request_body = None
        if json_body is not None:
            import json as json_mod
            request_body = json_mod.dumps(json_body)
        elif data is not None:
            request_body = data

        normalized_method = method.upper()
        retry_count = max(0, retries)
        if normalized_method not in SAFE_RETRY_METHODS:
            retry_count = 0

        last_error: Exception | None = None
        for attempt in range(retry_count + 1):
            try:
                start = time.monotonic()
                async with self._client.stream(
                    method=normalized_method,
                    url=url,
                    headers=merged_headers,
                    params=params,
                    json=json_body,
                    content=data.encode() if data and json_body is None else None,
                ) as response:
                    response_url = str(response.url)
                    response_headers = dict(response.headers)
                    status_code = response.status_code
                    resp_body = await self._read_response_body(response)
                    elapsed_ms = (time.monotonic() - start) * 1000

                return CapturedRequest(
                    method=normalized_method,
                    url=response_url,
                    headers=merged_headers,
                    body=request_body,
                    status_code=status_code,
                    response_headers=response_headers,
                    response_body=resp_body,
                    response_time_ms=elapsed_ms,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_error = e
                if attempt < retry_count:
                    await asyncio.sleep(1 * (attempt + 1))
                continue
            except (RequestBudgetExceeded, SecurityScopeViolation) as e:
                last_error = e
                break
            except Exception as e:
                last_error = e
                break

        # Return an error-state CapturedRequest
        return CapturedRequest(
            method=normalized_method,
            url=url,
            headers=merged_headers,
            body=request_body,
            status_code=0,
            response_headers={},
            response_body=(
                f"ERROR: {type(last_error).__name__}"
                if last_error is not None else "ERROR"
            ),
            response_time_ms=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    async def _read_response_body(self, response: httpx.Response) -> str:
        """Read and retain at most the configured decoded response bytes."""
        limit = self.config.max_security_response_bytes
        retained = bytearray()
        truncated = False
        async for chunk in response.aiter_bytes():
            remaining = limit - len(retained)
            if remaining <= 0:
                truncated = True
                break
            retained.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
                break

        encoding = response.encoding or "utf-8"
        try:
            body = bytes(retained).decode(encoding, errors="replace")
        except LookupError:
            body = bytes(retained).decode("utf-8", errors="replace")
        if truncated:
            body += "\n[response truncated by scanner safety limit]"
        return body

    def _validate_safety_bounds(self) -> None:
        """Reject programmatic configurations that bypass CLI range checks."""
        if not 0 < self.config.request_timeout <= 120:
            raise ValueError("request_timeout must be between 0 and 120 seconds")
        if not 0 <= self.config.rate_limit_delay <= 10:
            raise ValueError("rate_limit_delay must be between 0 and 10 seconds")
        if not 1 <= self.config.max_security_requests <= MAX_SECURITY_REQUESTS:
            raise ValueError("max_security_requests must be between 1 and 1000")
        if not 1024 <= self.config.max_security_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError(
                "max_security_response_bytes must be between 1024 and 10485760"
            )
        if not 0 <= self.config.max_redirects <= 10:
            raise ValueError("max_redirects must be between 0 and 10")

    async def get(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("PATCH", url, **kwargs)

    async def options(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("OPTIONS", url, **kwargs)

    @property
    def total_requests(self) -> int:
        return self._request_count
