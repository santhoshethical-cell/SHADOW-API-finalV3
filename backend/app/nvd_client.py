"""Minimal NVD CVE API 2.0 client with pagination, rate limiting and retries.

Reference: https://nvd.nist.gov/developers/vulnerabilities
- Results are paginated with ``startIndex`` / ``resultsPerPage`` (max 2000).
- Public rate limit: 5 requests per rolling 30 s without an API key,
  50 per rolling 30 s with one (sent in the ``apiKey`` request header).
- NVD answers 403/429/503 when throttling; we back off and retry.
- ``lastModStartDate`` / ``lastModEndDate`` ranges may span at most 120 days.

The API key is only ever placed in a request header — never in URLs, logs,
exceptions or return values.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Optional

import httpx

logger = logging.getLogger("sas.nvd")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_PAGE = 2000
MAX_LASTMOD_WINDOW = timedelta(days=120)
_RETRY_STATUS = {403, 429, 500, 502, 503, 504}


class NvdError(RuntimeError):
    """The NVD could not provide a complete answer (after retries)."""


def nvd_datetime(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def lastmod_windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Split [start, end] into <=120-day windows (NVD limit)."""
    windows = []
    cursor = start
    while cursor < end:
        nxt = min(cursor + MAX_LASTMOD_WINDOW - timedelta(seconds=1), end)
        windows.append((cursor, nxt))
        cursor = nxt
    return windows or [(start, end)]


class NvdClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        http: Optional[httpx.Client] = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        page_size: int = MAX_PAGE,
        max_retries: int = 5,
        base_url: str = NVD_API,
        timeout: float = 60.0,
    ) -> None:
        self._key = api_key or None
        self._http = http or httpx.Client(timeout=timeout)
        self._sleep = sleep
        self._clock = clock
        self.page_size = max(1, min(MAX_PAGE, page_size))
        self.max_retries = max_retries
        self.base_url = base_url
        # Stay one below the published ceilings.
        self._window_limit = 49 if self._key else 4
        self._window = 30.0
        self._recent: deque[float] = deque()
        self.requests_made = 0

    # -- rate limiting -------------------------------------------------------
    def _throttle(self) -> None:
        now = self._clock()
        while self._recent and now - self._recent[0] >= self._window:
            self._recent.popleft()
        if len(self._recent) >= self._window_limit:
            wait = self._window - (now - self._recent[0]) + 0.1
            if wait > 0:
                self._sleep(wait)
            now = self._clock()
            while self._recent and now - self._recent[0] >= self._window:
                self._recent.popleft()
        self._recent.append(self._clock())

    # -- single request with retries ----------------------------------------
    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {"apiKey": self._key} if self._key else {}
        last_problem = "unknown error"
        for attempt in range(self.max_retries + 1):
            self._throttle()
            self.requests_made += 1
            try:
                resp = self._http.get(self.base_url, params=params, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_problem = f"network error ({type(exc).__name__})"
                resp = None
            if resp is not None:
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except ValueError:
                        last_problem = "malformed JSON from NVD"
                    else:
                        if isinstance(data, dict) and "vulnerabilities" in data:
                            return data
                        last_problem = "unexpected NVD response shape"
                elif resp.status_code in _RETRY_STATUS:
                    last_problem = f"HTTP {resp.status_code} (throttled/unavailable)"
                else:
                    raise NvdError(f"NVD returned HTTP {resp.status_code}; "
                                   "request parameters were rejected.")
            if attempt < self.max_retries:
                delay = self._retry_delay(resp, attempt)
                logger.info("NVD request failed (%s); retry %d/%d in %.1fs",
                            last_problem, attempt + 1, self.max_retries, delay)
                self._sleep(delay)
        raise NvdError(f"NVD request failed after {self.max_retries + 1} attempts: "
                       f"{last_problem}")

    @staticmethod
    def _retry_delay(resp: Optional[httpx.Response], attempt: int) -> float:
        if resp is not None:
            ra = resp.headers.get("retry-after")
            if ra:
                try:
                    return min(120.0, max(0.0, float(ra)))
                except ValueError:
                    pass
        return min(60.0, 6.0 * (2 ** attempt))

    # -- pagination ------------------------------------------------------------
    def iter_items(self, params: dict[str, Any],
                   on_page: Optional[Callable[[int, int], None]] = None
                   ) -> Iterator[dict[str, Any]]:
        """Yield every ``vulnerabilities[]`` item for ``params``.

        Raises NvdError if the result set cannot be read completely, so a
        caller never mistakes a truncated download for full coverage.
        """
        start = 0
        total: Optional[int] = None
        seen = 0
        while True:
            page = dict(params, startIndex=start, resultsPerPage=self.page_size)
            data = self._get(page)
            page_total = int(data.get("totalResults", 0))
            items = data.get("vulnerabilities") or []
            if total is None:
                total = page_total
            elif page_total != total:
                logger.info("NVD totalResults changed %d -> %d during paging",
                            total, page_total)
                total = page_total
            for item in items:
                yield item
            seen += len(items)
            start += len(items)
            if on_page:
                on_page(seen, total)
            if start >= total:
                break
            if not items:
                raise NvdError(f"NVD returned an empty page at index {start} of "
                               f"{total}; download incomplete.")
        self.last_total = total

    def close(self) -> None:
        self._http.close()
