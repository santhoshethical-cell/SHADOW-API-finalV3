"""
Phase 2: Dynamic Traffic Monitor

Uses Playwright to crawl bounded same-origin pages and capture runtime API
requests. API capture remains scoped to the target's registered domain so
first-party API subdomains are allowed without inventory pollution from
unrelated third parties.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import parse_qs, urldefrag, urlparse

import tldextract

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, EndpointSource, EndpointType
from shadow_api_scanner.utils.helpers import (
    is_api_url,
    is_static_asset,
    is_same_origin,
    normalize_url,
)
from shadow_api_scanner.utils.redaction import redact_url

logger = logging.getLogger("shadow_api_scanner")
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


class TrafficMonitor:
    """Capture live API traffic from a bounded browser crawl."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.captured_endpoints: list[APIEndpoint] = []
        self._captured_urls: set[str] = set()
        self._response_tasks: set[asyncio.Task] = set()
        self._attached_pages: set[int] = set()
        self.errors: list[str] = []
        self.captured_cookie_header: str = ""
        self._target_domain = self._extract_registered_domain(config.target_url)

    async def run(self) -> list[APIEndpoint]:
        """Launch Chromium, crawl the target, and return captured APIs."""
        logger.info("=" * 60)
        logger.info("PHASE 2: Dynamic Traffic Monitoring")
        logger.info("=" * 60)

        if self.config.browser_timeout <= 0:
            logger.info("  Browser monitoring disabled; skipping dynamic capture.")
            return []

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            message = (
                "Playwright is not installed. Install with: "
                "pip install playwright && python -m playwright install chromium"
            )
            self.errors.append(message)
            logger.error(message)
            return []

        browser = None
        context = None
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=self.config.browser_headless,
                )
                context_options = {
                    "user_agent": self.config.user_agent,
                    "ignore_https_errors": not self.config.verify_tls,
                    "viewport": {"width": 1920, "height": 1080},
                    "extra_http_headers": self._browser_headers(),
                }
                if self.config.browser_storage_state:
                    context_options["storage_state"] = (
                        self.config.browser_storage_state
                    )
                context = await browser.new_context(**context_options)

                context.on("request", self._on_request)
                context.on("response", self._schedule_response)
                context.on("page", self._attach_page_handlers)

                page = await context.new_page()
                self._attach_page_handlers(page)
                logger.info("  Navigating to: %s", self.config.target_url)

                initial_loaded = await self._navigate(
                    page, self.config.target_url
                )
                if initial_loaded:
                    logger.info(
                        "  Waiting %ss for initial async requests...",
                        self.config.wait_after_load,
                    )
                    await asyncio.sleep(self.config.wait_after_load)

                    if (
                        not self.config.browser_headless
                        and self.config.interaction_wait
                    ):
                        logger.info(
                            "  Manual interaction window: %ss. Complete the "
                            "authorized workflow in the browser now...",
                            self.config.interaction_wait,
                        )
                        await asyncio.sleep(self.config.interaction_wait)

                    await self._crawl_pages(page)
                else:
                    logger.warning(
                        "  Skipping browser interactions because the target "
                        "page did not load."
                    )

                await asyncio.sleep(0.5)
                if self._response_tasks:
                    await asyncio.gather(
                        *list(self._response_tasks), return_exceptions=True
                    )

                self.captured_cookie_header = (
                    await self._context_cookie_header(context)
                )
                if self.captured_cookie_header and not self.config.cookie:
                    self.config.cookie = self.captured_cookie_header

        except Exception as error:
            message = f"Dynamic monitoring failed: {error}"
            self.errors.append(message)
            logger.error("  %s", message)
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception as error:
                    logger.debug("  Browser context cleanup failed: %s", error)
            if browser is not None:
                try:
                    await browser.close()
                except Exception as error:
                    logger.debug("  Browser cleanup failed: %s", error)

        logger.info("\nPhase 2 Results:")
        logger.info("  API requests captured: %s", len(self.captured_endpoints))
        for endpoint in self.captured_endpoints:
            logger.info(
                "    %-9s [%s] %s",
                endpoint.method,
                endpoint.status_code,
                endpoint.url,
            )
        return self.captured_endpoints

    def _schedule_response(self, response) -> None:
        task = asyncio.create_task(self._on_response(response))
        self._response_tasks.add(task)
        task.add_done_callback(self._response_tasks.discard)

    def _attach_page_handlers(self, page) -> None:
        page_id = id(page)
        if page_id in self._attached_pages:
            return
        self._attached_pages.add(page_id)
        page.on("websocket", self._on_websocket)

    def _on_websocket(self, websocket) -> None:
        if not self._is_api_request(websocket.url, "websocket"):
            return

        key = f"WEBSOCKET:{normalize_url(websocket.url)}"
        endpoint = None
        if key not in self._captured_urls:
            self._captured_urls.add(key)
            endpoint = APIEndpoint(
                url=websocket.url,
                method="WEBSOCKET",
                source=EndpointSource.DYNAMIC_TRAFFIC,
                endpoint_type=EndpointType.WEBSOCKET,
            )
            self.captured_endpoints.append(endpoint)
        else:
            endpoint = next(
                (
                    item for item in self.captured_endpoints
                    if item.method == "WEBSOCKET"
                    and normalize_url(item.url) == normalize_url(websocket.url)
                ),
                None,
            )

        if endpoint is None:
            return
        websocket.on(
            "framesent",
            lambda payload: self._record_websocket_frame(
                endpoint, "sent", payload
            ),
        )
        websocket.on(
            "framereceived",
            lambda payload: self._record_websocket_frame(
                endpoint, "received", payload
            ),
        )

    @staticmethod
    def _record_websocket_frame(
        endpoint: APIEndpoint,
        direction: str,
        payload,
    ) -> None:
        existing = endpoint.response_body or ""
        if len(existing) >= 8000:
            return
        if isinstance(payload, bytes):
            payload_text = payload[:1000].hex()
        else:
            payload_text = str(payload)[:1000]
        endpoint.response_body = f"{existing}[{direction}] {payload_text}\n"
        endpoint.response_size = len(endpoint.response_body)

    def _on_request(self, request) -> None:
        url = request.url
        method = request.method
        resource_type = request.resource_type

        if resource_type not in (
            "xhr", "fetch", "websocket", "eventsource", "other", "document"
        ):
            return
        if not self._is_api_request(url, resource_type, method):
            return

        captured_method = "WEBSOCKET" if resource_type == "websocket" else method
        key = f"{captured_method}:{normalize_url(url)}"
        if key in self._captured_urls:
            return
        self._captured_urls.add(key)

        endpoint_type = EndpointType.REST
        if resource_type == "websocket":
            endpoint_type = EndpointType.WEBSOCKET
        elif "graphql" in url.lower():
            endpoint_type = EndpointType.GRAPHQL

        try:
            headers = dict(request.headers)
        except Exception:
            headers = {}

        parsed_query = parse_qs(
            urlparse(url).query,
            keep_blank_values=True,
        )
        query_params = {
            name: values[0] if len(values) == 1 else values
            for name, values in parsed_query.items()
        }
        originating_page = self._request_page_url(request)
        redirected_from = self._redirected_from_url(request)

        endpoint = APIEndpoint(
            url=url,
            method=captured_method,
            source=EndpointSource.DYNAMIC_TRAFFIC,
            endpoint_type=endpoint_type,
            headers=headers,
            query_params=query_params,
            content_type=headers.get("content-type"),
            runtime_resource_type=resource_type,
            runtime_initiator=self._request_initiator(request, resource_type),
            originating_page=originating_page,
            redirected_from=redirected_from,
        )
        try:
            post_data = request.post_data_json
            if isinstance(post_data, (dict, list)):
                endpoint.body_params = post_data
            elif post_data is None:
                endpoint.body_params = self._form_body_params(
                    getattr(request, "post_data", None)
                )
        except Exception:
            endpoint.body_params = self._form_body_params(
                getattr(request, "post_data", None)
            )

        endpoint.parameter_evidence = {
            "runtime_query": sorted(str(name) for name in query_params),
            "runtime_body": sorted(
                str(name)
                for name in (
                    endpoint.body_params
                    if isinstance(endpoint.body_params, dict)
                    else {}
                )
            ),
        }

        self.captured_endpoints.append(endpoint)
        logger.debug(
            "    Captured: %s %s",
            captured_method,
            redact_url(url),
        )

    async def _on_response(self, response) -> None:
        url = response.url
        method = response.request.method
        key = f"{method}:{normalize_url(url)}"

        for endpoint in self.captured_endpoints:
            endpoint_key = f"{endpoint.method}:{normalize_url(endpoint.url)}"
            if endpoint_key != key or endpoint.status_code is not None:
                continue

            endpoint.status_code = response.status
            try:
                endpoint.response_headers = dict(response.headers)
            except Exception:
                pass
            content_type = endpoint.response_headers.get(
                "content-type", ""
            ).lower()
            endpoint.response_content_type = content_type or None
            if "json" in content_type:
                try:
                    response_body = await response.text()
                    endpoint.response_size = len(
                        response_body.encode("utf-8", errors="replace")
                    )
                    endpoint.response_body = response_body.encode(
                        "utf-8", errors="replace"
                    )[:self.config.browser_max_response_bytes].decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    pass
            break

    async def _crawl_pages(self, page) -> None:
        queue: list[tuple[str, int]] = [(self.config.target_url, 0)]
        visited: set[str] = set()
        first_page_loaded = True

        while queue and len(visited) < self.config.browser_max_pages:
            url, depth = queue.pop(0)
            normalized = normalize_url(url)
            if normalized in visited:
                continue
            visited.add(normalized)

            if first_page_loaded:
                first_page_loaded = False
            else:
                logger.info("  Exploring page: %s", url)
                if not await self._navigate(page, url):
                    continue

            await asyncio.sleep(self._per_page_wait())
            links = await self._extract_links(page)
            await self._interact_with_page(page)

            if depth >= self.config.browser_crawl_depth:
                continue
            for link in links:
                normalized_link = normalize_url(link)
                if (
                    normalized_link not in visited
                    and self._should_visit(link)
                    and len(queue) + len(visited)
                    < self.config.browser_max_pages
                ):
                    queue.append((link, depth + 1))

        logger.info("  Browser pages explored: %s", len(visited))

    async def _interact_with_page(self, page) -> None:
        logger.info("  Performing safe page interactions...")
        try:
            await page.evaluate(
                "window.scrollTo(0, document.body.scrollHeight)"
            )
            await asyncio.sleep(0.25)

            selectors = [
                "[role='tab']",
                "button[type='button']",
                "[role='button']:not(a)",
            ]
            interactions = 0
            for selector in selectors:
                elements = await page.query_selector_all(selector)
                for element in elements:
                    if interactions >= self.config.browser_max_interactions:
                        return
                    try:
                        label = (await element.inner_text()).strip().lower()
                        if (
                            self._is_safe_interaction(label)
                            and await element.is_visible()
                        ):
                            await element.click(timeout=2000)
                            await asyncio.sleep(0.25)
                            interactions += 1
                    except Exception:
                        continue

            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(0.25)
        except Exception as error:
            logger.debug("  Interaction error (non-critical): %s", error)

    async def _navigate(self, page, url: str) -> bool:
        try:
            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=self.config.browser_timeout * 1000,
            )
            return True
        except Exception as error:
            message = f"Browser navigation failed for {url}: {error}"
            if message not in self.errors:
                self.errors.append(message)
            logger.warning("  %s", message)
            return False

    async def _extract_links(self, page) -> list[str]:
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(element => element.href)",
            )
        except Exception:
            return []

        links: list[str] = []
        for href in hrefs:
            if not isinstance(href, str):
                continue
            clean_url = urldefrag(href).url
            if clean_url and clean_url not in links:
                links.append(clean_url)
        return links

    def _should_visit(self, url: str) -> bool:
        if not is_same_origin(self.config.target_url, url):
            return False
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        path = parsed.path.lower()
        if any(
            token in path
            for token in (
                "/logout",
                "/log-out",
                "/signout",
                "/delete-account",
            )
        ):
            return False
        return not any(
            path.endswith(extension)
            for extension in (
                ".js",
                ".css",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".ico",
                ".woff",
                ".woff2",
                ".pdf",
                ".zip",
                ".mp4",
            )
        )

    @staticmethod
    def _is_safe_interaction(label: str) -> bool:
        return not any(
            token in label
            for token in (
                "delete",
                "remove",
                "logout",
                "log out",
                "sign out",
                "purchase",
                "pay",
                "confirm",
                "submit",
                "send",
                "save",
                "place order",
            )
        )

    def _per_page_wait(self) -> float:
        return min(1.0, max(0.25, self.config.wait_after_load / 10))

    async def _context_cookie_header(self, context) -> str:
        try:
            cookies = await context.cookies([self.config.target_url])
        except Exception:
            return ""
        return "; ".join(
            f"{cookie['name']}={cookie['value']}"
            for cookie in sorted(cookies, key=lambda item: item["name"])
        )

    def _browser_headers(self) -> dict:
        headers = {}
        if self.config.auth_token:
            headers[self.config.auth_header] = self.config.auth_token
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie
        headers.update(self.config.custom_headers)
        return headers

    def _is_api_request(
        self,
        url: str,
        resource_type: str,
        method: str | None = None,
    ) -> bool:
        parsed = urlparse(url)

        request_domain = self._extract_registered_domain(url)
        if request_domain != self._target_domain:
            logger.debug(
                "    Skipping cross-origin: %s (target: %s)",
                parsed.hostname,
                self._target_domain,
            )
            return False

        if is_static_asset(url):
            return False
        if resource_type == "websocket":
            return True
        if is_api_url(url):
            return True
        if resource_type == "document" and method:
            return method.upper() not in {"GET", "HEAD", "OPTIONS"}
        return resource_type in ("xhr", "fetch", "eventsource")

    @staticmethod
    def _request_page_url(request) -> str | None:
        try:
            return request.frame.url or None
        except Exception:
            return None

    @staticmethod
    def _redirected_from_url(request) -> str | None:
        try:
            redirected_from = request.redirected_from
            return redirected_from.url if redirected_from else None
        except Exception:
            return None

    @staticmethod
    def _request_initiator(request, resource_type: str) -> str:
        try:
            if request.is_navigation_request():
                return "navigation"
        except Exception:
            pass
        return resource_type

    @staticmethod
    def _form_body_params(post_data: str | None) -> dict:
        if not post_data:
            return {}
        parsed = parse_qs(post_data, keep_blank_values=True)
        return {
            name: values[0] if len(values) == 1 else values
            for name, values in parsed.items()
        }

    @staticmethod
    def _extract_registered_domain(url: str) -> str:
        extracted = _TLD_EXTRACTOR(url)
        if extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return (extracted.domain or urlparse(url).hostname or "").lower()
