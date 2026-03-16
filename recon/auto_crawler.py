"""
recon/auto_crawler.py
---------------------
Autonomous Headless DOM Crawler.

Uses Playwright (async API) to drive a real browser, navigate the target
domain, and automatically:
  - Intercept all XHR / Fetch network requests made by the page
  - Extract JavaScript bundle URLs and parse them for API route references
  - Discover single-page application (SPA) routes via link traversal
  - Parse inline and external JS for hardcoded endpoints, tokens, and
    API key patterns

All discovered endpoints are returned as a deduplicated list, ready to be
fed directly into the AutonomousAgent OODA loop.

Dependencies
------------
- playwright (install with ``pip install playwright && playwright install chromium``)
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns for extracting endpoints from JavaScript source
# ---------------------------------------------------------------------------

# Matches relative and absolute API paths inside JS string literals
_JS_API_PATH_PATTERN = re.compile(
    r'["\`]'
    r'((?:https?://[^\s"\'`<>]+|/[a-zA-Z0-9_\-./]*'
    r'(?:api|v\d+|graphql|gql|rest|rpc|endpoint|service)[^\s"\'`<>]*'
    r'|/[a-zA-Z0-9_\-]{2,}/[a-zA-Z0-9_\-./]+))'
    r'["\`]',
    re.IGNORECASE,
)

# Template literal paths like `/api/users/${id}` → normalised to `/api/users/:id`
_TEMPLATE_LITERAL_PATTERN = re.compile(r'\$\{[^}]+\}')

# Hardcoded credential / secret patterns to flag during JS analysis
_SECRET_PATTERNS: Dict[str, re.Pattern[str]] = {
    "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "Generic API Key": re.compile(
        r'(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}'
    ),
    "Bearer Token": re.compile(r'Bearer\s+eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*'),
    "Private Key Header": re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
}

# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class AutoCrawler:
    """
    Autonomous headless browser crawler that feeds endpoints to the agent loop.

    Parameters
    ----------
    max_pages:
        Maximum number of pages to visit before stopping.
    max_js_files:
        Maximum number of JS bundle files to download and analyse.
    timeout_ms:
        Per-navigation Playwright timeout in milliseconds.
    headless:
        Run the browser in headless mode (default True).

    Usage::

        crawler = AutoCrawler(max_pages=50)
        result = await crawler.crawl("https://example.com")
        print(result.endpoints)
        print(result.secrets_found)
    """

    def __init__(
        self,
        max_pages: int = 50,
        max_js_files: int = 30,
        timeout_ms: int = 15_000,
        headless: bool = True,
    ) -> None:
        self._max_pages = max_pages
        self._max_js_files = max_js_files
        self._timeout_ms = timeout_ms
        self._headless = headless

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self, target_url: str) -> "CrawlResult":
        """
        Launch a headless browser, crawl *target_url*, and return all
        discovered endpoints and findings.

        Parameters
        ----------
        target_url:
            The root URL to start crawling from (e.g. ``https://example.com``).
        """
        try:
            from playwright.async_api import async_playwright, Request, Response
        except ImportError as exc:
            raise ImportError(
                "Playwright is required for AutoCrawler. "
                "Install it with: pip install playwright && playwright install chromium"
            ) from exc

        result = CrawlResult(target=target_url)
        parsed_target = urlparse(target_url)
        allowed_host = parsed_target.netloc

        visited_pages: Set[str] = set()
        js_files_processed: Set[str] = set()
        intercepted_api_calls: Set[str] = set()
        pages_to_visit: List[str] = [target_url]

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self._headless)
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            page = await context.new_page()

            # ── Network interception ──────────────────────────────────────
            async def _on_request(request: Request) -> None:
                req_url = request.url
                req_parsed = urlparse(req_url)

                # Capture XHR / Fetch API calls to the same host
                if (
                    req_parsed.netloc == allowed_host
                    and request.resource_type in ("xhr", "fetch")
                    and req_url not in intercepted_api_calls
                ):
                    intercepted_api_calls.add(req_url)
                    result.endpoints.add(req_url)
                    logger.info("[Crawler] Intercepted API call: %s", req_url)

                # Collect JS file URLs for later analysis
                if (
                    request.resource_type == "script"
                    and req_parsed.netloc == allowed_host
                    and req_url not in js_files_processed
                    and len(js_files_processed) < self._max_js_files
                ):
                    js_files_processed.add(req_url)

            page.on("request", _on_request)

            # ── Page traversal loop ───────────────────────────────────────
            while pages_to_visit and len(visited_pages) < self._max_pages:
                current_url = pages_to_visit.pop(0)
                if current_url in visited_pages:
                    continue

                visited_pages.add(current_url)
                logger.info(
                    "[Crawler] Visiting (%d/%d): %s",
                    len(visited_pages), self._max_pages, current_url,
                )

                try:
                    await page.goto(
                        current_url,
                        timeout=self._timeout_ms,
                        wait_until="networkidle",
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    logger.debug("[Crawler] Navigation error on %s: %s", current_url, exc)
                    continue

                # Collect all links on the page
                new_links = await self._extract_same_host_links(
                    page, allowed_host, visited_pages
                )
                pages_to_visit.extend(new_links)

                # Collect data-* attributes that may expose API routes
                await self._scrape_data_attributes(page, result)

                # Scrape inline <script> content
                inline_scripts = await page.evaluate(
                    """() => {
                        return Array.from(document.querySelectorAll('script:not([src])'))
                            .map(s => s.textContent);
                    }"""
                )
                for script_text in inline_scripts:
                    if script_text:
                        self._parse_js(script_text, target_url, allowed_host, result)

            # ── Analyse collected JS files ────────────────────────────────
            js_context = await context.new_page()
            for js_url in list(js_files_processed):
                await self._fetch_and_analyse_js(
                    js_context, js_url, target_url, allowed_host, result
                )

            await browser.close()

        logger.info(
            "[Crawler] Finished. Pages=%d, Endpoints=%d, Secrets=%d",
            len(visited_pages), len(result.endpoints), len(result.secrets_found),
        )
        return result

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    @staticmethod
    async def _extract_same_host_links(
        page: Any,
        allowed_host: str,
        already_visited: Set[str],
    ) -> List[str]:
        """Return all same-host href links found on the current page."""
        try:
            hrefs = await page.evaluate(
                """() => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)"""
            )
        except Exception:  # pylint: disable=broad-except
            return []

        links: List[str] = []
        for href in hrefs:
            parsed = urlparse(href)
            if parsed.netloc == allowed_host and href not in already_visited:
                # Exclude binary assets, anchors-only, mailto, etc.
                if parsed.scheme in ("http", "https") and not re.search(
                    r'\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|pdf|zip)$',
                    parsed.path, re.IGNORECASE,
                ):
                    links.append(href)
        return links

    # ------------------------------------------------------------------
    # data-* attribute scraping
    # ------------------------------------------------------------------

    @staticmethod
    async def _scrape_data_attributes(page: Any, result: "CrawlResult") -> None:
        """
        Extract API endpoint hints from HTML data-* attributes.
        Common patterns: data-api-url, data-endpoint, data-src, …
        """
        try:
            attrs = await page.evaluate(
                """() => {
                    const results = [];
                    const all = document.querySelectorAll('[data-api-url],[data-endpoint],[data-url]');
                    all.forEach(el => {
                        ['data-api-url','data-endpoint','data-url'].forEach(attr => {
                            const val = el.getAttribute(attr);
                            if (val) results.push(val);
                        });
                    });
                    return results;
                }"""
            )
        except Exception:  # pylint: disable=broad-except
            return

        for attr_val in attrs:
            if attr_val and attr_val.startswith(("/", "http")):
                result.endpoints.add(attr_val)

    # ------------------------------------------------------------------
    # JS file fetching & analysis
    # ------------------------------------------------------------------

    async def _fetch_and_analyse_js(
        self,
        page: Any,
        js_url: str,
        base_url: str,
        allowed_host: str,
        result: "CrawlResult",
    ) -> None:
        """Fetch a JS bundle URL and parse it for API routes and secrets."""
        try:
            response = await page.goto(js_url, timeout=self._timeout_ms)
            if response and response.ok:
                content = await response.text()
                self._parse_js(content, base_url, allowed_host, result)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("[Crawler] Could not fetch JS %s: %s", js_url, exc)

    # ------------------------------------------------------------------
    # JS source parser
    # ------------------------------------------------------------------

    def _parse_js(
        self,
        js_source: str,
        base_url: str,
        allowed_host: str,
        result: "CrawlResult",
    ) -> None:
        """
        Parse raw JavaScript source to extract:
          - API endpoint paths / URLs
          - Hardcoded secrets / credentials
        """
        # API endpoint extraction
        for match in _JS_API_PATH_PATTERN.finditer(js_source):
            raw = match.group(1)
            # Normalise template literals → parameterised form
            normalised = _TEMPLATE_LITERAL_PATTERN.sub(":param", raw)

            if normalised.startswith("http"):
                parsed = urlparse(normalised)
                if parsed.netloc == allowed_host:
                    result.endpoints.add(normalised)
            elif normalised.startswith("/"):
                full_url = urljoin(base_url, normalised)
                result.endpoints.add(full_url)

        # Secret / credential detection
        for label, pattern in _SECRET_PATTERNS.items():
            for match in pattern.finditer(js_source):
                finding = {
                    "type": f"Hardcoded Secret in JS: {label}",
                    "severity": "Critical",
                    "details": (
                        f"Pattern '{label}' matched in JavaScript source. "
                        "Rotate the credential immediately."
                    ),
                    "snippet": match.group(0)[:120],
                }
                # Avoid duplicate findings for the same label
                if not any(
                    f.get("type") == finding["type"] and
                    f.get("snippet", "")[:20] == finding["snippet"][:20]
                    for f in result.secrets_found
                ):
                    result.secrets_found.append(finding)
                    logger.warning(
                        "[Crawler] Secret detected in JS: %s", label
                    )


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

class CrawlResult:
    """
    Aggregated output from a crawl session.

    Attributes
    ----------
    target:
        The root URL that was crawled.
    endpoints:
        Deduplicated set of discovered API endpoint URLs.
    secrets_found:
        List of secret/credential finding dicts.
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self.endpoints: Set[str] = set()
        self.secrets_found: List[Dict[str, str]] = []

    def endpoint_list(self) -> List[str]:
        """Return endpoints as a sorted list."""
        return sorted(self.endpoints)

    def summary(self) -> Dict[str, Any]:
        """Return a JSON-serialisable summary dict."""
        return {
            "target": self.target,
            "endpoints_discovered": self.endpoint_list(),
            "secrets_found": self.secrets_found,
        }
