"""
utils/auto_evasion.py
---------------------
Self-Healing WAF Auto-Tuning Engine.

Extends the base EvasionEngine with:
  - Automatic retry logic when a 403 / WAF block is detected
  - Per-retry strategy rotation (IP headers, User-Agent, delay jitter,
    path normalisation) so each attempt looks different to the WAF
  - A ``resilient_request`` coroutine that wraps any aiohttp request and
    transparently handles blocks without caller intervention

No external dependencies beyond the standard library and aiohttp.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Dict, Optional, Tuple

import aiohttp

from utils.evasion import EvasionEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF block detection signatures
# ---------------------------------------------------------------------------

# HTTP status codes that indicate a WAF/rate-limit block
_BLOCK_STATUSES = frozenset({403, 429, 503})

# Body substrings that indicate a WAF challenge / block page
_BLOCK_BODY_SIGNATURES = [
    "Access Denied",
    "Request blocked",
    "Your IP has been blocked",
    "Enable JavaScript and cookies",  # Cloudflare interstitial
    "cf-browser-verification",
    "DDoS protection",
    "Bot detected",
    "Forbidden",
    "Security check",
    "Sucuri WebSite Firewall",
    "Incapsula",
    "__cf_chl",  # Cloudflare challenge token
]

# ---------------------------------------------------------------------------
# Retry strategy sequence
# ---------------------------------------------------------------------------

# Each strategy is applied in order on successive retries
_STRATEGY_SEQUENCE = [
    "rotate_ua",
    "rotate_ip",
    "rotate_ua_and_ip",
    "mutate_path",
    "add_delay",
    "randomise_casing",
    "full_rotation",
]


class AutoEvasionEngine(EvasionEngine):
    """
    Self-healing request wrapper built on top of ``EvasionEngine``.

    When ``resilient_request`` receives a blocked response it automatically:
      1. Detects whether the block is WAF-based or rate-limit-based.
      2. Selects the next evasion strategy from the rotation sequence.
      3. Modifies the request (headers, path, timing) accordingly.
      4. Retries up to ``max_retries`` times before giving up.

    Parameters
    ----------
    max_retries:
        Number of evasion-enhanced retries before returning the last response.
    base_delay:
        Minimum seconds to wait between retries.  Actual delay is jittered.
    """

    def __init__(
        self,
        max_retries: int = 4,
        base_delay: float = 0.5,
        rotate_ua: bool = True,
        inject_ip_spoof: bool = True,
    ) -> None:
        super().__init__(rotate_ua=rotate_ua, inject_ip_spoof=inject_ip_spoof)
        self._max_retries = max_retries
        self._base_delay = base_delay

    # ------------------------------------------------------------------
    # Primary interface
    # ------------------------------------------------------------------

    async def resilient_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[aiohttp.ClientResponse], str]:
        """
        Execute an HTTP request with automatic WAF-evasion retry logic.

        Returns a ``(response, body_text)`` tuple.  If all retries are
        exhausted, ``(None, "")`` is returned so callers can handle the
        failure gracefully.

        Parameters
        ----------
        session:
            An active ``aiohttp.ClientSession``.
        method:
            HTTP verb ("GET", "POST", …).
        url:
            Target URL.
        headers:
            Initial request headers (will be merged with evasion headers on
            each retry attempt).
        json:
            JSON-serialisable body (mutually exclusive with *data*).
        data:
            Raw body bytes or string.
        params:
            URL query parameters.
        """
        current_url = url
        current_headers = {**self.build_headers(), **(headers or {})}
        last_response: Optional[aiohttp.ClientResponse] = None
        last_body = ""

        for attempt in range(self._max_retries + 1):
            try:
                async with session.request(
                    method,
                    current_url,
                    headers=current_headers,
                    json=json,
                    data=data,
                    params=params,
                    allow_redirects=True,
                ) as resp:
                    body = await resp.text(errors="replace")
                    last_response = resp
                    last_body = body

                    if not self._is_blocked(resp.status, body):
                        return resp, body

                    # Blocked — log and prepare a retry
                    logger.warning(
                        "[AutoEvasion] Blocked on attempt %d/%d: %s %s (HTTP %d)",
                        attempt + 1, self._max_retries + 1, method, current_url, resp.status,
                    )

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.debug(
                    "[AutoEvasion] Request error on attempt %d: %s", attempt + 1, exc
                )

            if attempt < self._max_retries:
                strategy = _STRATEGY_SEQUENCE[attempt % len(_STRATEGY_SEQUENCE)]
                current_url, current_headers = self._apply_strategy(
                    strategy, url, headers or {}
                )
                delay = self._jitter_delay(attempt)
                logger.info(
                    "[AutoEvasion] Retry %d/%d after %.2fs using strategy '%s'",
                    attempt + 1, self._max_retries, delay, strategy,
                )
                await asyncio.sleep(delay)

        logger.error(
            "[AutoEvasion] All %d retries exhausted for %s %s",
            self._max_retries, method, url,
        )
        return last_response, last_body

    # ------------------------------------------------------------------
    # Block detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_blocked(status: int, body: str) -> bool:
        """Return True if the response looks like a WAF block or rate-limit."""
        if status in _BLOCK_STATUSES:
            return True
        for sig in _BLOCK_BODY_SIGNATURES:
            if sig.lower() in body.lower():
                return True
        return False

    # ------------------------------------------------------------------
    # Evasion strategy application
    # ------------------------------------------------------------------

    def _apply_strategy(
        self,
        strategy: str,
        original_url: str,
        original_extra_headers: Dict[str, str],
    ) -> Tuple[str, Dict[str, str]]:
        """
        Return a ``(url, headers)`` pair modified according to *strategy*.
        """
        new_url = original_url
        new_headers: Dict[str, str] = {}

        if strategy == "rotate_ua":
            new_headers = self.build_headers(
                extra=original_extra_headers, randomise_casing=False
            )
            # Force a fresh User-Agent by rebuilding headers
            new_headers["User-Agent"] = self.random_ua()

        elif strategy == "rotate_ip":
            new_headers = self.build_headers(extra=original_extra_headers)
            ip = self.random_bypass_ip()
            new_headers.update(self.get_ip_spoof_headers(ip=ip))

        elif strategy == "rotate_ua_and_ip":
            new_headers = self.build_headers(extra=original_extra_headers)
            new_headers["User-Agent"] = self.random_ua()
            new_headers.update(self.get_ip_spoof_headers())

        elif strategy == "mutate_path":
            new_url = self.mutate_path(original_url)
            new_headers = self.build_headers(extra=original_extra_headers)

        elif strategy == "add_delay":
            # Just rebuild headers; delay is applied by the caller
            new_headers = self.build_headers(extra=original_extra_headers)

        elif strategy == "randomise_casing":
            new_headers = self.build_headers(
                extra=original_extra_headers, randomise_casing=True
            )

        elif strategy == "full_rotation":
            new_url = self.mutate_path(original_url)
            new_headers = self.build_headers(
                extra=original_extra_headers, randomise_casing=True
            )
            new_headers["User-Agent"] = self.random_ua()
            new_headers.update(self.get_ip_spoof_headers())

        else:
            new_headers = self.build_headers(extra=original_extra_headers)

        return new_url, new_headers

    # ------------------------------------------------------------------
    # Timing helpers
    # ------------------------------------------------------------------

    def _jitter_delay(self, attempt: int) -> float:
        """
        Calculate a jittered exponential back-off delay.

        Delay grows with each attempt but includes ±50 % random jitter
        to avoid thundering-herd patterns that WAFs can fingerprint.
        """
        base = self._base_delay * (2 ** attempt)
        jitter = base * random.uniform(-0.5, 0.5)
        return max(0.1, base + jitter)
