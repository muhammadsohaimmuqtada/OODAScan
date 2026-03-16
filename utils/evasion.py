"""
utils/evasion.py
----------------
WAF Evasion Engine.

Provides:
  - Header injection & rotation (X-Forwarded-For, X-Originating-IP, Client-IP, …)
  - User-Agent rotation
  - Request mutation helpers (header casing, path normalization bypasses)

All logic is self-contained with no external dependencies beyond the standard
library and aiohttp.
"""

from __future__ import annotations

import random
import string
import urllib.parse
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Static data pools
# ---------------------------------------------------------------------------

_USER_AGENTS: List[str] = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mobile Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Googlebot (sometimes bypasses WAF rules)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    # curl (useful for API endpoints)
    "curl/8.6.0",
]

_BYPASS_IPS: List[str] = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "::1",
    "0177.0.0.1",     # Octal representation of 127.0.0.1
    "2130706433",     # Decimal representation of 127.0.0.1
    "0x7f000001",     # Hex representation of 127.0.0.1
]

_IP_SPOOF_HEADERS: List[str] = [
    "X-Forwarded-For",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "Client-IP",
    "X-Client-IP",
    "True-Client-IP",
    "Forwarded",
    "X-Real-IP",
    "X-Cluster-Client-IP",
    "X-ProxyUser-Ip",
]

# Path normalisation bypass fragments
_PATH_MUTATIONS: List[str] = [
    "",           # no mutation
    "/./",        # dot-segment
    "/../",       # parent traversal attempt
    "/;/",        # semicolon bypass
    "/%2f",       # encoded slash
    "/..;/",      # Spring-specific bypass
]


# ---------------------------------------------------------------------------
# EvasionEngine
# ---------------------------------------------------------------------------

class EvasionEngine:
    """
    Builds mutated HTTP headers and request attributes to evade WAF detection.

    Usage::

        engine = EvasionEngine()

        # Get a full header dict ready to pass to aiohttp
        headers = engine.build_headers()

        # Mutate a URL path
        mutated_url = engine.mutate_path("https://example.com/api/users")

        # Rotate through IP-spoof headers (useful for per-request variation)
        spoof_headers = engine.get_ip_spoof_headers()
    """

    def __init__(
        self,
        rotate_ua: bool = True,
        inject_ip_spoof: bool = True,
    ) -> None:
        self._rotate_ua = rotate_ua
        self._inject_ip_spoof = inject_ip_spoof

    # ------------------------------------------------------------------
    # Primary interface
    # ------------------------------------------------------------------

    def build_headers(
        self,
        extra: Optional[Dict[str, str]] = None,
        randomise_casing: bool = False,
    ) -> Dict[str, str]:
        """
        Build a header dictionary suitable for passing directly to aiohttp.

        Parameters
        ----------
        extra:
            Additional headers to merge in (highest priority).
        randomise_casing:
            When True, randomly alternate the casing of header names to
            confuse signature-based WAF rules.
        """
        headers: Dict[str, str] = {}

        if self._rotate_ua:
            headers["User-Agent"] = random.choice(_USER_AGENTS)

        if self._inject_ip_spoof:
            ip = random.choice(_BYPASS_IPS)
            # Pick a random subset of spoof headers to inject
            chosen = random.sample(_IP_SPOOF_HEADERS, k=random.randint(1, 3))
            for hdr in chosen:
                headers[hdr] = ip
            # Forwarded header uses a different format
            if "Forwarded" in chosen:
                headers["Forwarded"] = f"for={ip};proto=https"

        # Standard innocuous headers
        headers["Accept"] = "application/json, text/html, */*"
        headers["Accept-Encoding"] = "gzip, deflate, br"
        headers["Cache-Control"] = "no-cache"
        headers["Connection"] = "keep-alive"

        if extra:
            headers.update(extra)

        if randomise_casing:
            headers = self._randomise_header_casing(headers)

        return headers

    def get_ip_spoof_headers(self, ip: Optional[str] = None) -> Dict[str, str]:
        """
        Return the full set of IP-spoofing headers set to *ip*
        (defaults to a random bypass IP).
        """
        chosen_ip = ip or random.choice(_BYPASS_IPS)
        result: Dict[str, str] = {}
        for hdr in _IP_SPOOF_HEADERS:
            if hdr == "Forwarded":
                result[hdr] = f"for={chosen_ip};proto=https"
            else:
                result[hdr] = chosen_ip
        return result

    def mutate_path(self, url: str, mutation_index: Optional[int] = None) -> str:
        """
        Return a path-mutated variant of *url* using a random (or specified)
        normalisation bypass fragment.

        Parameters
        ----------
        url:
            Full URL to mutate.
        mutation_index:
            If provided, selects the specific mutation from the internal list
            (useful for exhaustive scanning); otherwise a random one is chosen.
        """
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"

        if mutation_index is not None:
            fragment = _PATH_MUTATIONS[mutation_index % len(_PATH_MUTATIONS)]
        else:
            fragment = random.choice(_PATH_MUTATIONS)

        if not fragment:
            return url  # No mutation

        # Insert the fragment before the last path segment
        parts = path.rsplit("/", 1)
        if len(parts) == 2:
            mutated_path = parts[0] + fragment + parts[1]
        else:
            mutated_path = fragment + path

        mutated = parsed._replace(path=mutated_path)
        return urllib.parse.urlunparse(mutated)

    def iter_path_mutations(self, url: str) -> List[str]:
        """Return a list of all available path-mutation variants for *url*."""
        return [
            self.mutate_path(url, i) for i in range(len(_PATH_MUTATIONS))
            if _PATH_MUTATIONS[i]  # Skip the empty (no-op) mutation
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _randomise_header_casing(headers: Dict[str, str]) -> Dict[str, str]:
        """
        Randomly alternate the case of each character in header names.
        Example: ``Content-Type`` → ``cOnTeNt-TyPe``
        """
        result: Dict[str, str] = {}
        for key, value in headers.items():
            mutated_key = "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in key
            )
            result[mutated_key] = value
        return result

    @staticmethod
    def random_ua() -> str:
        """Return a single random User-Agent string."""
        return random.choice(_USER_AGENTS)

    @staticmethod
    def random_bypass_ip() -> str:
        """Return a single random bypass IP."""
        return random.choice(_BYPASS_IPS)
