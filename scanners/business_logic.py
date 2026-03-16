"""
scanners/business_logic.py
--------------------------
Advanced business-logic vulnerability scanner.

Covers:
  - HTTP Parameter Pollution (HPP)
  - Mass Assignment probing
  - Race Condition detection via highly concurrent async requests
  - IDOR State Machine: replays every endpoint across multiple auth contexts
    (Unauthenticated, User A, User B, Admin) to surface Broken Access Control
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from utils.evasion import EvasionEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    """Represents a single authentication role/context."""
    name: str
    token: Optional[str] = None

    @property
    def headers(self) -> Dict[str, str]:
        if self.token:
            return {"Authorization": self.token}
        return {}


@dataclass
class ScanResult:
    """A single finding produced by the business-logic scanner."""
    vuln_type: str
    url: str
    method: str
    details: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    severity: str = "Medium"


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class BusinessLogicScanner:
    """
    Scans a list of endpoints for business-logic vulnerabilities using
    fully async, internally crafted HTTP requests (aiohttp).

    Parameters
    ----------
    contexts:
        Auth contexts to test with.  At minimum provide an unauthenticated
        context plus any user/admin tokens you have captured.
    concurrency:
        Maximum number of simultaneous in-flight requests.
    timeout:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        contexts: List[AuthContext],
        concurrency: int = 50,
        timeout: float = 10.0,
    ) -> None:
        self._contexts = contexts
        self._concurrency = concurrency
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._evasion = EvasionEngine()
        self._findings: List[ScanResult] = []

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def scan_endpoints(
        self,
        endpoints: List[str],
        method: str = "GET",
        body: Optional[Dict[str, Any]] = None,
    ) -> List[ScanResult]:
        """Run all checks against *endpoints* and return deduplicated findings."""
        self._findings = []
        connector = aiohttp.TCPConnector(limit=self._concurrency, ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._timeout
        ) as session:
            tasks: List[asyncio.Task[None]] = []
            for url in endpoints:
                tasks.append(
                    asyncio.create_task(
                        self._check_all(session, url, method, body or {})
                    )
                )
            await asyncio.gather(*tasks, return_exceptions=True)
        return self._findings

    # ------------------------------------------------------------------
    # Aggregate check dispatcher
    # ------------------------------------------------------------------

    async def _check_all(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        body: Dict[str, Any],
    ) -> None:
        await asyncio.gather(
            self._check_hpp(session, url),
            self._check_mass_assignment(session, url, body),
            self._check_race_condition(session, url, method, body),
            self._check_idor_state_machine(session, url, method, body),
            return_exceptions=True,
        )

    # ------------------------------------------------------------------
    # HTTP Parameter Pollution
    # ------------------------------------------------------------------

    async def _check_hpp(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> None:
        """
        Probe for HPP by duplicating common parameters and comparing
        server behaviour.  A status-code divergence or unexpected value
        echo is flagged.
        """
        probe_params = [
            ("id", ["1", "2"]),
            ("user_id", ["1", "99999"]),
            ("role", ["user", "admin"]),
            ("price", ["100", "0"]),
        ]
        for param_name, values in probe_params:
            try:
                # Build a query string that duplicates the parameter
                qs = "&".join(f"{param_name}={v}" for v in values)
                probe_url = f"{url}{'&' if '?' in url else '?'}{qs}"
                headers = self._evasion.build_headers()
                async with session.get(probe_url, headers=headers) as resp:
                    text = await resp.text()
                    if resp.status in (200, 302) and values[1] in text:
                        self._record(
                            ScanResult(
                                vuln_type="HTTP Parameter Pollution",
                                url=probe_url,
                                method="GET",
                                details=(
                                    f"Parameter '{param_name}' appears pollutable — "
                                    f"second value '{values[1]}' echoed back."
                                ),
                                evidence={
                                    "status": resp.status,
                                    "polluted_param": param_name,
                                },
                                severity="High",
                            )
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.debug("HPP probe error on %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Mass Assignment
    # ------------------------------------------------------------------

    async def _check_mass_assignment(
        self,
        session: aiohttp.ClientSession,
        url: str,
        original_body: Dict[str, Any],
    ) -> None:
        """
        Inject privileged fields into the request body and look for
        indicators that the server accepted them.
        """
        privileged_fields: Dict[str, Any] = {
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "is_superuser": True,
            "verified": True,
            "balance": 99999,
            "credits": 99999,
            "permissions": ["read", "write", "delete", "admin"],
        }
        probe_body = {**original_body, **privileged_fields}
        try:
            headers = {
                **self._evasion.build_headers(),
                "Content-Type": "application/json",
            }
            async with session.post(
                url, json=probe_body, headers=headers
            ) as resp:
                text = await resp.text()
                # Heuristic: privileged field name appears in a 2xx response
                matched = [
                    k for k in privileged_fields if k in text and resp.status < 300
                ]
                if matched:
                    self._record(
                        ScanResult(
                            vuln_type="Mass Assignment",
                            url=url,
                            method="POST",
                            details=(
                                f"Server accepted privileged fields: {matched}. "
                                "Verify manually whether these were persisted."
                            ),
                            evidence={
                                "status": resp.status,
                                "matched_fields": matched,
                            },
                            severity="Critical",
                        )
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.debug("Mass-assignment probe error on %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Race Condition
    # ------------------------------------------------------------------

    async def _check_race_condition(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        body: Dict[str, Any],
        burst: int = 30,
    ) -> None:
        """
        Fire *burst* identical requests as close to simultaneously as possible.
        If more than one request returns a distinct success indicator, a race
        condition is likely.
        """
        headers = {
            **self._evasion.build_headers(),
            "Content-Type": "application/json",
        }

        async def _single() -> Tuple[int, str]:
            start = time.monotonic()
            async with session.request(
                method, url, json=body, headers=headers
            ) as r:
                text = await r.text()
                return r.status, text

        tasks = [asyncio.create_task(_single()) for _ in range(burst)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successes = [
            r for r in results
            if isinstance(r, tuple) and r[0] in (200, 201)
        ]
        if len(successes) > 1:
            self._record(
                ScanResult(
                    vuln_type="Race Condition",
                    url=url,
                    method=method,
                    details=(
                        f"{len(successes)}/{burst} concurrent requests succeeded "
                        "simultaneously. Investigate for double-spend or duplicate "
                        "resource creation."
                    ),
                    evidence={
                        "burst_size": burst,
                        "success_count": len(successes),
                    },
                    severity="High",
                )
            )

    # ------------------------------------------------------------------
    # IDOR State Machine
    # ------------------------------------------------------------------

    async def _check_idor_state_machine(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        body: Dict[str, Any],
    ) -> None:
        """
        Replay the endpoint across every registered auth context and
        compare responses.  A 200-class response from a *lower-privilege*
        context that matches a *higher-privilege* baseline is flagged as
        Broken Access Control / IDOR.
        """
        if not self._contexts:
            return

        responses: List[Tuple[AuthContext, int, str]] = []
        for ctx in self._contexts:
            headers = {
                **self._evasion.build_headers(),
                **ctx.headers,
                "Content-Type": "application/json",
            }
            try:
                async with session.request(
                    method, url, json=body, headers=headers
                ) as resp:
                    text = await resp.text()
                    responses.append((ctx, resp.status, text))
                    logger.debug(
                        "IDOR probe [%s] %s %s -> %d",
                        ctx.name, method, url, resp.status,
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.debug(
                    "IDOR probe error [%s] %s: %s", ctx.name, url, exc
                )

        self._analyse_idor_responses(url, method, responses)

    def _analyse_idor_responses(
        self,
        url: str,
        method: str,
        responses: List[Tuple[AuthContext, int, str]],
    ) -> None:
        """
        Compare response bodies across contexts.

        Logic:
          1. Identify the admin/highest-privilege baseline.
          2. If a lower-privilege context returns the *same* 2xx status AND
             substantially similar body length, flag as BAC/IDOR.
          3. If an unauthenticated context returns 2xx, flag as missing auth.
        """
        if not responses:
            return

        # Determine the privileged baseline (last context is treated as highest)
        baseline_ctx, baseline_status, baseline_body = responses[-1]

        for ctx, status, body in responses[:-1]:
            if status in range(200, 300) and baseline_status in range(200, 300):
                # Length similarity heuristic (within 20 %)
                len_b = len(body)
                len_base = len(baseline_body)
                if len_base > 0:
                    ratio = len_b / len_base
                else:
                    ratio = 1.0 if len_b == 0 else 0.0

                if 0.8 <= ratio <= 1.2:
                    severity = "Critical" if ctx.token is None else "High"
                    self._record(
                        ScanResult(
                            vuln_type="Broken Access Control / IDOR",
                            url=url,
                            method=method,
                            details=(
                                f"Context '{ctx.name}' received a {status} response "
                                f"similar to '{baseline_ctx.name}' ({baseline_status}). "
                                "Possible IDOR or missing authorisation check."
                            ),
                            evidence={
                                "privileged_context": baseline_ctx.name,
                                "tested_context": ctx.name,
                                "privileged_status": baseline_status,
                                "tested_status": status,
                                "body_length_ratio": round(ratio, 3),
                            },
                            severity=severity,
                        )
                    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _record(self, result: ScanResult) -> None:
        self._findings.append(result)
        logger.warning(
            "[%s] %s — %s %s",
            result.severity,
            result.vuln_type,
            result.method,
            result.url,
        )
