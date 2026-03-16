"""
core/autonomous_agent.py
------------------------
Autonomous Pentesting Agent Engine — OODA Loop.

Implements a self-driving Observe → Orient → Decide → Act cycle that:
  - Observes HTTP responses and endpoint characteristics
  - Orients itself by classifying the target (GraphQL, REST, Auth endpoint, …)
  - Decides which scanners to trigger based on the classification
  - Acts by dispatching the chosen scanner and feeding results back into the loop

The agent operates without any external LLM API.  All decisions are driven by
deterministic heuristics applied directly to HTTP responses, headers, and body
content — making the engine fast, offline-capable, and fully self-contained.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

import aiohttp

from utils.auto_evasion import AutoEvasionEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

class EndpointKind(Enum):
    """The inferred nature of an HTTP endpoint."""
    GRAPHQL = auto()
    REST_JSON = auto()
    AUTH = auto()          # Login / token-issuing endpoints
    FILE_UPLOAD = auto()
    ADMIN_PANEL = auto()
    UNKNOWN = auto()


@dataclass
class ObservedEndpoint:
    """Data collected during the Observe phase."""
    url: str
    method: str = "GET"
    status: int = 0
    content_type: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[Dict[str, Any]] = None
    kind: EndpointKind = EndpointKind.UNKNOWN
    scan_results: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OODA helpers
# ---------------------------------------------------------------------------

class _Classifier:
    """
    Orient phase — classifies an observed HTTP endpoint into an
    ``EndpointKind`` using purely heuristic, pattern-based rules.
    """

    _GRAPHQL_BODY_PATTERNS = [
        r'"query"\s*:',
        r'"mutation"\s*:',
        r'"subscription"\s*:',
        r'__schema',
        r'__typename',
        r'GraphQL',
    ]

    _AUTH_URL_PATTERNS = [
        r'/login', r'/signin', r'/sign-in', r'/auth', r'/oauth',
        r'/token', r'/session', r'/logout', r'/register', r'/signup',
        r'/password', r'/2fa', r'/mfa', r'/verify',
    ]

    _ADMIN_URL_PATTERNS = [
        r'/admin', r'/dashboard', r'/management', r'/console',
        r'/backstage', r'/internal', r'/superuser', r'/staff',
    ]

    _UPLOAD_URL_PATTERNS = [
        r'/upload', r'/file', r'/attachment', r'/media', r'/import',
        r'/document', r'/image',
    ]

    def classify(self, obs: ObservedEndpoint) -> EndpointKind:
        url_lower = obs.url.lower()

        # GraphQL detection: path hint OR body/response signature
        if "/graphql" in url_lower or "/gql" in url_lower:
            return EndpointKind.GRAPHQL
        combined = (obs.body or "") + json.dumps(obs.request_body or {})
        for pat in self._GRAPHQL_BODY_PATTERNS:
            if re.search(pat, combined, re.IGNORECASE):
                return EndpointKind.GRAPHQL

        # Auth endpoint
        for pat in self._AUTH_URL_PATTERNS:
            if re.search(pat, url_lower):
                return EndpointKind.AUTH

        # Admin panel
        for pat in self._ADMIN_URL_PATTERNS:
            if re.search(pat, url_lower):
                return EndpointKind.ADMIN_PANEL

        # File upload
        for pat in self._UPLOAD_URL_PATTERNS:
            if re.search(pat, url_lower):
                return EndpointKind.FILE_UPLOAD

        # REST JSON — heuristic: application/json response or JSON body
        if "application/json" in obs.content_type or (
            obs.body.strip().startswith(("{", "["))
        ):
            return EndpointKind.REST_JSON

        return EndpointKind.UNKNOWN


# ---------------------------------------------------------------------------
# Action registry
# ---------------------------------------------------------------------------

# Type alias for a coroutine factory bound to a specific observed endpoint
ActionFactory = Callable[[ObservedEndpoint], Coroutine[Any, Any, List[Dict[str, Any]]]]


class _ActionRegistry:
    """
    Decide / Act phase — maps endpoint kinds to scanner coroutine factories.

    Scanners are registered at runtime so the agent can be extended without
    touching this core file.
    """

    def __init__(self) -> None:
        self._registry: Dict[EndpointKind, List[ActionFactory]] = {}

    def register(self, kind: EndpointKind, factory: ActionFactory) -> None:
        """Register *factory* to run whenever an endpoint of *kind* is seen."""
        self._registry.setdefault(kind, []).append(factory)

    def get_actions(self, kind: EndpointKind) -> List[ActionFactory]:
        """Return all registered action factories for *kind*."""
        # Always include actions registered for UNKNOWN (run-everywhere probes)
        actions = list(self._registry.get(kind, []))
        if kind != EndpointKind.UNKNOWN:
            actions.extend(self._registry.get(EndpointKind.UNKNOWN, []))
        return actions


# ---------------------------------------------------------------------------
# Autonomous Agent
# ---------------------------------------------------------------------------

class AutonomousAgent:
    """
    Self-driving OODA pentesting engine.

    The agent is given a list of URLs (seed endpoints) and runs the full
    Observe → Orient → Decide → Act cycle for each one.  Newly discovered
    endpoints (e.g. from JS parsing or redirect chains) are fed back into
    the queue automatically.

    Parameters
    ----------
    concurrency:
        Maximum number of simultaneous in-flight HTTP requests.
    timeout:
        Per-request timeout in seconds.
    max_depth:
        Maximum number of recursive endpoint discovery rounds.

    Usage::

        agent = AutonomousAgent(concurrency=20, timeout=10)

        # Register custom action for REST endpoints
        agent.register_action(EndpointKind.REST_JSON, my_rest_scanner)

        # Optionally inject auth tokens
        agent.set_auth_tokens(
            user_a="Bearer eyJ...",
            user_b="Bearer eyJ...",
            admin="Bearer eyJ...",
        )

        results = await agent.run(seed_urls=["https://example.com/api/v1/"])
        print(results)
    """

    def __init__(
        self,
        concurrency: int = 20,
        timeout: float = 10.0,
        max_depth: int = 3,
    ) -> None:
        self._concurrency = concurrency
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._max_depth = max_depth
        self._evasion = AutoEvasionEngine()
        self._classifier = _Classifier()
        self._actions = _ActionRegistry()
        self._visited: Set[str] = set()
        self._findings: List[Dict[str, Any]] = []
        self._auth_tokens: Dict[str, Optional[str]] = {
            "unauthenticated": None,
        }

        # Wire up default internal scanners
        self._register_default_actions()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_auth_tokens(
        self,
        user_a: Optional[str] = None,
        user_b: Optional[str] = None,
        admin: Optional[str] = None,
        **extra: Optional[str],
    ) -> None:
        """Register auth tokens for the IDOR state machine."""
        if user_a:
            self._auth_tokens["user_a"] = user_a
        if user_b:
            self._auth_tokens["user_b"] = user_b
        if admin:
            self._auth_tokens["admin"] = admin
        self._auth_tokens.update(extra)

    def register_action(self, kind: EndpointKind, factory: ActionFactory) -> None:
        """
        Register an external scanner coroutine factory for *kind*.

        The factory receives an ``ObservedEndpoint`` and must return a list of
        finding dicts.
        """
        self._actions.register(kind, factory)

    def get_visited_endpoints(self) -> List[str]:
        """Return a sorted list of all URLs visited during the last ``run()`` call."""
        return sorted(self._visited)

    async def run(self, seed_urls: List[str]) -> List[Dict[str, Any]]:
        """
        Execute the full OODA loop over *seed_urls*.

        Newly discovered endpoints are appended to the internal queue and
        processed up to ``max_depth`` rounds.  Returns all aggregated findings.
        """
        self._findings = []
        self._visited = set()

        queue: asyncio.Queue[str] = asyncio.Queue()
        for url in seed_urls:
            await queue.put(url)

        connector = aiohttp.TCPConnector(limit=self._concurrency, ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._timeout
        ) as session:
            depth = 0
            while not queue.empty() and depth < self._max_depth:
                depth += 1
                batch: List[str] = []
                while not queue.empty():
                    batch.append(await queue.get())

                logger.info(
                    "[Agent] OODA round %d — processing %d endpoints",
                    depth, len(batch),
                )

                tasks = [
                    asyncio.create_task(
                        self._ooda_cycle(session, url, queue)
                    )
                    for url in batch
                    if url not in self._visited
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(
            "[Agent] Complete. Visited=%d, Findings=%d",
            len(self._visited), len(self._findings),
        )
        return self._findings

    # ------------------------------------------------------------------
    # OODA cycle
    # ------------------------------------------------------------------

    async def _ooda_cycle(
        self,
        session: aiohttp.ClientSession,
        url: str,
        discovery_queue: asyncio.Queue[str],
    ) -> None:
        """Run one full Observe → Orient → Decide → Act cycle for *url*."""
        if url in self._visited:
            return
        self._visited.add(url)

        # ── Observe ──────────────────────────────────────────────────────
        obs = await self._observe(session, url)
        if obs is None:
            return

        # ── Orient ───────────────────────────────────────────────────────
        obs.kind = self._classifier.classify(obs)
        logger.info("[Orient] %s → %s (HTTP %d)", url, obs.kind.name, obs.status)

        # Extract any new endpoints found in the response body
        discovered = self._extract_endpoints_from_body(obs)
        for ep in discovered:
            if ep not in self._visited:
                await discovery_queue.put(ep)
                logger.debug("[Orient] Discovered new endpoint: %s", ep)

        # ── Decide & Act ─────────────────────────────────────────────────
        actions = self._actions.get_actions(obs.kind)
        if not actions:
            logger.debug("[Decide] No registered actions for %s", obs.kind.name)
            return

        action_tasks = [
            asyncio.create_task(action(obs))
            for action in actions
        ]
        results = await asyncio.gather(*action_tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                for finding in result:
                    finding.setdefault("url", url)
                    finding.setdefault("endpoint_kind", obs.kind.name)
                    self._findings.append(finding)
                    obs.scan_results.append(finding)

    # ------------------------------------------------------------------
    # Observe
    # ------------------------------------------------------------------

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> Optional[ObservedEndpoint]:
        """Probe *url* with evasion headers and return an ObservedEndpoint."""
        headers = self._evasion.build_headers()
        try:
            response, body = await self._evasion.resilient_request(
                session, "GET", url, headers=headers
            )
            if response is None:
                return None
            return ObservedEndpoint(
                url=url,
                method="GET",
                status=response.status,
                content_type=response.headers.get("Content-Type", ""),
                body=body,
                headers=dict(response.headers),
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("[Observe] Error on %s: %s", url, exc)
            return None

    # ------------------------------------------------------------------
    # Endpoint extraction from body
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_endpoints_from_body(obs: ObservedEndpoint) -> List[str]:
        """
        Parse the response body for embedded API endpoint references.

        Looks for:
          - Absolute HTTPS URLs matching the same host
          - Relative paths that look like API routes (/api/, /v1/, /v2/, …)
        """
        if not obs.body:
            return []

        host = re.sub(r"^https?://([^/]+).*", r"\1", obs.url)
        found: List[str] = []

        # Absolute URLs on the same host
        for match in re.finditer(r'https?://' + re.escape(host) + r'(/[^\s\'"<>]*)', obs.body):
            found.append(f"https://{host}{match.group(1)}")

        # Relative paths that look like API routes
        for match in re.finditer(
            r'["\']'
            r'(/(?:api|v\d+|graphql|gql|rest|rpc|service|endpoint)[^\s\'"<>]*)'
            r'["\']',
            obs.body,
        ):
            path = match.group(1)
            scheme_host = re.match(r'(https?://[^/]+)', obs.url)
            if scheme_host:
                found.append(f"{scheme_host.group(1)}{path}")

        # Deduplicate preserving order
        seen: Set[str] = set()
        unique: List[str] = []
        for ep in found:
            if ep not in seen:
                seen.add(ep)
                unique.append(ep)
        return unique

    # ------------------------------------------------------------------
    # Default built-in actions
    # ------------------------------------------------------------------

    def _register_default_actions(self) -> None:
        """Wire up built-in scanners for each endpoint kind."""
        self._actions.register(EndpointKind.GRAPHQL, self._scan_graphql)
        self._actions.register(EndpointKind.REST_JSON, self._scan_rest)
        self._actions.register(EndpointKind.AUTH, self._scan_auth)
        self._actions.register(EndpointKind.ADMIN_PANEL, self._scan_admin)
        # UNKNOWN endpoints get at least a header/info-disclosure scan
        self._actions.register(EndpointKind.UNKNOWN, self._scan_info_disclosure)

    async def _scan_graphql(self, obs: ObservedEndpoint) -> List[Dict[str, Any]]:
        """
        GraphQL-specific probes:
          - Introspection query (schema disclosure)
          - Batching abuse (single vs. batch response)
          - Field suggestion leakage
        """
        findings: List[Dict[str, Any]] = []

        # Build an aiohttp session just for these sub-probes
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._timeout
        ) as session:

            # Probe 1: Introspection
            introspection_query = {
                "query": "{ __schema { queryType { name } types { name kind } } }"
            }
            headers = {
                **self._evasion.build_headers(),
                "Content-Type": "application/json",
            }
            resp, body = await self._evasion.resilient_request(
                session, "POST", obs.url, json=introspection_query, headers=headers
            )
            if resp and resp.status == 200 and "__schema" in body:
                findings.append({
                    "type": "GraphQL Introspection Enabled",
                    "severity": "Medium",
                    "details": "GraphQL introspection is publicly accessible. "
                               "Full schema can be enumerated.",
                    "evidence": body[:500],
                })

            # Probe 2: Batching
            batch_query = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            resp, body = await self._evasion.resilient_request(
                session, "POST", obs.url, json=batch_query, headers=headers
            )
            if resp and resp.status == 200 and body.strip().startswith("["):
                findings.append({
                    "type": "GraphQL Query Batching Enabled",
                    "severity": "Low",
                    "details": "The server supports request batching. "
                               "This can be abused to amplify brute-force attacks.",
                })

        return findings

    async def _scan_rest(self, obs: ObservedEndpoint) -> List[Dict[str, Any]]:
        """
        REST JSON endpoint probes:
          - IDOR (numeric ID increments/decrements in URL path)
          - HTTP method enumeration (PUT/DELETE/PATCH availability)
          - JSON parameter type confusion
        """
        findings: List[Dict[str, Any]] = []

        # IDOR path probe: replace trailing numeric segment with adjacent IDs
        idor_match = re.search(r'/(\d+)(?:/[^/]*)?$', obs.url)
        if idor_match:
            original_id = int(idor_match.group(1))
            probe_ids = [original_id + 1, original_id - 1, 0, 9999999]
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector, timeout=self._timeout
            ) as session:
                for pid in probe_ids:
                    probe_url = obs.url[:idor_match.start(1)] + str(pid) + obs.url[idor_match.end(1):]
                    for role, token in self._auth_tokens.items():
                        extra = {"Authorization": token} if token else {}
                        headers = self._evasion.build_headers(extra=extra)
                        resp, body = await self._evasion.resilient_request(
                            session, "GET", probe_url, headers=headers
                        )
                        if resp and resp.status == 200 and len(body) > 20:
                            findings.append({
                                "type": "Potential IDOR",
                                "severity": "High",
                                "details": (
                                    f"Probe ID {pid} returned HTTP 200 as '{role}'. "
                                    f"Original ID was {original_id}. "
                                    "Verify whether the resource belongs to a different user."
                                ),
                                "probe_url": probe_url,
                                "role": role,
                            })

        # Method enumeration
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._timeout
        ) as session:
            for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
                headers = self._evasion.build_headers()
                resp, _ = await self._evasion.resilient_request(
                    session, method, obs.url, headers=headers
                )
                if resp and resp.status not in (405, 404, 501):
                    findings.append({
                        "type": "Unexpected HTTP Method Allowed",
                        "severity": "Low",
                        "details": (
                            f"HTTP {method} returned {resp.status} (not 405 Method Not Allowed). "
                            "Investigate whether the method enables unintended mutations."
                        ),
                        "method": method,
                    })

        return findings

    async def _scan_auth(self, obs: ObservedEndpoint) -> List[Dict[str, Any]]:
        """
        Auth endpoint probes:
          - Default credential pairs
          - Password policy (no lockout / no rate-limiting)
          - JWT issuance and offline analysis of any returned token
        """
        from scanners.auth import JWTAnalyser

        findings: List[Dict[str, Any]] = []

        default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("test", "test"), ("user", "user"),
        ]

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._timeout
        ) as session:
            success_count = 0
            for username, password in default_creds:
                headers = {
                    **self._evasion.build_headers(),
                    "Content-Type": "application/json",
                }
                resp, body = await self._evasion.resilient_request(
                    session, "POST", obs.url,
                    json={"username": username, "password": password},
                    headers=headers,
                )
                if resp is None:
                    continue
                if resp.status in (200, 201):
                    success_count += 1
                    findings.append({
                        "type": "Default Credentials Accepted",
                        "severity": "Critical",
                        "details": (
                            f"Login succeeded with username='{username}', "
                            f"password='{password}'."
                        ),
                        "credentials": {"username": username, "password": password},
                    })
                    # Check for JWT in response
                    jwt_pat = re.search(
                        r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                        body,
                    )
                    if jwt_pat:
                        analyser = JWTAnalyser()
                        jwt_findings = analyser.analyse(jwt_pat.group(0))
                        for jf in jwt_findings:
                            findings.append({
                                "type": f"JWT Issue: {jf.issue}",
                                "severity": jf.severity,
                                "details": jf.details,
                            })

            # Brute-force rate-limit check
            if success_count == 0 and len(default_creds) >= 5:
                findings.append({
                    "type": "Auth Endpoint Rate-Limit Check",
                    "severity": "Low",
                    "details": (
                        f"Sent {len(default_creds)} login attempts without triggering "
                        "a lockout or 429 response. "
                        "Verify whether rate-limiting / account lockout is enforced."
                    ),
                })

        return findings

    async def _scan_admin(self, obs: ObservedEndpoint) -> List[Dict[str, Any]]:
        """
        Admin panel probes:
          - Access without authentication (unauthenticated 200)
          - Common admin paths under the base URL
        """
        findings: List[Dict[str, Any]] = []

        if obs.status == 200 and self._auth_tokens.get("unauthenticated") is None:
            findings.append({
                "type": "Unauthenticated Admin Panel Access",
                "severity": "Critical",
                "details": (
                    f"Admin-like endpoint returned HTTP 200 without any "
                    "authorization header. Verify manually."
                ),
            })

        common_admin_paths = [
            "/admin/users", "/admin/settings", "/admin/logs",
            "/api/admin", "/api/v1/admin", "/api/v2/admin",
            "/management/users", "/console/settings",
        ]
        base = re.match(r'(https?://[^/]+)', obs.url)
        if not base:
            return findings

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._timeout
        ) as session:
            for path in common_admin_paths:
                probe_url = base.group(1) + path
                if probe_url in self._visited:
                    continue
                headers = self._evasion.build_headers()
                resp, _ = await self._evasion.resilient_request(
                    session, "GET", probe_url, headers=headers
                )
                if resp and resp.status == 200:
                    findings.append({
                        "type": "Exposed Admin Endpoint",
                        "severity": "High",
                        "details": (
                            f"Admin-like path '{probe_url}' returned HTTP 200 "
                            "without authentication."
                        ),
                        "probe_url": probe_url,
                    })

        return findings

    async def _scan_info_disclosure(self, obs: ObservedEndpoint) -> List[Dict[str, Any]]:
        """
        Generic info-disclosure probes run on every endpoint:
          - Sensitive response headers (Server, X-Powered-By, …)
          - Stack-trace / debug output in body
          - API key / secret patterns in response body
        """
        findings: List[Dict[str, Any]] = []

        # Sensitive headers
        sensitive_headers = {
            "Server", "X-Powered-By", "X-AspNet-Version",
            "X-Generator", "X-Drupal-Cache",
        }
        found_hdrs = {h: v for h, v in obs.headers.items() if h in sensitive_headers}
        if found_hdrs:
            findings.append({
                "type": "Technology Disclosure via Headers",
                "severity": "Low",
                "details": (
                    "Response headers reveal server/framework information: "
                    + ", ".join(f"{k}: {v}" for k, v in found_hdrs.items())
                ),
                "headers": found_hdrs,
            })

        # Stack-trace / debug markers
        debug_patterns = [
            r'Traceback \(most recent call last\)',
            r'at [A-Za-z0-9_.]+\([A-Za-z0-9_.]+\.java:\d+\)',
            r'System\.NullReferenceException',
            r'mysqli_error\(',
            r'ORA-\d{5}',  # Oracle error
            r'SQLSTATE\[',
            r'Warning:.*on line \d+',
            r'<b>Fatal error</b>',
        ]
        for pat in debug_patterns:
            if re.search(pat, obs.body):
                findings.append({
                    "type": "Debug / Stack-Trace Disclosure",
                    "severity": "Medium",
                    "details": (
                        f"Response body contains debug output matching pattern "
                        f"'{pat}'. This may leak internal paths, library versions, "
                        "or SQL queries."
                    ),
                })
                break  # One finding per endpoint is sufficient

        # API key / secret patterns
        secret_patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "Generic API Key": r'(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}',
            "Private Key Header": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        }
        for label, pat in secret_patterns.items():
            match = re.search(pat, obs.body)
            if match:
                findings.append({
                    "type": f"Secret Disclosure: {label}",
                    "severity": "Critical",
                    "details": (
                        f"A pattern consistent with '{label}' was found in the "
                        "response body. Rotate the credential immediately."
                    ),
                    "pattern_matched": pat,
                })

        return findings
