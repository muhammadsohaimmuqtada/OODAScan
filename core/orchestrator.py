"""
core/orchestrator.py
--------------------
Asynchronous task orchestrator for the Advanced BB Toolkit.

Manages the full lifecycle of a bug-bounty hunt:
  - Queues and dispatches recon, scanning, and reporting tasks
  - Tracks discovered endpoints, parameters, and auth roles in memory
  - Provides clean start/stop semantics and graceful error recovery
  - Instantiates the AutonomousAgent for fully self-driving operation
    when no manual endpoint list is provided
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class TaskStatus(Enum):
    PENDING = auto()
    RUNNING = auto()
    DONE = auto()
    FAILED = auto()


class TaskPriority(int, Enum):
    HIGH = 0
    NORMAL = 1
    LOW = 2


@dataclass(order=True)
class HuntTask:
    """A single unit of work managed by the orchestrator."""
    priority: TaskPriority
    name: str = field(compare=False)
    coro_factory: Callable[[], Coroutine[Any, Any, Any]] = field(compare=False)
    status: TaskStatus = field(default=TaskStatus.PENDING, compare=False)
    result: Any = field(default=None, compare=False)
    error: Optional[Exception] = field(default=None, compare=False)


@dataclass
class HuntState:
    """Shared, in-memory state for a single hunt session."""
    target: str
    endpoints: Set[str] = field(default_factory=set)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    roles: Dict[str, Optional[str]] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def add_endpoint(self, url: str) -> None:
        self.endpoints.add(url)
        logger.debug("Endpoint tracked: %s", url)

    def add_parameter(self, endpoint: str, param: str) -> None:
        self.parameters.setdefault(endpoint, [])
        if param not in self.parameters[endpoint]:
            self.parameters[endpoint].append(param)
            logger.debug("Parameter tracked: %s -> %s", endpoint, param)

    def add_role(self, role_name: str, token: Optional[str]) -> None:
        self.roles[role_name] = token
        logger.debug("Role registered: %s", role_name)

    def record_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)
        logger.info("Finding recorded: %s", finding.get("title", "unknown"))


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """
    Async task runner that manages the state of the hunt.

    Usage::

        orch = Orchestrator(target="https://example.com", concurrency=10)
        orch.state.add_role("unauthenticated", None)
        orch.state.add_role("user_a", "Bearer eyJ...")

        orch.enqueue(TaskPriority.HIGH, "cloud_recon", cloud_recon_factory)
        orch.enqueue(TaskPriority.NORMAL, "biz_logic_fuzz", biz_logic_factory)

        await orch.run()
        report = orch.get_report()
    """

    def __init__(self, target: str, concurrency: int = 10) -> None:
        self.state = HuntState(target=target)
        self._concurrency = concurrency
        self._queue: asyncio.PriorityQueue[HuntTask] = asyncio.PriorityQueue()
        self._tasks: List[HuntTask] = []
        self._semaphore: Optional[asyncio.Semaphore] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue(
        self,
        priority: TaskPriority,
        name: str,
        coro_factory: Callable[[], Coroutine[Any, Any, Any]],
    ) -> HuntTask:
        """Add a task to the work queue and return the task descriptor."""
        task = HuntTask(priority=priority, name=name, coro_factory=coro_factory)
        self._tasks.append(task)
        logger.debug("Enqueued task '%s' with priority %s", name, priority.name)
        return task

    async def run(self) -> None:
        """Drain the task list, respecting concurrency limits."""
        self._semaphore = asyncio.Semaphore(self._concurrency)

        # Load all registered tasks into the priority queue
        for task in self._tasks:
            await self._queue.put(task)

        workers = [
            asyncio.create_task(self._worker(), name=f"worker-{i}")
            for i in range(min(self._concurrency, len(self._tasks)))
        ]

        await self._queue.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        logger.info(
            "Hunt completed. Endpoints=%d, Findings=%d",
            len(self.state.endpoints),
            len(self.state.findings),
        )

    def get_report(self) -> Dict[str, Any]:
        """Return a structured summary of the current hunt state."""
        return {
            "target": self.state.target,
            "endpoints_discovered": sorted(self.state.endpoints),
            "parameters_discovered": self.state.parameters,
            "roles_tested": list(self.state.roles.keys()),
            "findings": self.state.findings,
            "task_summary": [
                {
                    "name": t.name,
                    "status": t.status.name,
                    "error": str(t.error) if t.error else None,
                }
                for t in self._tasks
            ],
        }

    # ------------------------------------------------------------------
    # Autonomous mode
    # ------------------------------------------------------------------

    def run_autonomous(
        self,
        seed_urls: Optional[List[str]] = None,
        use_crawler: bool = False,
        token_user_a: Optional[str] = None,
        token_user_b: Optional[str] = None,
        token_admin: Optional[str] = None,
    ) -> "Coroutine[Any, Any, Dict[str, Any]]":
        """
        Convenience entry-point that wires up the ``AutonomousAgent`` and
        optional ``AutoCrawler``, then runs the full self-driving OODA loop.

        Parameters
        ----------
        seed_urls:
            Initial URLs to feed the agent.  Defaults to ``[target]``.
        use_crawler:
            When True, run the headless ``AutoCrawler`` first and add its
            discovered endpoints to the seed list before starting the agent.
            Requires ``playwright`` to be installed.
        token_user_a / token_user_b / token_admin:
            Optional auth tokens for IDOR state-machine testing.

        Returns
        -------
        A coroutine that, when awaited, returns the full findings report dict.

        Usage::

            orch = Orchestrator(target="https://example.com")
            report = await orch.run_autonomous(
                token_user_a="Bearer eyJ...",
                token_admin="Bearer eyJ...",
                use_crawler=True,
            )
        """
        return self._autonomous_pipeline(
            seed_urls=seed_urls,
            use_crawler=use_crawler,
            token_user_a=token_user_a,
            token_user_b=token_user_b,
            token_admin=token_admin,
        )

    async def _autonomous_pipeline(
        self,
        seed_urls: Optional[List[str]],
        use_crawler: bool,
        token_user_a: Optional[str],
        token_user_b: Optional[str],
        token_admin: Optional[str],
    ) -> Dict[str, Any]:
        """Internal implementation of the autonomous pipeline."""
        # Import here to avoid circular imports at module load time
        from core.autonomous_agent import AutonomousAgent

        urls: List[str] = list(seed_urls) if seed_urls else [self.state.target]

        # ── Optional: auto-crawl with headless browser ─────────────────
        if use_crawler:
            try:
                from recon.auto_crawler import AutoCrawler
                logger.info("[Orchestrator] Starting AutoCrawler on %s", self.state.target)
                crawler = AutoCrawler()
                crawl_result = await crawler.crawl(self.state.target)
                crawled_endpoints = crawl_result.endpoint_list()
                logger.info(
                    "[Orchestrator] Crawler discovered %d endpoints",
                    len(crawled_endpoints),
                )
                urls = list({*urls, *crawled_endpoints})
                # Track in state and record any crawler secrets as findings
                for ep in crawled_endpoints:
                    self.state.add_endpoint(ep)
                for secret in crawl_result.secrets_found:
                    self.state.record_finding(secret)
            except ImportError:
                logger.warning(
                    "[Orchestrator] Playwright not installed — skipping auto-crawl. "
                    "Run: pip install playwright && playwright install chromium"
                )

        # ── Instantiate and configure the autonomous agent ─────────────
        agent = AutonomousAgent(concurrency=self._concurrency)
        agent.set_auth_tokens(
            user_a=token_user_a,
            user_b=token_user_b,
            admin=token_admin,
        )

        # Register tokens in shared state for cross-module visibility
        if token_user_a:
            self.state.add_role("user_a", token_user_a)
        if token_user_b:
            self.state.add_role("user_b", token_user_b)
        if token_admin:
            self.state.add_role("admin", token_admin)

        # ── Run the OODA loop ───────────────────────────────────────────
        logger.info(
            "[Orchestrator] Launching AutonomousAgent with %d seed URLs", len(urls)
        )
        agent_findings = await agent.run(seed_urls=urls)

        # ── Merge agent findings into shared hunt state ─────────────────
        for finding in agent_findings:
            self.state.record_finding(finding)
        for ep in agent.get_visited_endpoints():
            self.state.add_endpoint(ep)

        return self.get_report()

    # ------------------------------------------------------------------
    # Internal machinery
    # ------------------------------------------------------------------

    async def _worker(self) -> None:
        assert self._semaphore is not None
        while True:
            task = await self._queue.get()
            task.status = TaskStatus.RUNNING
            logger.info("Starting task '%s'", task.name)
            try:
                async with self._semaphore:
                    task.result = await task.coro_factory()
                task.status = TaskStatus.DONE
                logger.info("Task '%s' finished successfully", task.name)
            except asyncio.CancelledError:
                task.status = TaskStatus.FAILED
                task.error = asyncio.CancelledError("Task cancelled")
                raise
            except Exception as exc:  # pylint: disable=broad-except
                task.status = TaskStatus.FAILED
                task.error = exc
                logger.error("Task '%s' failed: %s", task.name, exc, exc_info=True)
            finally:
                self._queue.task_done()
