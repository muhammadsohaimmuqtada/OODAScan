"""
core/orchestrator.py
--------------------
Asynchronous task orchestrator for the Advanced BB Toolkit.

Manages the full lifecycle of a bug-bounty hunt:
  - Queues and dispatches recon, scanning, and reporting tasks
  - Tracks discovered endpoints, parameters, and auth roles in memory
  - Provides clean start/stop semantics and graceful error recovery
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
