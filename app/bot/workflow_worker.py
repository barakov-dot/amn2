"""One thread owns the workflow resource; the event loop owns its bounded FIFO."""
from __future__ import annotations

import asyncio
import contextvars
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal, Protocol


class SyncWorkflowResource(Protocol):
    def invoke(self, method: str, args: tuple, kwargs: dict) -> object: ...
    def close(self) -> None: ...


class WorkflowBusy(RuntimeError):
    pass


class WorkflowClosed(RuntimeError):
    pass


@dataclass(frozen=True)
class JobOutcome:
    method: str
    status: Literal['success', 'error', 'partial']


@dataclass(eq=False)
class _Job:
    method: str
    args: tuple
    kwargs: dict
    context: contextvars.Context
    waiter: asyncio.Future
    state: str = 'QUEUED'
    released: bool = False


class WorkflowWorker:
    def __init__(
        self, factory: Callable[[], SyncWorkflowResource], *,
        allowed_methods: frozenset[str], capacity: int = 8,
        outcome_sink: Callable[[JobOutcome], None] | None = None,
        error_status: Callable[[BaseException], Literal['error', 'partial']] | None = None,
    ) -> None:
        if capacity <= 0:
            raise ValueError('capacity must be positive')
        self._factory = factory
        self._allowed = allowed_methods
        self._capacity = capacity
        self._sink = outcome_sink
        self._error_status = error_status
        self._state = 'NEW'
        self._queued: deque[_Job] = deque()
        self._outstanding = 0
        self._wake = asyncio.Event()
        self._executor: ThreadPoolExecutor | None = None
        self._resource: SyncWorkflowResource | None = None
        self._starting: asyncio.Task | None = None
        self._pump_task: asyncio.Task | None = None
        self._closing: asyncio.Task | None = None

    async def start(self) -> None:
        if self._state != 'NEW':
            raise WorkflowClosed('Workflow start is only allowed once')
        self._state = 'OPEN'
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='bot-workflow')
        self._starting = asyncio.create_task(self._open_resource())
        await asyncio.shield(self._starting)

    async def _open_resource(self) -> None:
        if self._state != 'OPEN':
            raise WorkflowClosed('Workflow closed before factory dispatch')
        self._resource = await asyncio.get_running_loop().run_in_executor(self._executor, self._factory)
        self._pump_task = asyncio.create_task(self._pump())

    async def call(self, method: str, /, *args, **kwargs) -> object:
        if method not in self._allowed:
            raise ValueError('Unknown workflow method')
        if self._state != 'OPEN' or self._resource is None:
            raise WorkflowClosed('Workflow is not accepting jobs')
        if self._outstanding >= self._capacity:
            raise WorkflowBusy('Workflow capacity reached')
        job = _Job(method, args, dict(kwargs), contextvars.copy_context(), asyncio.get_running_loop().create_future())
        self._queued.append(job)
        self._outstanding += 1
        self._wake.set()
        try:
            return await job.waiter
        except asyncio.CancelledError:
            if job.state == 'QUEUED':
                self._queued.remove(job)
                job.state = 'TERMINAL'
                self._release_slot(job)
            if job.waiter.done() and not job.waiter.cancelled():
                job.waiter.exception()
            raise

    def _release_slot(self, job: _Job) -> None:
        assert not job.released
        job.released = True
        self._outstanding -= 1

    def _observe(self, job: _Job, error: BaseException | None) -> None:
        status = 'success'
        if error is not None:
            status = 'error'
            if self._error_status is not None:
                try:
                    if self._error_status(error) == 'partial':
                        status = 'partial'
                except BaseException:
                    pass
        if self._sink is not None:
            try:
                self._sink(JobOutcome(job.method, status))
            except BaseException:
                pass

    async def _pump(self) -> None:
        while True:
            if not self._queued:
                if self._state == 'CLOSING':
                    return
                self._wake.clear()
                await self._wake.wait()
                continue
            job = self._queued.popleft()
            # Task.cancel() cancels the waiter synchronously, but the caller's
            # cancellation handler may run after this pump has been awakened.
            if job.waiter.cancelled():
                job.state = 'TERMINAL'
                self._release_slot(job)
                continue
            job.state = 'DISPATCHED'
            error = None
            try:
                future = asyncio.get_running_loop().run_in_executor(
                    self._executor, job.context.run, self._resource.invoke,
                    job.method, job.args, job.kwargs,
                )
                result = await asyncio.shield(future)
            except BaseException as exc:
                error = exc
                if not job.waiter.done():
                    job.waiter.set_exception(exc)
            else:
                if not job.waiter.done():
                    job.waiter.set_result(result)
            finally:
                job.state = 'TERMINAL'
                self._release_slot(job)
                self._observe(job, error)

    async def aclose(self) -> None:
        if self._closing is None:
            self._state = 'CLOSING'
            self._wake.set()
            self._closing = asyncio.create_task(self._close())
        await asyncio.shield(self._closing)

    async def _close(self) -> None:
        try:
            if self._starting is not None:
                try:
                    await self._starting
                except BaseException:
                    # The startup waiter owns this failure; cleanup still owns the executor.
                    pass
            if self._pump_task is not None:
                await self._pump_task
            if self._resource is not None:
                await asyncio.get_running_loop().run_in_executor(self._executor, self._resource.close)
        finally:
            try:
                if self._executor is not None:
                    await asyncio.to_thread(self._executor.shutdown, wait=True)
            finally:
                self._state = 'CLOSED'
