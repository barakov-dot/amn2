"""One process-scoped signal owner; accepted workflow cleanup stays in the runtime."""
from __future__ import annotations

import asyncio
import signal
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class StopController:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._attached_once = False
        self._detached = False
        self._pending = False
        self._requested = False
        self._task: asyncio.Task | None = None
        self._cancel_target: asyncio.Task | None = None
        self._close_admission: Callable[[], None] | None = None
        self._owner_notified = False
        self._cleaning = False
        self._cancel_token = object()
        self._cancel_sent = False
        self._external_cancel_seen = False
        self._failure: BaseException | None = None

    @property
    def requested(self) -> bool:
        return self._requested

    @property
    def failure(self) -> BaseException | None:
        return self._failure

    def notify_signal(self) -> None:
        if self._detached:
            return
        loop = self._loop
        if loop is None:
            self._pending = True
        else:
            loop.call_soon_threadsafe(self._deliver_if_attached)

    def _deliver_if_attached(self) -> None:
        if self._loop is not None and not self._detached:
            self.request_stop()

    def attach(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._attached_once or loop is not asyncio.get_running_loop():
            raise RuntimeError('Stop controller needs one owning loop')
        self._attached_once = True
        self._loop = loop
        if self._pending:
            self.request_stop()

    def detach(self) -> None:
        self._detached = True
        self._loop = None
        self._task = None
        self._close_admission = None

    def _require_loop(self) -> None:
        if self._loop is None or self._loop is not asyncio.get_running_loop():
            raise RuntimeError('Stop transition requires its owning loop')

    def request_stop(self) -> None:
        self._require_loop()
        if self._requested:
            return
        self._requested = True
        self._notify_owner()

    def _notify_owner(self) -> None:
        if self._task is None or self._owner_notified:
            return
        self._owner_notified = True
        try:
            if self._close_admission is not None:
                self._close_admission()
        except BaseException as exc:
            self._failure = exc
        finally:
            if not self._cleaning and not self._task.done():
                self._external_cancel_seen = self._task.cancelling() != 0
                self._cancel_target = self._task
                self._cancel_sent = self._task.cancel(self._cancel_token)

    @contextmanager
    def bind(self, task: asyncio.Task, close_admission: Callable[[], None]) -> Iterator[None]:
        self._require_loop()
        if self._task is not None or self._cancel_target is not None:
            raise RuntimeError('Stop controller already owns a runtime')
        self._task = task
        self._close_admission = close_admission
        try:
            if self._requested:
                self._notify_owner()
            yield
        finally:
            self._task = None
            self._close_admission = None

    def begin_cleanup(self) -> None:
        self._require_loop()
        self._cleaning = True

    def raise_if_requested(self) -> None:
        self._require_loop()
        if self._requested:
            raise asyncio.CancelledError(self._cancel_token)

    def owns_cancellation(self, exc: asyncio.CancelledError, task: asyncio.Task) -> bool:
        if len(exc.args) != 1 or exc.args[0] is not self._cancel_token:
            return False
        if self._external_cancel_seen:
            return False
        if self._cancel_sent:
            return self._cancel_target is task and task.cancelling() == 1
        return task.cancelling() == 0


class ProcessSignalScope:
    """Restore prior handlers even if installation or another restoration fails."""

    def __init__(self, controller: StopController, *,
                 get_handler=signal.getsignal, set_handler=signal.signal) -> None:
        self._controller = controller
        self._get = get_handler
        self._set = set_handler
        self._previous: list[tuple[signal.Signals, object]] = []

    def _handle(self, signum, frame) -> None:
        self._controller.notify_signal()

    def _restore(self) -> list[BaseException]:
        errors = []
        while self._previous:
            signum, previous = self._previous.pop()
            try:
                self._set(signum, previous)
            except BaseException as exc:
                errors.append(exc)
        return errors

    def __enter__(self) -> ProcessSignalScope:
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous = self._get(signum)
                self._set(signum, self._handle)
                self._previous.append((signum, previous))
        except BaseException as exc:
            errors = self._restore()
            if errors:
                raise BaseExceptionGroup('Signal installation and restoration failed', [exc, *errors]) from None
            raise
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        errors = self._restore()
        if errors:
            raise BaseExceptionGroup('Signal restoration failed', ([exc] if exc is not None else []) + errors) from None
        return False
