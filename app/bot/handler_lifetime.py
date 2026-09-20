"""Own accepted handler tasks until delivery and workflow work have finished."""
from __future__ import annotations

import asyncio
import contextvars
import logging
from collections.abc import Awaitable, Callable
from typing import TypeVar

from aiogram import BaseMiddleware

from app.bot.workflow_worker import WorkflowBusy, WorkflowClosed

T = TypeVar('T')
logger = logging.getLogger(__name__)


class HandlerLifetime:
    def __init__(self, *, limit: int = 8) -> None:
        if limit <= 0:
            raise ValueError('handler limit must be positive')
        self._limit = limit
        self._closing = False
        self._tasks: set[asyncio.Task] = set()
        self._tickets: dict[object, asyncio.Task] = {}
        self._ticket = contextvars.ContextVar('bot_handler_ticket', default=None)

    async def run(self, handler: Callable[[], Awaitable[T]]) -> T:
        if self._closing:
            raise WorkflowClosed('Handler admission is closed')
        if len(self._tasks) >= self._limit:
            raise WorkflowBusy('Handler capacity reached')
        ticket = object()

        async def owned():
            token = self._ticket.set(ticket)
            try:
                return await handler()
            finally:
                self._ticket.reset(token)

        task = asyncio.create_task(owned())
        self._tasks.add(task)
        self._tickets[ticket] = task
        task.add_done_callback(lambda done: self._on_done(ticket, done))
        return await asyncio.shield(task)

    def _on_done(self, ticket: object, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        self._tickets.pop(ticket, None)
        if not task.cancelled() and task.exception() is not None:
            logger.warning('bot_handler_failed')

    def require_active(self) -> None:
        task = self._tickets.get(self._ticket.get())
        if task is None or task is not asyncio.current_task() or task.done():
            raise WorkflowClosed('No active owned handler')

    def begin_shutdown(self) -> None:
        self._closing = True

    async def drain(self) -> None:
        self.begin_shutdown()
        while self._tasks:
            # A caller cancelling drain must not cancel accepted handlers.
            await asyncio.shield(asyncio.gather(*self._tasks, return_exceptions=True))


class WorkflowLifetimeMiddleware(BaseMiddleware):
    def __init__(self, owner: HandlerLifetime) -> None:
        self._owner = owner

    async def __call__(self, handler, event, data):
        return await self._owner.run(lambda: handler(event, data))


async def await_owned_cleanup(cleanup: Awaitable[None]) -> None:
    async def finish():
        await cleanup

    owned = asyncio.create_task(finish())
    cancelled = False
    while not owned.done():
        try:
            await asyncio.shield(owned)
        except asyncio.CancelledError:
            cancelled = True
    owned.result()
    if cancelled:
        raise asyncio.CancelledError()
