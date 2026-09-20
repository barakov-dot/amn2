import asyncio
import contextvars

import pytest

from app.bot.handler_lifetime import HandlerLifetime, WorkflowLifetimeMiddleware, await_owned_cleanup
from app.bot.workflow_worker import WorkflowBusy, WorkflowClosed


def test_parent_cancel_keeps_delivery_alive_until_record_and_drain():
    async def scenario():
        owner = HandlerLifetime()
        sent, allow_record = asyncio.Event(), asyncio.Event()
        events = []

        async def delivery(event, data):
            owner.require_active()
            events.append('sent')
            sent.set()
            await allow_record.wait()
            owner.require_active()
            events.append('recorded')

        middleware = WorkflowLifetimeMiddleware(owner)
        parent = asyncio.create_task(middleware(delivery, object(), {}))
        await sent.wait()
        parent.cancel()
        with pytest.raises(asyncio.CancelledError):
            await parent
        owner.begin_shutdown()
        drain = asyncio.create_task(owner.drain())
        try:
            with pytest.raises(WorkflowClosed):
                await owner.run(lambda: delivery(None, {}))
            await asyncio.sleep(0)
            assert not drain.done()
            allow_record.set()
            await asyncio.wait_for(drain, 1)
            assert events == ['sent', 'recorded']
        finally:
            allow_record.set()
            await owner.drain()
        owner.begin_shutdown()
        await owner.drain()
    asyncio.run(scenario())


def test_capacity_and_forked_or_stale_ticket_cannot_admit_jobs():
    async def scenario():
        owner = HandlerLifetime()
        gate = asyncio.Event()
        entered = 0
        contexts = []

        async def child():
            with pytest.raises(WorkflowClosed):
                owner.require_active()

        async def handler():
            nonlocal entered
            owner.require_active()
            contexts.append(contextvars.copy_context())
            await asyncio.create_task(child())
            entered += 1
            await gate.wait()

        parents = [asyncio.create_task(owner.run(handler)) for _ in range(8)]
        try:
            for _ in range(20):
                await asyncio.sleep(0)
                if entered == 8:
                    break
            assert entered == 8
            with pytest.raises(WorkflowBusy):
                await owner.run(handler)
            with pytest.raises(WorkflowClosed):
                owner.require_active()
            owner.begin_shutdown()
            gate.set()
            await asyncio.gather(*parents)
            await owner.drain()
            for ctx in contexts:
                await asyncio.create_task(child(), context=ctx)
        finally:
            gate.set()
            await owner.drain()
    asyncio.run(scenario())


def test_orphan_failure_is_observed_without_secret_logging(caplog):
    async def scenario():
        owner = HandlerLifetime()
        entered, release = asyncio.Event(), asyncio.Event()

        async def handler():
            entered.set()
            await release.wait()
            raise ValueError('test-private-key-secret')

        parent = asyncio.create_task(owner.run(handler))
        await entered.wait()
        parent.cancel()
        with pytest.raises(asyncio.CancelledError):
            await parent
        release.set()
        await owner.drain()
    asyncio.run(scenario())
    assert 'test-private-key-secret' not in caplog.text
    assert 'bot_handler_failed' in caplog.text


def test_repeated_cancel_waits_for_owned_cleanup():
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        finished = []

        async def cleanup():
            entered.set()
            await release.wait()
            finished.append(True)

        parent = asyncio.create_task(await_owned_cleanup(cleanup()))
        await entered.wait()
        for _ in range(2):
            parent.cancel()
            await asyncio.sleep(0)
            assert not parent.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await parent
        assert finished == [True]
    asyncio.run(scenario())


def test_cleanup_failure_is_observed():
    async def scenario():
        async def cleanup():
            raise ValueError('cleanup failed')
        with pytest.raises(ValueError, match='cleanup failed'):
            await await_owned_cleanup(cleanup())
    asyncio.run(scenario())


@pytest.mark.parametrize('locale', ['ru', 'en'])
def test_middleware_partial_failure_is_safe_and_localized(locale, caplog):
    from types import SimpleNamespace
    from app.services.access import RemoteOperationPartialFailure

    async def scenario():
        owner = HandlerLifetime()
        middleware = WorkflowLifetimeMiddleware(owner)
        replies = []

        class Event:
            from_user = SimpleNamespace(language_code=locale)

            async def answer(self, value):
                replies.append(value)

        async def handler(event, data):
            raise RemoteOperationPartialFailure(
                SimpleNamespace(operation_id='revoke', recovery_note='private-sentinel'),
                ValueError('secret-cause'))

        await middleware(handler, Event(), {})
        await owner.drain()
        assert len(replies) == 1
        assert ('частично' if locale == 'ru' else 'partially') in replies[0]
        assert 'private-sentinel' not in replies[0] + caplog.text
        assert 'secret-cause' not in replies[0] + caplog.text
    asyncio.run(scenario())


def test_partial_reply_send_error_does_not_escape_with_secret_context(caplog):
    from types import SimpleNamespace
    from app.services.access import RemoteOperationPartialFailure

    async def scenario():
        owner = HandlerLifetime()

        class Event:
            async def answer(self, value):
                raise RuntimeError('transport-private-detail')

        async def handler(event, data):
            raise RemoteOperationPartialFailure(
                SimpleNamespace(operation_id='reset', recovery_note='partial-private-detail'),
                ValueError('secret-cause'))

        await WorkflowLifetimeMiddleware(owner)(handler, Event(), {})
        await owner.drain()
    asyncio.run(scenario())
    assert 'private-detail' not in caplog.text and 'secret-cause' not in caplog.text
    assert 'bot_safe_reply_failed' in caplog.text
