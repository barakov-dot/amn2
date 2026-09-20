import asyncio
import contextvars
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.bot.workflow_worker import WorkflowBusy, WorkflowClosed, WorkflowWorker


def test_sqlite_owned_by_worker_and_event_loop_remains_free():
    async def scenario():
        entered, release = threading.Event(), threading.Event()
        threads = []

        class Resource:
            def __init__(self):
                threads.append(threading.get_ident())
                self.conn = sqlite3.connect(':memory:')
                self.conn.execute('CREATE TABLE observations (value INTEGER)')

            def invoke(self, method, args, kwargs):
                threads.append(threading.get_ident())
                entered.set()
                assert release.wait(5)
                self.conn.execute('INSERT INTO observations VALUES (?)', args)
                self.conn.commit()
                return self.conn.execute('SELECT value FROM observations').fetchone()[0]

            def close(self):
                threads.append(threading.get_ident())
                self.conn.close()

        worker = WorkflowWorker(Resource, allowed_methods=frozenset({'save'}))
        await worker.start()
        task = asyncio.create_task(worker.call('save', 7))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            assert await asyncio.wait_for(asyncio.sleep(0, result='alive'), 1) == 'alive'
            assert not task.done()
            release.set()
            assert await task == 7
        finally:
            release.set()
            await worker.aclose()
        assert len(set(threads)) == 1 and threads[0] != threading.get_ident()
    asyncio.run(scenario())


def test_fifo_capacity_cancel_churn_and_dispatched_finalization(monkeypatch):
    import app.bot.workflow_worker as module
    submitted = []

    class CountingExecutor(ThreadPoolExecutor):
        def submit(self, fn, *args, **kwargs):
            submitted.append(fn)
            return super().submit(fn, *args, **kwargs)

    monkeypatch.setattr(module, 'ThreadPoolExecutor', CountingExecutor)

    async def scenario():
        entered, release = threading.Event(), threading.Event()
        calls, finalized, outcomes = [], [], []

        class Resource:
            def invoke(self, method, args, kwargs):
                calls.append(args[0])
                if args[0] == 0:
                    entered.set()
                    assert release.wait(5)
                finalized.append(args[0])
                return args[0]

            def close(self):
                finalized.append('closed')

        worker = WorkflowWorker(Resource, allowed_methods=frozenset({'save'}), outcome_sink=outcomes.append)
        await worker.start()
        first = asyncio.create_task(worker.call('save', 0))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            queued = [asyncio.create_task(worker.call('save', n)) for n in range(1, 8)]
            await asyncio.sleep(0)
            with pytest.raises(WorkflowBusy):
                await worker.call('save', 8)
            with pytest.raises(ValueError):
                await worker.call('unknown')
            queued[-1].cancel()
            with pytest.raises(asyncio.CancelledError):
                await queued[-1]
            for _ in range(100):
                cancelled = asyncio.create_task(worker.call('save', 99))
                await asyncio.sleep(0)
                cancelled.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await cancelled
            assert len(submitted) == 2  # factory and the single dispatched invoke
            replacement = asyncio.create_task(worker.call('save', 8))
            await asyncio.sleep(0)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            release.set()
            assert await asyncio.gather(*queued[:-1], replacement) == [1, 2, 3, 4, 5, 6, 8]
        finally:
            release.set()
            await worker.aclose()
        assert calls == [0, 1, 2, 3, 4, 5, 6, 8]
        assert finalized == [0, 1, 2, 3, 4, 5, 6, 8, 'closed']
        assert all(o.method == 'save' and o.status == 'success' for o in outcomes)
        await worker.aclose()
        with pytest.raises(WorkflowClosed):
            await worker.call('save', 10)
    asyncio.run(scenario())


def test_each_call_copies_context_and_failures_do_not_poison_worker():
    marker = contextvars.ContextVar('test_marker', default='absent')

    async def scenario():
        outcomes, contexts = [], []

        class Resource:
            def invoke(self, method, args, kwargs):
                contexts.append(marker.get())
                marker.set('changed-in-worker')
                if args[0]:
                    raise ValueError('synthetic-secret')
                return kwargs['answer']

            def close(self):
                pass

        def sink(outcome):
            outcomes.append(outcome)
            raise RuntimeError('sink failure')

        def classifier(exc):
            raise RuntimeError('classifier failure')

        worker = WorkflowWorker(Resource, allowed_methods=frozenset({'read'}), outcome_sink=sink, error_status=classifier)
        await worker.start()
        try:
            marker.set('one')
            with pytest.raises(ValueError, match='synthetic-secret'):
                await worker.call('read', True, answer=1)
            marker.set('two')
            assert await worker.call('read', False, answer=42) == 42
            assert marker.get() == 'two'
        finally:
            await worker.aclose()
        assert contexts == ['one', 'two']
        assert [o.status for o in outcomes] == ['error', 'success']
        assert 'secret' not in repr(outcomes)
    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['factory', 'close'])
def test_failure_still_joins_executor(monkeypatch, failure):
    import app.bot.workflow_worker as module
    joined = []

    class Executor(ThreadPoolExecutor):
        def shutdown(self, *args, **kwargs):
            joined.append(threading.get_ident())
            return super().shutdown(*args, **kwargs)

    monkeypatch.setattr(module, 'ThreadPoolExecutor', Executor)

    async def scenario():
        class Resource:
            def close(self):
                raise ValueError('close failed')

        def factory():
            if failure == 'factory':
                raise ValueError('factory failed')
            return Resource()

        worker = WorkflowWorker(factory, allowed_methods=frozenset())
        if failure == 'factory':
            with pytest.raises(ValueError):
                await worker.start()
            await worker.aclose()
        else:
            await worker.start()
            with pytest.raises(ValueError):
                await worker.aclose()
        assert len(joined) == 1 and joined[0] != threading.get_ident()
    asyncio.run(scenario())


def test_start_cancel_then_close_waits_for_factory_on_owner_thread():
    async def scenario():
        entered, release = threading.Event(), threading.Event()
        threads = []

        class Resource:
            def __init__(self):
                threads.append(threading.get_ident())
                entered.set()
                assert release.wait(5)

            def close(self):
                threads.append(threading.get_ident())

        worker = WorkflowWorker(Resource, allowed_methods=frozenset())
        start = asyncio.create_task(worker.start())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            start.cancel()
            with pytest.raises(asyncio.CancelledError):
                await start
            close = asyncio.create_task(worker.aclose())
            await asyncio.sleep(0)
            assert not close.done()
            release.set()
            await close
            assert len(threads) == 2 and threads[0] == threads[1]
        finally:
            release.set()
            await worker.aclose()
    asyncio.run(scenario())


def test_cancelled_waiter_before_pump_dispatch_never_invokes():
    async def scenario():
        calls = []

        class Resource:
            def invoke(self, method, args, kwargs):
                calls.append('side effect')

            def close(self):
                pass

        worker = WorkflowWorker(Resource, allowed_methods=frozenset({'save'}), capacity=1)
        await worker.start()
        try:
            pending = asyncio.create_task(worker.call('save'))
            # Let call enqueue; this task resumes before the newly awakened pump.
            await asyncio.sleep(0)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            await worker.aclose()
            assert calls == []
        finally:
            await worker.aclose()
    asyncio.run(scenario())


def test_close_before_factory_dispatch_does_not_open_resource():
    async def scenario():
        calls = []

        class Resource:
            def __init__(self):
                calls.append('factory')

            def close(self):
                calls.append('close')

        worker = WorkflowWorker(Resource, allowed_methods=frozenset())
        start = asyncio.create_task(worker.start())
        await asyncio.sleep(0)
        await worker.aclose()
        outcome = await asyncio.gather(start, return_exceptions=True)
        assert calls == []
        assert isinstance(outcome[0], WorkflowClosed)
    asyncio.run(scenario())
