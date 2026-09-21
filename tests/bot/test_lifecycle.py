"""Stop ownership tests; OS registration is replaced only at the boundary."""
import asyncio
import signal

import pytest


def test_signal_before_attach_is_retained():
    from app.bot.lifecycle import StopController

    stop = StopController()
    stop.notify_signal()

    async def scenario():
        stop.attach(asyncio.get_running_loop())
        try:
            assert stop.requested
            assert not stop.owns_cancellation(asyncio.CancelledError('external'), asyncio.current_task())
        finally:
            stop.detach()
    asyncio.run(scenario())


def test_partial_install_restores_first_signal():
    from app.bot.lifecycle import ProcessSignalScope, StopController

    previous = {signal.SIGTERM: object(), signal.SIGINT: object()}
    registry = dict(previous)

    def set_handler(signum, handler):
        if signum == signal.SIGINT and handler is not previous[signum]:
            raise ValueError('synthetic registration failure')
        registry[signum] = handler

    with pytest.raises(ValueError, match='synthetic registration failure'):
        with ProcessSignalScope(StopController(), get_handler=registry.__getitem__, set_handler=set_handler):
            pytest.fail('runtime must not start')
    assert registry == previous


@pytest.mark.parametrize('external', [None, 'before', 'after'])
def test_repeated_stop_owns_only_its_cancellation(external):
    from app.bot.lifecycle import StopController

    async def scenario():
        stop = StopController()
        stop.attach(asyncio.get_running_loop())
        events, caught = [], []
        started, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def runtime():
            with stop.bind(asyncio.current_task(), lambda: events.append('closed')):
                started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError as exc:
                    caught.append(exc)
                    stop.begin_cleanup()
                    cleaning.set()
                    await release.wait()
                    raise

        task = asyncio.create_task(runtime())
        try:
            await started.wait()
            if external == 'before':
                task.cancel('external')
            stop.request_stop()
            if external == 'after':
                task.cancel('external')
            await cleaning.wait()
            stop.request_stop()
            stop.notify_signal()
            await asyncio.sleep(0)
            assert not task.done()
            assert events == ['closed']
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert stop.owns_cancellation(caught[0], task) is (external is None)
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
            stop.detach()
    asyncio.run(scenario())


def test_pending_bind_and_stop_during_cleanup_do_not_cancel_cleanup():
    from app.bot.lifecycle import StopController

    async def scenario():
        stop = StopController()
        stop.attach(asyncio.get_running_loop())
        events = []
        stop.request_stop()
        with stop.bind(asyncio.current_task(), lambda: events.append('closed')):
            try:
                await asyncio.sleep(0)
            except asyncio.CancelledError as exc:
                assert stop.owns_cancellation(exc, asyncio.current_task())
            stop.begin_cleanup()
        assert events == ['closed']
        stop.detach()

        second = StopController()
        second.attach(asyncio.get_running_loop())
        with second.bind(asyncio.current_task(), lambda: events.append('cleanup_closed')):
            second.begin_cleanup()
            second.request_stop()
            await asyncio.sleep(0)
        assert events[-1] == 'cleanup_closed'
        second.detach()
    asyncio.run(scenario())


def test_detached_queued_callback_cannot_touch_old_owner():
    from app.bot.lifecycle import StopController

    async def scenario():
        stop = StopController()
        loop = asyncio.get_running_loop()
        stop.attach(loop)
        events = []
        with stop.bind(asyncio.current_task(), lambda: events.append('closed')):
            stop.notify_signal()
        stop.detach()
        await asyncio.sleep(0)
        assert events == []
        with pytest.raises(RuntimeError):
            stop.attach(loop)
    asyncio.run(scenario())


def test_restore_attempts_both_signals_and_preserves_body_error():
    from app.bot.lifecycle import ProcessSignalScope, StopController

    previous = {signal.SIGTERM: object(), signal.SIGINT: object()}
    registry, restored = dict(previous), []
    def setter(sig, handler):
        if handler is previous[sig]:
            restored.append(sig)
            if sig == signal.SIGINT:
                raise ValueError('restore failed')
        registry[sig] = handler
    with pytest.raises(BaseExceptionGroup) as captured:
        with ProcessSignalScope(StopController(), get_handler=registry.__getitem__, set_handler=setter):
            raise RuntimeError('body failed')
    assert restored == [signal.SIGINT, signal.SIGTERM]
    assert [type(e) for e in captured.value.exceptions] == [RuntimeError, ValueError]
    assert registry[signal.SIGTERM] is previous[signal.SIGTERM]


def test_signal_scope_delivers_pending_and_restores_normally():
    from app.bot.lifecycle import ProcessSignalScope, StopController

    previous = {signal.SIGTERM: object(), signal.SIGINT: object()}
    registry = dict(previous)
    stop = StopController()
    with ProcessSignalScope(stop, get_handler=registry.__getitem__, set_handler=registry.__setitem__):
        registry[signal.SIGTERM](signal.SIGTERM, None)
        async def scenario():
            stop.attach(asyncio.get_running_loop())
            assert stop.requested
            stop.detach()
        asyncio.run(scenario())
    assert registry == previous


def test_admission_close_error_still_requests_owner_cleanup():
    from app.bot.lifecycle import StopController

    async def scenario():
        stop = StopController()
        stop.attach(asyncio.get_running_loop())
        error = ValueError('close failed')
        def fail():
            raise error
        try:
            with stop.bind(asyncio.current_task(), fail):
                stop.request_stop()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.sleep(0)
                assert stop.failure is error
        finally:
            stop.detach()
    asyncio.run(scenario())


def test_controller_cannot_bind_a_second_runtime_generation():
    from app.bot.lifecycle import StopController
    async def scenario():
        stop = StopController()
        stop.attach(asyncio.get_running_loop())
        try:
            with stop.bind(asyncio.current_task(), lambda: None):
                pass
            with pytest.raises(RuntimeError, match='already owns'):
                with stop.bind(asyncio.current_task(), lambda: None):
                    pass
        finally:
            stop.detach()
    asyncio.run(scenario())
