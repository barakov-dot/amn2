"""Disposable, synthetic Linux signal child. Fixed records only; never live I/O."""
import asyncio
import os
from pathlib import Path
import sys
import threading

from app.bot.lifecycle import ProcessSignalScope, StopController
from app.main import _supervise, run_persistent_bot
from tests.bot.test_app_bootstrap import (
    _FakeDispatcher, _FakeNotifier, _FakePersistentBot, _RecordingLock,
    _passing_admission, _passing_recheck, _persistent_settings, _runtime_workflow,
)


def run_child(barrier: str, scratch: Path) -> None:
    if barrier not in ('PRE_LOOP', 'FACTORY_DISPATCHED', 'READY'):
        raise ValueError('Invalid synthetic barrier')
    output_lock = threading.Lock()
    go, release, finished = threading.Event(), threading.Event(), threading.Event()

    def emit(record):
        with output_lock:
            print(record, flush=True)

    def watchdog():
        if not finished.wait(10):
            os._exit(70)

    def commands():
        for line in sys.stdin:
            command = line.strip()
            if command == 'GO':
                go.set()
            elif command == 'RELEASE':
                emit('RELEASE')
                release.set()
            else:
                os._exit(71)

    class Controller(StopController):
        def request_stop(self):
            first = not self.requested
            super().request_stop()
            if first:
                emit('STOP_ACCEPTED')

    class Events(list):
        def append(self, event):
            super().append(event)
            if event in ('workflow_close', 'session_close', 'lock_exit'):
                emit(event.upper())

    class Notifier(_FakeNotifier):
        def ready(self, status):
            super().ready(status)
            emit('READY')
            emit('BARRIER:READY')
        def stopping(self, status):
            super().stopping(status)
            emit('STOPPING')

    async def runtime(stop):
        stop.raise_if_requested()
        events = Events()
        def factory(settings):
            if barrier == 'FACTORY_DISPATCHED':
                emit('BARRIER:FACTORY_DISPATCHED')
                if not release.wait(5):
                    raise TimeoutError('Synthetic factory release missing')
            workflow = _runtime_workflow()
            closer = workflow._resource_closer
            def close():
                closer()
                events.append('workflow_close')
            workflow._resource_closer = close
            return workflow
        await run_persistent_bot(
            _persistent_settings(scratch), stop_controller=stop,
            bot_factory=lambda **kw: _FakePersistentBot(events), workflow_factory=factory,
            dispatcher_factory=lambda **kw: _FakeDispatcher(events),
            admission_checker=_passing_admission(events), state_checker=_passing_recheck(events),
            notifier=Notifier(events), lock_factory=lambda path: _RecordingLock(events),
            receipt_writer=lambda value: None)

    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=commands, daemon=True).start()
    stop = Controller()
    try:
        with ProcessSignalScope(stop):
            if barrier == 'PRE_LOOP':
                emit('BARRIER:PRE_LOOP')
                if not go.wait(5):
                    raise TimeoutError('Synthetic GO missing')
            asyncio.run(_supervise(stop, runtime))
        if not stop.requested:
            raise RuntimeError('Synthetic stop missing')
        emit('CLOSED')
    except BaseException:
        emit('FAILED')
        raise SystemExit(72) from None
    finally:
        finished.set()
