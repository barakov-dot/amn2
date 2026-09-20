"""Persistent runtime tests: real SQLite/workflow, synthetic network boundaries."""
import asyncio
import threading

import pytest

from app.bot.async_workflow import AsyncBotWorkflow
from app.bot.handlers import handle_user_revoke_device_confirm, handle_admin_issue_config
from app.bot.ux import USER_REVOKE_CONFIRM_PREFIX
from app.bot.workflow_worker import WorkflowClosed
from app.bot.workflows import AdminConfigHandoff
from app.main import run_persistent_bot
from tests.bot.test_app_bootstrap import (
    _FakePersistentBot, _FakeDispatcher, _FakeNotifier, _RecordingLock,
    _passing_admission, _passing_recheck, _persistent_settings, _runtime_workflow,
)
from tests.bot.test_bot_handlers import FakeCallback, FakeMessage
from tests.bot.test_bot_workflows import _create_encrypted_device


def _runtime(tmp_path, events, factory, dispatcher_factory, **extra):
    return run_persistent_bot(
        _persistent_settings(tmp_path), bot_factory=lambda **kw: _FakePersistentBot(events),
        workflow_factory=factory, dispatcher_factory=dispatcher_factory,
        admission_checker=_passing_admission(events), state_checker=_passing_recheck(events),
        lock_factory=lambda path: _RecordingLock(events), notifier=_FakeNotifier(events),
        receipt_writer=lambda value: None, **extra)


def test_busy_revoke_drain_retains_lock_and_runs_queued_reset_once(tmp_path):
    async def scenario():
        events, threads, holder = [], [], {}
        entered, release = threading.Event(), threading.Event()
        dispatcher = _FakeDispatcher(events)

        def factory(settings):
            threads.append(threading.get_ident())
            workflow = _runtime_workflow()
            repo = workflow._repo
            user_id = repo.upsert_user(telegram_id=1001, username=None, first_name=None, last_name=None)
            ids = [_create_encrypted_device(repo, user_id=user_id, server_id=workflow._default_server_id, name=name)
                   for name in ('phone', 'laptop')]
            holder['ids'] = ids

            class Peer:
                def remove_peer(self, *, server, peer_public_key):
                    threads.append(threading.get_ident())
                    events.append(peer_public_key)
                    if peer_public_key == 'peer-phone':
                        entered.set()
                        assert release.wait(5)

            workflow._peer_remover = Peer()
            closer = workflow._resource_closer

            def close():
                threads.append(threading.get_ident())
                events.append(('statuses', [repo.get_device(i)['status'] for i in ids]))
                events.append('workflow_close')
                closer()
            workflow._resource_closer = close
            return workflow

        def build_dispatcher(*, workflow, lifetime):
            assert isinstance(workflow, AsyncBotWorkflow)
            holder.update(workflow=workflow, owner=lifetime)
            return dispatcher

        root = asyncio.create_task(_runtime(tmp_path, events, factory, build_dispatcher))
        try:
            await asyncio.wait_for(dispatcher.started.wait(), 2)
            cb = FakeCallback(data=f'{USER_REVOKE_CONFIRM_PREFIX}:{holder["ids"][0]}', user_id=1001)
            first = asyncio.create_task(holder['owner'].run(
                lambda: handle_user_revoke_device_confirm(cb, workflow=holder['workflow'])))
            assert await asyncio.to_thread(entered.wait, 1)
            second = asyncio.create_task(holder['owner'].run(
                lambda: holder['workflow'].reset_user_devices(telegram_id=1001)))
            await asyncio.sleep(0)
            assert not second.done()
            assert events.count('peer-phone') == 1 and 'peer-laptop' not in events
            root.cancel()
            for _ in range(10):
                await asyncio.sleep(0)
            root.cancel()
            await asyncio.sleep(0)
            assert not root.done()
            assert 'session_close' not in events and 'lock_exit' not in events
            with pytest.raises(WorkflowClosed):
                await holder['owner'].run(lambda: holder['workflow'].list_active_plans())
            release.set()
            await first
            assert await second == 1
            with pytest.raises(asyncio.CancelledError):
                await root
            assert events.count('peer-phone') == events.count('peer-laptop') == 1
            assert ('statuses', ['revoked', 'revoked']) in events
            assert events[-3:] == ['workflow_close', 'session_close', 'lock_exit']
            assert len(set(threads)) == 1 and threads[0] != threading.get_ident()
        finally:
            release.set()
            if not root.done():
                root.cancel()
            await asyncio.gather(root, return_exceptions=True)
    asyncio.run(scenario())


def test_shutdown_between_send_and_record_drains_delivery_before_close(tmp_path):
    async def scenario():
        events, holder = [], {}
        entered, release = threading.Event(), threading.Event()
        dispatcher = _FakeDispatcher(events)

        def factory(settings):
            workflow = _runtime_workflow()
            workflow.issue_admin_config = lambda **kw: AdminConfigHandoff(1, 7, 'test-device', 'test.conf', b'synthetic')

            def record(**kw):
                events.append('record_enter')
                entered.set()
                assert release.wait(5)
                workflow._repo._conn.execute('SELECT 1')
                events.append('record_done')
                return True

            workflow.record_admin_config_delivery = record
            closer = workflow._resource_closer
            workflow._resource_closer = lambda: (events.append('workflow_close'), closer())
            return workflow

        def build_dispatcher(*, workflow, lifetime):
            holder.update(workflow=workflow, owner=lifetime)
            return dispatcher

        root = asyncio.create_task(_runtime(tmp_path, events, factory, build_dispatcher))
        try:
            await asyncio.wait_for(dispatcher.started.wait(), 2)
            message = FakeMessage(user_id=9001)
            message.text = '/admin_issue_config recipient | phone | android'
            parent = asyncio.create_task(holder['owner'].run(
                lambda: handle_admin_issue_config(message, workflow=holder['workflow'])))
            assert await asyncio.to_thread(entered.wait, 1)
            assert len(message.bot.sent_documents) == 1
            parent.cancel()
            with pytest.raises(asyncio.CancelledError):
                await parent
            dispatcher.stop.set()
            await asyncio.sleep(0)
            assert 'session_close' not in events
            release.set()
            await root
            assert events[-4:] == ['record_done', 'workflow_close', 'session_close', 'lock_exit']
            assert len(message.bot.sent_documents) == 1
            assert 'delivered to admin' in message.answers[-1]['text']
        finally:
            release.set()
            if not root.done():
                root.cancel()
            await asyncio.gather(root, return_exceptions=True)
    asyncio.run(scenario())


@pytest.mark.parametrize('poll_error', [False, True])
def test_poll_early_exit_closes_workflow_before_session_and_lock(tmp_path, poll_error):
    events = []

    def factory(settings):
        workflow = _runtime_workflow()
        close = workflow._resource_closer
        workflow._resource_closer = lambda: (events.append('workflow_close'), close())
        return workflow

    class Dispatcher:
        async def start_polling(self, *args, **kwargs):
            if poll_error:
                raise ValueError('poll failed')

    async def scenario():
        if poll_error:
            with pytest.raises(ValueError, match='poll failed'):
                await _runtime(tmp_path, events, factory, lambda **kw: Dispatcher())
        else:
            await _runtime(tmp_path, events, factory, lambda **kw: Dispatcher())
        assert events[-3:] == ['workflow_close', 'session_close', 'lock_exit']
        assert not any(isinstance(e, tuple) and e[0] == 'ready' for e in events)
    asyncio.run(scenario())


def test_startup_timeout_drains_started_factory_without_polling(tmp_path):
    async def scenario():
        events = []
        entered, release = threading.Event(), threading.Event()
        from app.bot.persistent_runtime import PersistentBotAdmissionError

        def factory(settings):
            entered.set()
            assert release.wait(5)
            workflow = _runtime_workflow()
            closer = workflow._resource_closer
            workflow._resource_closer = lambda: (events.append('workflow_close'), closer())
            return workflow

        root = asyncio.create_task(run_persistent_bot(
            _persistent_settings(tmp_path).model_copy(update={'telegram_admission_timeout_seconds': 0.05}),
            bot_factory=lambda **kw: _FakePersistentBot(events), workflow_factory=factory,
            dispatcher_factory=lambda **kw: events.append('dispatcher'),
            admission_checker=_passing_admission(events), state_checker=_passing_recheck(events),
            lock_factory=lambda path: _RecordingLock(events), notifier=_FakeNotifier(events)))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            await asyncio.sleep(0.1)
            assert not root.done() and 'lock_exit' not in events
            release.set()
            with pytest.raises(PersistentBotAdmissionError, match='timed out'):
                await root
            assert 'dispatcher' not in events
            assert events[-3:] == ['workflow_close', 'session_close', 'lock_exit']
        finally:
            release.set()
            await asyncio.gather(root, return_exceptions=True)
    asyncio.run(scenario())


def test_primary_and_cleanup_failure_are_both_preserved(tmp_path):
    events = []
    primary, secondary = ValueError('poll failed'), RuntimeError('close failed')

    def factory(settings):
        workflow = _runtime_workflow()
        closer = workflow._resource_closer

        def close():
            closer()
            raise secondary
        workflow._resource_closer = close
        return workflow

    class Dispatcher:
        async def start_polling(self, *args, **kw):
            raise primary

    async def scenario():
        with pytest.raises(BaseExceptionGroup) as caught:
            await _runtime(tmp_path, events, factory, lambda **kw: Dispatcher())

        def leaves(error):
            if isinstance(error, BaseExceptionGroup):
                return [leaf for item in error.exceptions for leaf in leaves(item)]
            return [error]
        assert primary in leaves(caught.value) and secondary in leaves(caught.value)
        assert events[-2:] == ['session_close', 'lock_exit']
    asyncio.run(scenario())
