import asyncio
import sqlite3
from dataclasses import dataclass

import pytest

from app.bot.async_workflow import AsyncBotWorkflow, WORKFLOW_METHODS, make_workflow_resource, snapshot_result
from app.bot.workflow_worker import WorkflowWorker
from app.bot.workflows import AdminConfigHandoff, BotWorkflow
from app.config import Settings
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.main import create_workflow_from_settings


def test_real_facade_preserves_auth_and_detaches_results(tmp_path):
    async def scenario():
        settings = Settings(_env_file=None, database_path=str(tmp_path / 'facade.sqlite3'),
                            telegram_bot_token='123456:test',
                            app_secret_key='synthetic-test-secret-with-more-than-32-chars',
                            admin_telegram_ids='9001', vps_apply_enabled=False)
        worker = WorkflowWorker(lambda: make_workflow_resource(lambda: create_workflow_from_settings(settings)),
                                allowed_methods=WORKFLOW_METHODS)
        permitted = True

        def guard():
            if not permitted:
                raise PermissionError('handler ended')

        facade = AsyncBotWorkflow(worker, guard=guard)
        await worker.start()
        try:
            user = await facade.register_user(telegram_id=42, username=None, first_name='Test', last_name=None)
            assert user > 0
            plans = await facade.list_active_plans()
            assert plans[0]['id'] == 'days_3'
            assert await facade.list_user_devices(telegram_id=42) == []
            assert await facade.is_admin(42) is False
            assert await facade.get_operator_status(admin_telegram_id=42) is None
            permitted = False
            with pytest.raises(PermissionError):
                await facade.register_user(telegram_id=99, username=None, first_name=None, last_name=None)
            permitted = True
            users = await facade.list_users(admin_telegram_id=9001)
            assert 99 not in [row['telegram_id'] for row in users]
        finally:
            await worker.aclose()
        assert plans[0]['id'] == 'days_3'
        assert not hasattr(facade, '_phase15_awg3_components')
    asyncio.run(scenario())


def test_snapshot_detaches_rows_and_preserves_dto_and_bytes():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT 1280 AS mtu').fetchone()

    @dataclass(frozen=True)
    class Nested:
        values: object

    original = {'rows': [row], 'tuple': (Nested([row]),)}
    value = snapshot_result(original)
    dto = AdminConfigHandoff(1, 2, 'test-device', 'test.conf', b'synthetic-config')
    result = snapshot_result(dto)
    conn.close()
    original['rows'].clear()
    assert value == {'rows': [{'mtu': 1280}], 'tuple': (Nested([{'mtu': 1280}]),)}
    assert isinstance(result, AdminConfigHandoff) and result == dto
    assert result.config_bytes == b'synthetic-config'


def test_snapshot_rejects_resources_even_when_nested():
    conn = sqlite3.connect(':memory:')
    try:
        for resource in (conn, conn.cursor(), Repository(conn), iter([1]), object()):
            with pytest.raises(TypeError, match='Unsupported workflow result'):
                snapshot_result([{'resource': resource}])
    finally:
        conn.close()


def test_external_repository_is_not_closed_by_workflow():
    conn = sqlite3.connect(':memory:')
    initialize_schema(conn)
    workflow = BotWorkflow(repo=Repository(conn), admin_telegram_ids=set())
    workflow.close()
    workflow.close()
    assert conn.execute('SELECT 1').fetchone()[0] == 1
    conn.close()


def test_queued_admin_read_rechecks_authorization_when_executed():
    import threading
    from tests.bot.test_app_bootstrap import _runtime_workflow
    from tests.bot.test_bot_workflows import _create_encrypted_device

    async def scenario():
        entered, release = threading.Event(), threading.Event()
        holder = {}

        def factory():
            workflow = _runtime_workflow()
            repo = workflow._repo
            user = repo.upsert_user(telegram_id=42, username=None, first_name=None, last_name=None)
            repo._conn.execute('UPDATE users SET is_admin=1 WHERE id=?', (user,))
            repo._conn.commit()
            device = _create_encrypted_device(repo, user_id=user, server_id=workflow._default_server_id, name='phone')
            holder['device'] = device

            class Peer:
                def remove_peer(self, **kwargs):
                    entered.set()
                    assert release.wait(5)
                    repo._conn.execute('UPDATE users SET is_admin=0 WHERE id=?', (user,))
                    repo._conn.commit()
            workflow._peer_remover = Peer()
            return workflow

        worker = WorkflowWorker(lambda: make_workflow_resource(factory), allowed_methods=WORKFLOW_METHODS)
        facade = AsyncBotWorkflow(worker, guard=lambda: None)
        await worker.start()
        try:
            assert await facade.is_admin(42)
            revoke = asyncio.create_task(facade.revoke_user_device(telegram_id=42, device_id=holder['device']))
            assert await asyncio.to_thread(entered.wait, 1)
            read = asyncio.create_task(facade.list_users(admin_telegram_id=42))
            await asyncio.sleep(0)
            assert not read.done()
            release.set()
            assert await revoke
            assert await read == []
        finally:
            release.set()
            await worker.aclose()
    asyncio.run(scenario())


def test_remote_success_local_failure_remains_partial_across_worker(caplog):
    from types import SimpleNamespace
    from app.bot.handler_lifetime import HandlerLifetime, WorkflowLifetimeMiddleware
    from app.bot.handlers import handle_user_revoke_device_confirm
    from app.bot.ux import USER_REVOKE_CONFIRM_PREFIX
    from app.services.access import RemoteOperationPartialFailure
    from tests.bot.test_app_bootstrap import _runtime_workflow
    from tests.bot.test_bot_handlers import FakeCallback
    from tests.bot.test_bot_workflows import _create_encrypted_device

    async def scenario():
        remote, outcomes, holder = [], [], {}

        def factory():
            workflow = _runtime_workflow()
            repo = workflow._repo
            user = repo.upsert_user(telegram_id=42, username=None, first_name=None, last_name=None)
            holder['device'] = _create_encrypted_device(repo, user_id=user, server_id=workflow._default_server_id, name='phone')
            workflow._peer_remover = SimpleNamespace(remove_peer=lambda **kw: remote.append('removed'))
            repo._conn.execute("CREATE TRIGGER fail_revoke BEFORE UPDATE OF status ON devices BEGIN SELECT RAISE(ABORT, 'local-secret-sentinel'); END")
            repo._conn.commit()
            return workflow

        owner = HandlerLifetime()
        worker = WorkflowWorker(lambda: make_workflow_resource(factory), allowed_methods=WORKFLOW_METHODS,
                                outcome_sink=outcomes.append,
                                error_status=lambda exc: 'partial' if isinstance(exc, RemoteOperationPartialFailure) else 'error')
        facade = AsyncBotWorkflow(worker, guard=owner.require_active)
        await worker.start()
        try:
            cb = FakeCallback(data=f'{USER_REVOKE_CONFIRM_PREFIX}:{holder["device"]}', user_id=42)
            await WorkflowLifetimeMiddleware(owner)(lambda event, data: handle_user_revoke_device_confirm(event, workflow=facade), cb, {})
            assert remote == ['removed']
            assert len(cb.message.answers) == 1
            assert 'частично' in cb.message.answers[0]['text']
            assert 'local-secret-sentinel' not in cb.message.answers[0]['text'] + caplog.text
            assert [o.status for o in outcomes] == ['partial']
        finally:
            await owner.drain()
            await worker.aclose()
    asyncio.run(scenario())
