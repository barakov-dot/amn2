"""Explicit async bot boundary and detached snapshots of synchronous results."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import fields, is_dataclass, replace
from datetime import date, datetime
from enum import Enum
from typing import Any

from app.bot.workflow_worker import SyncWorkflowResource, WorkflowWorker
from app.bot.workflows import (
    AccessRequestResult, AdminConfigHandoff, ApprovalResult, Awg3Confirmation,
    BotWorkflow, ResendResult,
)
from app.services.operator_status import OperatorStatusSummary
from app.services.operator_server_status import OperatorServerStatusView
from app.services.operator_credential_status import OperatorCredentialStatusView
from app.services.self_service_issuance import SelfServiceIssuanceResult
from app.services.traffic import DeviceTrafficView


def snapshot_result(value: object) -> object:
    if value is None or isinstance(value, (str, bytes, bool, int, float, date, Enum)):
        return value
    if isinstance(value, sqlite3.Row):
        return {key: snapshot_result(value[key]) for key in value.keys()}
    if isinstance(value, dict):
        return {snapshot_result(key): snapshot_result(item) for key, item in value.items()}
    if isinstance(value, list):
        return [snapshot_result(item) for item in value]
    if isinstance(value, tuple):
        return tuple(snapshot_result(item) for item in value)
    if is_dataclass(value) and not isinstance(value, type):
        return replace(value, **{field.name: snapshot_result(getattr(value, field.name)) for field in fields(value)})
    raise TypeError('Unsupported workflow result type')


WORKFLOW_METHODS = frozenset({
    'is_admin',
    'is_configured_admin',
    'request_awg3',
    'confirm_awg3',
    'issue_admin_config',
    'record_admin_config_delivery',
    'build_admin_config_handoff_for_device',
    'register_user',
    'set_user_locale',
    'get_user_locale',
    'request_access',
    'create_manual_user',
    'create_manual_access_request',
    'grant_admin',
    'list_active_plans',
    'build_user_traffic_views',
    'list_user_devices',
    'build_admin_traffic_views',
    'list_pending_orders',
    'get_operator_status',
    'get_operator_server_statuses',
    'get_operator_credential_statuses',
    'list_users',
    'approve_order',
    'get_config_ready_template',
    'reset_config_ready_template',
    'build_resend_delivery',
    'build_user_resend_delivery',
    'revoke_user_device',
    'reset_user_devices',
})


class _WorkflowResource:
    def __init__(self, workflow: BotWorkflow) -> None:
        self._workflow = workflow
        self._methods = {
            'is_admin': workflow.is_admin,
            'is_configured_admin': workflow.is_configured_admin,
            'request_awg3': workflow.request_awg3,
            'confirm_awg3': workflow.confirm_awg3,
            'issue_admin_config': workflow.issue_admin_config,
            'record_admin_config_delivery': workflow.record_admin_config_delivery,
            'build_admin_config_handoff_for_device': workflow.build_admin_config_handoff_for_device,
            'register_user': workflow.register_user,
            'set_user_locale': workflow.set_user_locale,
            'get_user_locale': workflow.get_user_locale,
            'request_access': workflow.request_access,
            'create_manual_user': workflow.create_manual_user,
            'create_manual_access_request': workflow.create_manual_access_request,
            'grant_admin': workflow.grant_admin,
            'list_active_plans': workflow.list_active_plans,
            'build_user_traffic_views': workflow.build_user_traffic_views,
            'list_user_devices': workflow.list_user_devices,
            'build_admin_traffic_views': workflow.build_admin_traffic_views,
            'list_pending_orders': workflow.list_pending_orders,
            'get_operator_status': workflow.get_operator_status,
            'get_operator_server_statuses': workflow.get_operator_server_statuses,
            'get_operator_credential_statuses': workflow.get_operator_credential_statuses,
            'list_users': workflow.list_users,
            'approve_order': workflow.approve_order,
            'get_config_ready_template': workflow.get_config_ready_template,
            'reset_config_ready_template': workflow.reset_config_ready_template,
            'build_resend_delivery': workflow.build_resend_delivery,
            'build_user_resend_delivery': workflow.build_user_resend_delivery,
            'revoke_user_device': workflow.revoke_user_device,
            'reset_user_devices': workflow.reset_user_devices,
        }

    def invoke(self, method: str, args: tuple, kwargs: dict) -> object:
        return snapshot_result(self._methods[method](*args, **kwargs))

    def close(self) -> None:
        self._workflow.close()


def make_workflow_resource(factory: Callable[[], BotWorkflow]) -> SyncWorkflowResource:
    workflow = factory()
    try:
        return _WorkflowResource(workflow)
    except BaseException:
        workflow.close()
        raise


class AsyncBotWorkflow:
    def __init__(self, worker: WorkflowWorker, *, guard: Callable[[], None]) -> None:
        self._worker = worker
        self._guard = guard

    async def is_admin(self, telegram_id: int) -> bool:
        self._guard()
        return await self._worker.call('is_admin', telegram_id)

    async def is_configured_admin(self, telegram_id: int) -> bool:
        self._guard()
        return await self._worker.call('is_configured_admin', telegram_id)

    async def request_awg3(self, *, telegram_id: int, selection_handle: str) -> SelfServiceIssuanceResult:
        self._guard()
        return await self._worker.call('request_awg3', telegram_id=telegram_id, selection_handle=selection_handle)

    async def confirm_awg3(self, *, telegram_id: int, confirmation_token: str) -> Awg3Confirmation | None:
        self._guard()
        return await self._worker.call('confirm_awg3', telegram_id=telegram_id, confirmation_token=confirmation_token)

    async def issue_admin_config(self, *, admin_telegram_id: int, request_id: str, recipient_label: str, device_label: str, platform: str) -> AdminConfigHandoff | None:
        self._guard()
        return await self._worker.call('issue_admin_config', admin_telegram_id=admin_telegram_id, request_id=request_id, recipient_label=recipient_label, device_label=device_label, platform=platform)

    async def record_admin_config_delivery(self, *, admin_telegram_id: int, passport_device_id: str, delivered: bool, reference: str) -> bool:
        self._guard()
        return await self._worker.call('record_admin_config_delivery', admin_telegram_id=admin_telegram_id, passport_device_id=passport_device_id, delivered=delivered, reference=reference)

    async def build_admin_config_handoff_for_device(self, *, admin_telegram_id: int, device_id: int) -> AdminConfigHandoff | None:
        self._guard()
        return await self._worker.call('build_admin_config_handoff_for_device', admin_telegram_id=admin_telegram_id, device_id=device_id)

    async def register_user(self, *, telegram_id: int, username: str | None, first_name: str | None, last_name: str | None) -> int:
        self._guard()
        return await self._worker.call('register_user', telegram_id=telegram_id, username=username, first_name=first_name, last_name=last_name)

    async def set_user_locale(self, *, telegram_id: int, username: str | None, first_name: str | None, last_name: str | None, locale: str) -> bool:
        self._guard()
        return await self._worker.call('set_user_locale', telegram_id=telegram_id, username=username, first_name=first_name, last_name=last_name, locale=locale)

    async def get_user_locale(self, *, telegram_id: int) -> str:
        self._guard()
        return await self._worker.call('get_user_locale', telegram_id=telegram_id)

    async def request_access(self, *, telegram_id: int, username: str | None, first_name: str | None, last_name: str | None, config_version: str, plan_id: str | None=None) -> AccessRequestResult:
        self._guard()
        return await self._worker.call('request_access', telegram_id=telegram_id, username=username, first_name=first_name, last_name=last_name, config_version=config_version, plan_id=plan_id)

    async def create_manual_user(self, *, admin_telegram_id: int, target_telegram_id: int, username: str | None, first_name: str | None, last_name: str | None) -> int | None:
        self._guard()
        return await self._worker.call('create_manual_user', admin_telegram_id=admin_telegram_id, target_telegram_id=target_telegram_id, username=username, first_name=first_name, last_name=last_name)

    async def create_manual_access_request(self, *, admin_telegram_id: int, target_telegram_id: int, username: str | None, first_name: str | None, last_name: str | None, config_version: str, plan_id: str | None) -> AccessRequestResult | None:
        self._guard()
        return await self._worker.call('create_manual_access_request', admin_telegram_id=admin_telegram_id, target_telegram_id=target_telegram_id, username=username, first_name=first_name, last_name=last_name, config_version=config_version, plan_id=plan_id)

    async def grant_admin(self, *, admin_telegram_id: int, target_telegram_id: int, username: str | None, first_name: str | None, last_name: str | None) -> bool:
        self._guard()
        return await self._worker.call('grant_admin', admin_telegram_id=admin_telegram_id, target_telegram_id=target_telegram_id, username=username, first_name=first_name, last_name=last_name)

    async def list_active_plans(self) -> Any:
        self._guard()
        return await self._worker.call('list_active_plans')

    async def build_user_traffic_views(self, *, telegram_id: int, now: str | None=None) -> list[DeviceTrafficView]:
        self._guard()
        return await self._worker.call('build_user_traffic_views', telegram_id=telegram_id, now=now)

    async def list_user_devices(self, *, telegram_id: int) -> Any:
        self._guard()
        return await self._worker.call('list_user_devices', telegram_id=telegram_id)

    async def build_admin_traffic_views(self, *, admin_telegram_id: int, now: str | None=None) -> list[DeviceTrafficView]:
        self._guard()
        return await self._worker.call('build_admin_traffic_views', admin_telegram_id=admin_telegram_id, now=now)

    async def list_pending_orders(self, *, admin_telegram_id: int) -> Any:
        self._guard()
        return await self._worker.call('list_pending_orders', admin_telegram_id=admin_telegram_id)

    async def get_operator_status(self, *, admin_telegram_id: int, now: datetime | str | None=None) -> OperatorStatusSummary | None:
        self._guard()
        return await self._worker.call('get_operator_status', admin_telegram_id=admin_telegram_id, now=now)

    async def get_operator_server_statuses(self, *, admin_telegram_id: int, limit: int=20) -> list[OperatorServerStatusView] | None:
        self._guard()
        return await self._worker.call('get_operator_server_statuses', admin_telegram_id=admin_telegram_id, limit=limit)

    async def get_operator_credential_statuses(self, *, admin_telegram_id: int, limit: int=20) -> list[OperatorCredentialStatusView] | None:
        self._guard()
        return await self._worker.call('get_operator_credential_statuses', admin_telegram_id=admin_telegram_id, limit=limit)

    async def list_users(self, *, admin_telegram_id: int) -> Any:
        self._guard()
        return await self._worker.call('list_users', admin_telegram_id=admin_telegram_id)

    async def approve_order(self, *, admin_telegram_id: int, order_id: int, config_version: str) -> ApprovalResult | None:
        self._guard()
        return await self._worker.call('approve_order', admin_telegram_id=admin_telegram_id, order_id=order_id, config_version=config_version)

    async def get_config_ready_template(self, *, admin_telegram_id: int) -> str | None:
        self._guard()
        return await self._worker.call('get_config_ready_template', admin_telegram_id=admin_telegram_id)

    async def reset_config_ready_template(self, *, admin_telegram_id: int) -> bool:
        self._guard()
        return await self._worker.call('reset_config_ready_template', admin_telegram_id=admin_telegram_id)

    async def build_resend_delivery(self, *, admin_telegram_id: int, device_id: int) -> ResendResult | None:
        self._guard()
        return await self._worker.call('build_resend_delivery', admin_telegram_id=admin_telegram_id, device_id=device_id)

    async def build_user_resend_delivery(self, *, telegram_id: int, device_id: int) -> ResendResult | None:
        self._guard()
        return await self._worker.call('build_user_resend_delivery', telegram_id=telegram_id, device_id=device_id)

    async def revoke_user_device(self, *, telegram_id: int, device_id: int, revoked_at: str | None=None) -> bool:
        self._guard()
        return await self._worker.call('revoke_user_device', telegram_id=telegram_id, device_id=device_id, revoked_at=revoked_at)

    async def reset_user_devices(self, *, telegram_id: int, revoked_at: str | None=None) -> int:
        self._guard()
        return await self._worker.call('reset_user_devices', telegram_id=telegram_id, revoked_at=revoked_at)
