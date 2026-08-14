from aiogram import Dispatcher, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery
from aiogram.types import Message

from app.bot.handlers import (
    AWG3_CONFIRM_PREFIX,
    AWG3_SELECT_PREFIX,
    handle_admin_add_user,
    handle_admin_approve,
    handle_admin_create_order,
    handle_admin_grant,
    handle_admin_integrations,
    handle_admin_issue_config,
    handle_admin_pending,
    handle_admin_servers,
    handle_admin_status,
    handle_admin_traffic,
    handle_admin_resend_config,
    handle_admin_resend_issued_config,
    handle_admin_reset_template,
    handle_admin_template,
    handle_admin_users,
    handle_config_request,
    handle_awg3_confirm,
    handle_awg3_select,
    handle_my_devices,
    handle_language_choice,
    handle_my_tariff,
    handle_my_traffic,
    handle_plan_request,
    handle_request_config_prompt,
    handle_start,
    handle_user_resend_config,
    handle_user_reset_devices,
    handle_user_reset_devices_confirm,
    handle_user_revoke_device,
    handle_user_revoke_device_confirm,
)
from app.bot.ux import (
    ADMIN_APPROVE_PREFIX,
    ADMIN_INTEGRATIONS_CALLBACK,
    ADMIN_PENDING_CALLBACK,
    ADMIN_SERVERS_CALLBACK,
    ADMIN_STATUS_CALLBACK,
    ADMIN_TRAFFIC_CALLBACK,
    ADMIN_RESEND_PREFIX,
    ADMIN_TEMPLATE_RESET_CALLBACK,
    ADMIN_TEMPLATES_CALLBACK,
    ADMIN_USERS_CALLBACK,
    LANGUAGE_CALLBACK_PREFIX,
    MY_DEVICES_CALLBACK,
    MY_TARIFF_CALLBACK,
    MY_TRAFFIC_CALLBACK,
    REQUEST_CONFIG_PREFIX,
    REQUEST_PLAN_PREFIX,
    USER_RESEND_PREFIX,
    USER_RESET_DEVICES_CONFIRM_CALLBACK,
    USER_RESET_DEVICES_CALLBACK,
    USER_REVOKE_CONFIRM_PREFIX,
    USER_REVOKE_PREFIX,
)


def create_dispatcher(*, workflow=None) -> Dispatcher:
    router = Router()

    @router.message(CommandStart())
    async def start(message: Message) -> None:
        if workflow is None:
            await message.answer("Amneziya VPN")
            return
        await handle_start(message, workflow=workflow)

    @router.message(Command("admin_grant"))
    async def admin_grant(message: Message) -> None:
        await handle_admin_grant(message, workflow=workflow)

    @router.message(Command("admin_add_user"))
    async def admin_add_user(message: Message) -> None:
        await handle_admin_add_user(message, workflow=workflow)

    @router.message(Command("admin_create_order"))
    async def admin_create_order(message: Message) -> None:
        await handle_admin_create_order(message, workflow=workflow)

    @router.message(Command("admin_issue_config"))
    async def admin_issue_config(message: Message) -> None:
        await handle_admin_issue_config(message, workflow=workflow)

    @router.message(Command("admin_resend_issued_config"))
    async def admin_resend_issued_config(message: Message) -> None:
        await handle_admin_resend_issued_config(message, workflow=workflow)

    @router.callback_query(F.data == REQUEST_CONFIG_PREFIX)
    async def request_config(callback: CallbackQuery) -> None:
        await handle_request_config_prompt(callback)

    @router.callback_query(F.data.startswith(f"{AWG3_SELECT_PREFIX}:"))
    async def awg3_select(callback: CallbackQuery) -> None:
        await handle_awg3_select(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{AWG3_CONFIRM_PREFIX}:"))
    async def awg3_confirm(callback: CallbackQuery) -> None:
        await handle_awg3_confirm(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{LANGUAGE_CALLBACK_PREFIX}:"))
    async def language_choice(callback: CallbackQuery) -> None:
        await handle_language_choice(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{REQUEST_CONFIG_PREFIX}:"))
    async def request_config_version(callback: CallbackQuery) -> None:
        await handle_config_request(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{REQUEST_PLAN_PREFIX}:"))
    async def request_plan(callback: CallbackQuery) -> None:
        await handle_plan_request(callback, workflow=workflow)

    @router.callback_query(F.data == MY_TRAFFIC_CALLBACK)
    async def my_traffic(callback: CallbackQuery) -> None:
        await handle_my_traffic(callback, workflow=workflow)

    @router.callback_query(F.data == MY_TARIFF_CALLBACK)
    async def my_tariff(callback: CallbackQuery) -> None:
        await handle_my_tariff(callback, workflow=workflow)

    @router.callback_query(F.data == MY_DEVICES_CALLBACK)
    async def my_devices(callback: CallbackQuery) -> None:
        await handle_my_devices(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{USER_RESEND_PREFIX}:"))
    async def user_resend(callback: CallbackQuery) -> None:
        await handle_user_resend_config(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{USER_REVOKE_PREFIX}:"))
    async def user_revoke(callback: CallbackQuery) -> None:
        await handle_user_revoke_device(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{USER_REVOKE_CONFIRM_PREFIX}:"))
    async def user_revoke_confirm(callback: CallbackQuery) -> None:
        await handle_user_revoke_device_confirm(callback, workflow=workflow)

    @router.callback_query(F.data == USER_RESET_DEVICES_CALLBACK)
    async def user_reset_devices(callback: CallbackQuery) -> None:
        await handle_user_reset_devices(callback, workflow=workflow)

    @router.callback_query(F.data == USER_RESET_DEVICES_CONFIRM_CALLBACK)
    async def user_reset_devices_confirm(callback: CallbackQuery) -> None:
        await handle_user_reset_devices_confirm(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_PENDING_CALLBACK)
    async def admin_pending(callback: CallbackQuery) -> None:
        await handle_admin_pending(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_STATUS_CALLBACK)
    async def admin_status(callback: CallbackQuery) -> None:
        await handle_admin_status(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_SERVERS_CALLBACK)
    async def admin_servers(callback: CallbackQuery) -> None:
        await handle_admin_servers(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_INTEGRATIONS_CALLBACK)
    async def admin_integrations(callback: CallbackQuery) -> None:
        await handle_admin_integrations(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_TRAFFIC_CALLBACK)
    async def admin_traffic(callback: CallbackQuery) -> None:
        await handle_admin_traffic(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_TEMPLATES_CALLBACK)
    async def admin_template(callback: CallbackQuery) -> None:
        await handle_admin_template(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_USERS_CALLBACK)
    async def admin_users(callback: CallbackQuery) -> None:
        await handle_admin_users(callback, workflow=workflow)

    @router.callback_query(F.data == ADMIN_TEMPLATE_RESET_CALLBACK)
    async def admin_template_reset(callback: CallbackQuery) -> None:
        await handle_admin_reset_template(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{ADMIN_RESEND_PREFIX}:"))
    async def admin_resend(callback: CallbackQuery) -> None:
        await handle_admin_resend_config(callback, workflow=workflow)

    @router.callback_query(F.data.startswith(f"{ADMIN_APPROVE_PREFIX}:"))
    async def admin_approve(callback: CallbackQuery) -> None:
        await handle_admin_approve(callback, workflow=workflow)

    dispatcher = Dispatcher()
    dispatcher["workflow"] = workflow
    dispatcher["phase15_awg3_components"] = getattr(
        workflow,
        "_phase15_awg3_components",
        None,
    )
    dispatcher.include_router(router)
    return dispatcher
