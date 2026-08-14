from __future__ import annotations

import re

from aiogram.types import (
    BufferedInputFile,
    CopyTextButton,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

from app.bot.assets import BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH
from app.bot.delivery import TELEGRAM_COPY_TEXT_MAX_LENGTH
from app.bot.texts import text
from app.bot.ux import (
    ADMIN_APPROVE_PREFIX,
    ADMIN_INTEGRATIONS_CALLBACK,
    ADMIN_PENDING_CALLBACK,
    ADMIN_SERVERS_CALLBACK,
    ADMIN_STATUS_CALLBACK,
    ADMIN_TRAFFIC_CALLBACK,
    ADMIN_RESEND_PREFIX,
    parse_admin_issue_config_command,
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
    build_plan_keyboard,
    build_language_keyboard,
    build_user_device_keyboard,
    build_user_reset_confirm_keyboard,
    build_user_revoke_confirm_keyboard,
    build_user_devices_reset_keyboard,
    build_config_version_keyboard,
    build_admin_order_keyboard,
    build_admin_navigation_keyboard,
    build_main_menu,
    parse_admin_approve_callback,
    parse_config_version_callback,
    parse_language_callback,
    render_admin_template,
    render_admin_integrations,
    render_admin_pending_orders,
    render_admin_servers,
    render_admin_status,
    render_admin_traffic,
    render_admin_users,
    render_config_version_prompt,
    render_language_prompt,
    render_my_devices,
    render_my_tariff,
    render_plan_prompt,
    render_start_text,
    render_user_traffic,
)
from app.security.redaction import redact
from app.server.peer_apply import PeerApplyError
from app.services.config_material import ConfigMaterialUnavailable


AWG3_SELECT_PREFIX = "a3s"
AWG3_CONFIRM_PREFIX = "a3c"
_AWG3_SELECT_RE = re.compile(r"^a3s:([A-Za-z0-9_-]{22,60})$")
_AWG3_CONFIRM_RE = re.compile(r"^a3c:([A-Za-z0-9_-]{22,60})$")


async def handle_start(message, *, workflow) -> None:
    user = message.from_user
    workflow.register_user(
        telegram_id=int(user.id),
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
    )
    if BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH.exists():
        await message.answer_photo(
            FSInputFile(str(BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH)),
            caption=render_language_prompt(),
            reply_markup=build_language_keyboard(),
        )
        return
    await message.answer(
        render_language_prompt(),
        reply_markup=build_language_keyboard(),
    )


async def handle_language_choice(callback, *, workflow) -> None:
    locale = parse_language_callback(str(callback.data))
    if locale is None:
        await callback.message.answer(text("handler.unknown_language"))
        await callback.answer()
        return

    user = callback.from_user
    workflow.set_user_locale(
        telegram_id=int(user.id),
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
        locale=locale,
    )
    await callback.message.answer(
        render_start_text(
            first_name=user.first_name,
            is_admin=workflow.is_admin(int(user.id)),
            locale=locale,
        ),
        reply_markup=build_main_menu(
            is_admin=workflow.is_admin(int(user.id)),
            locale=locale,
        ),
    )
    await callback.answer()


async def handle_request_config_prompt(callback) -> None:
    await callback.message.answer(
        render_config_version_prompt(),
        reply_markup=build_config_version_keyboard(prefix=REQUEST_CONFIG_PREFIX),
    )
    await callback.answer()


async def handle_awg3_select(callback, *, workflow) -> None:
    if not _is_private_callback(callback):
        await callback.answer()
        return
    parsed = _parse_awg3_select_callback(str(callback.data))
    if parsed is None:
        await callback.message.answer(text("handler.awg3_invalid_selection"))
        await callback.answer()
        return
    try:
        result = workflow.request_awg3(
            telegram_id=int(callback.from_user.id),
            selection_handle=parsed,
        )
    except (LookupError, ValueError):
        await callback.message.answer(text("handler.awg3_invalid_selection"))
        await callback.answer()
        return
    if result.status == "confirmation_required" and result.token:
        await callback.message.answer(
            text("handler.awg3_confirm_prompt"),
            reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        InlineKeyboardButton(
                            text=text("button.awg3_confirm"),
                            callback_data=f"{AWG3_CONFIRM_PREFIX}:{result.token}",
                        )
                    ]
                ]
            ),
        )
    else:
        await callback.message.answer(
            text("handler.awg3_blocked"),
            reply_markup=_awg2_offer_markup() if result.offer_awg2 else None,
        )
    await callback.answer()


async def handle_awg3_confirm(callback, *, workflow) -> None:
    if not _is_private_callback(callback):
        await callback.answer()
        return
    confirmation_token = _parse_awg3_confirm_callback(str(callback.data))
    if confirmation_token is None:
        await callback.message.answer(text("handler.awg3_invalid_confirmation"))
        await callback.answer()
        return
    confirmed = workflow.confirm_awg3(
        telegram_id=int(callback.from_user.id),
        confirmation_token=confirmation_token,
    )
    if confirmed is None:
        await callback.message.answer(text("handler.awg3_invalid_confirmation"))
        await callback.answer()
        return
    if confirmed.result.status != "issued" or confirmed.delivery is None:
        await callback.message.answer(
            text("handler.awg3_blocked"),
            reply_markup=(
                _awg2_offer_markup() if confirmed.result.offer_awg2 else None
            ),
        )
        await callback.answer()
        return
    await _send_awg3_delivery(
        callback.bot,
        chat_id=int(callback.from_user.id),
        delivery=confirmed.delivery,
    )
    await callback.answer()


async def handle_config_request(callback, *, workflow) -> None:
    config_version = parse_config_version_callback(
        str(callback.data),
        prefix=REQUEST_CONFIG_PREFIX,
    )
    if config_version is None:
        await callback.message.answer(text("handler.unknown_config"))
        await callback.answer()
        return

    plans = workflow.list_active_plans()
    await callback.message.answer(
        render_plan_prompt(config_version=config_version),
        reply_markup=build_plan_keyboard(config_version=config_version, plans=plans),
    )
    await callback.answer()


async def handle_plan_request(callback, *, workflow) -> None:
    parsed = _parse_plan_callback(str(callback.data))
    if parsed is None:
        await callback.message.answer(text("handler.unknown_tariff"))
        await callback.answer()
        return

    config_version, plan_id = parsed
    user = callback.from_user
    result = workflow.request_access(
        telegram_id=int(user.id),
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
        config_version=config_version,
        plan_id=plan_id,
    )
    await callback.message.answer(result.text)
    await callback.answer()


async def handle_my_traffic(callback, *, workflow) -> None:
    views = workflow.build_user_traffic_views(telegram_id=int(callback.from_user.id))
    await callback.message.answer(render_user_traffic(views))
    await callback.answer()


async def handle_my_tariff(callback, *, workflow) -> None:
    devices = workflow.list_user_devices(telegram_id=int(callback.from_user.id))
    await callback.message.answer(render_my_tariff(devices, now=_utc_now()))
    await callback.answer()


async def handle_my_devices(callback, *, workflow) -> None:
    devices = workflow.list_user_devices(telegram_id=int(callback.from_user.id))
    await callback.message.answer(render_my_devices(devices, now=_utc_now()))
    for device in devices:
        await callback.message.answer(
            f"Device #{device['id']}",
            reply_markup=build_user_device_keyboard(
                device_id=int(device["id"]),
                can_resend=_device_config_material_status(device) == "available",
            ),
        )
    if devices:
        await callback.message.answer(
            "Reset all devices",
            reply_markup=build_user_devices_reset_keyboard(),
        )
    await callback.answer()


async def handle_user_resend_config(callback, *, workflow) -> None:
    device_id = _parse_int_suffix(str(callback.data), USER_RESEND_PREFIX)
    if device_id is None:
        await callback.message.answer(text("handler.unknown_resend"))
        await callback.answer()
        return

    try:
        result = workflow.build_user_resend_delivery(
            telegram_id=int(callback.from_user.id),
            device_id=device_id,
        )
    except ConfigMaterialUnavailable:
        await callback.message.answer(text("handler.config_unavailable"))
        await callback.answer()
        return
    if result is None:
        await callback.message.answer(text("handler.device_not_found"))
        await callback.answer()
        return

    await _send_delivery(callback.bot, result)
    await callback.message.answer(text("handler.config_resent", device_id=device_id))
    await callback.answer()


async def handle_user_revoke_device(callback, *, workflow) -> None:
    device_id = _parse_int_suffix(str(callback.data), USER_REVOKE_PREFIX)
    if device_id is None:
        await callback.message.answer(text("handler.unknown_delete"))
        await callback.answer()
        return

    await callback.message.answer(
        text("handler.confirm_device_delete", device_id=device_id),
        reply_markup=build_user_revoke_confirm_keyboard(device_id=device_id),
    )
    await callback.answer()


async def handle_user_revoke_device_confirm(callback, *, workflow) -> None:
    await callback.answer()
    device_id = _parse_int_suffix(str(callback.data), USER_REVOKE_CONFIRM_PREFIX)
    if device_id is None:
        await callback.message.answer(text("handler.unknown_delete_confirm"))
        return

    try:
        revoked = workflow.revoke_user_device(
            telegram_id=int(callback.from_user.id),
            device_id=device_id,
        )
    except PeerApplyError as exc:
        await callback.message.answer(
            _peer_apply_failure_message(
                headline="VPS peer revoke failed. Device was not removed in the bot.",
                exc=exc,
                next_checks=(
                    "Next checks: run server check, then revoke-peer --dry-run "
                    "for this peer."
                ),
            )
        )
        return

    if not revoked:
        await callback.message.answer(text("handler.device_not_found"))
        return

    await callback.message.answer(
        text("handler.device_removed", device_id=device_id)
    )


async def handle_user_reset_devices(callback, *, workflow) -> None:
    await callback.message.answer(
        text("handler.confirm_reset"),
        reply_markup=build_user_reset_confirm_keyboard(),
    )
    await callback.answer()


async def handle_user_reset_devices_confirm(callback, *, workflow) -> None:
    await callback.answer()
    try:
        changed = workflow.reset_user_devices(telegram_id=int(callback.from_user.id))
    except PeerApplyError as exc:
        await callback.message.answer(
            _peer_apply_failure_message(
                headline="VPS peer revoke failed. Devices were not removed in the bot.",
                exc=exc,
                next_checks=(
                    "Next checks: run server check, then revoke-peer --dry-run "
                    "for affected peers."
                ),
            )
        )
        return
    await callback.message.answer(
        text("handler.devices_removed", count=changed)
    )


async def handle_admin_pending(callback, *, workflow) -> None:
    await callback.answer()
    admin_telegram_id = int(callback.from_user.id)
    if not workflow.is_admin(admin_telegram_id):
        await callback.message.answer(text("handler.admin_required"))
        return

    orders = workflow.list_pending_orders(admin_telegram_id=admin_telegram_id)
    await callback.message.answer(
        render_admin_pending_orders(orders),
        reply_markup=build_admin_navigation_keyboard(),
    )
    for order in orders:
        await callback.message.answer(
            f"Order #{order['id']}",
            reply_markup=build_admin_order_keyboard(
                order_id=int(order["id"]),
                requested_config_version=_order_requested_config_version(order),
            ),
        )


async def handle_admin_users(callback, *, workflow) -> None:
    admin_telegram_id = int(callback.from_user.id)
    if not workflow.is_admin(admin_telegram_id):
        await callback.message.answer(text("handler.admin_required"))
        await callback.answer()
        return

    rendered_text, keyboard = render_admin_users(
        workflow.list_users(admin_telegram_id=admin_telegram_id)
    )
    await callback.message.answer(rendered_text, reply_markup=keyboard)
    await callback.answer()


async def handle_admin_status(callback, *, workflow) -> None:
    await callback.answer()
    admin_telegram_id = int(callback.from_user.id)
    status = workflow.get_operator_status(admin_telegram_id=admin_telegram_id)
    if status is None:
        await callback.message.answer(text("handler.admin_required"))
        return
    locale = workflow.get_user_locale(telegram_id=admin_telegram_id)
    rendered_text, keyboard = render_admin_status(status, locale=locale)
    await callback.message.answer(rendered_text, reply_markup=keyboard)


async def handle_admin_servers(callback, *, workflow) -> None:
    await callback.answer()
    admin_telegram_id = int(callback.from_user.id)
    statuses = workflow.get_operator_server_statuses(
        admin_telegram_id=admin_telegram_id,
    )
    if statuses is None:
        await callback.message.answer(text("handler.admin_required"))
        return
    locale = workflow.get_user_locale(telegram_id=admin_telegram_id)
    rendered_text, keyboard = render_admin_servers(statuses, locale=locale)
    await callback.message.answer(rendered_text, reply_markup=keyboard)


async def handle_admin_integrations(callback, *, workflow) -> None:
    await callback.answer()
    admin_telegram_id = int(callback.from_user.id)
    statuses = workflow.get_operator_credential_statuses(
        admin_telegram_id=admin_telegram_id,
    )
    if statuses is None:
        await callback.message.answer(text("handler.admin_required"))
        return
    locale = workflow.get_user_locale(telegram_id=admin_telegram_id)
    rendered_text, keyboard = render_admin_integrations(statuses, locale=locale)
    await callback.message.answer(rendered_text, reply_markup=keyboard)


async def handle_admin_traffic(callback, *, workflow) -> None:
    await callback.answer()
    admin_telegram_id = int(callback.from_user.id)
    if not workflow.is_admin(admin_telegram_id):
        await callback.message.answer(text("handler.admin_required"))
        return

    views = workflow.build_admin_traffic_views(
        admin_telegram_id=admin_telegram_id,
    )
    locale = workflow.get_user_locale(telegram_id=admin_telegram_id)
    rendered_text, keyboard = render_admin_traffic(views, locale=locale)
    await callback.message.answer(rendered_text, reply_markup=keyboard)


async def handle_admin_approve(callback, *, workflow) -> None:
    await callback.answer()
    admin_telegram_id = int(callback.from_user.id)
    parsed = parse_admin_approve_callback(str(callback.data))
    if parsed is None:
        await callback.message.answer("Unknown admin approval request.")
        return
    if not workflow.is_admin(admin_telegram_id):
        await callback.message.answer(text("handler.admin_required"))
        return

    order_id, config_version = parsed
    try:
        result = workflow.approve_order(
            admin_telegram_id=admin_telegram_id,
            order_id=order_id,
            config_version=config_version,
        )
    except PeerApplyError as exc:
        await callback.message.answer(
            _peer_apply_failure_message(
                headline="VPS peer apply failed. Config was not sent to the user.",
                exc=exc,
                next_checks=(
                    "Next checks: run server check, then apply-peer --dry-run "
                    "for a test peer."
                ),
            )
        )
        return
    if result is None:
        await callback.message.answer(text("handler.admin_required"))
        return

    await callback.message.answer(result.admin_text)
    try:
        await _send_delivery(callback.bot, result)
    except Exception:
        await callback.message.answer(
            "Could not deliver config to the user automatically. "
            "The config was not sent here because it contains client secrets. "
            "Ask the user to open the bot and retry delivery, or use the "
            "operator-local private handoff gate."
        )


async def handle_admin_template(callback, *, workflow) -> None:
    admin_telegram_id = int(callback.from_user.id)
    template_text = workflow.get_config_ready_template(
        admin_telegram_id=admin_telegram_id
    )
    if template_text is None:
        await callback.message.answer(text("handler.admin_required"))
        await callback.answer()
        return

    text, keyboard = render_admin_template(template_text)
    await callback.message.answer(text, reply_markup=keyboard)
    await callback.answer()


async def handle_admin_reset_template(callback, *, workflow) -> None:
    admin_telegram_id = int(callback.from_user.id)
    if not workflow.reset_config_ready_template(admin_telegram_id=admin_telegram_id):
        await callback.message.answer(text("handler.admin_required"))
        await callback.answer()
        return

    await callback.message.answer(text("handler.template_reset"))
    await callback.answer()


async def handle_admin_resend_config(callback, *, workflow) -> None:
    admin_telegram_id = int(callback.from_user.id)
    device_id = _parse_int_suffix(str(callback.data), ADMIN_RESEND_PREFIX)
    if device_id is None:
        await callback.message.answer(text("handler.unknown_resend"))
        await callback.answer()
        return

    try:
        result = workflow.build_resend_delivery(
            admin_telegram_id=admin_telegram_id,
            device_id=device_id,
        )
    except ConfigMaterialUnavailable:
        await callback.message.answer(text("handler.config_unavailable"))
        await callback.answer()
        return
    if result is None:
        await callback.message.answer(text("handler.admin_required"))
        await callback.answer()
        return

    await _send_delivery(callback.bot, result)
    await callback.message.answer(text("handler.config_resent", device_id=device_id))
    await callback.answer()


async def handle_admin_grant(message, *, workflow) -> None:
    admin_telegram_id = int(message.from_user.id)
    parsed = _parse_target_user_command(str(getattr(message, "text", "")))
    if parsed is None:
        await message.answer("Usage: /admin_grant <telegram_id> [username] [first_name]")
        return
    target_telegram_id, username, first_name = parsed
    if not workflow.grant_admin(
        admin_telegram_id=admin_telegram_id,
        target_telegram_id=target_telegram_id,
        username=username,
        first_name=first_name,
        last_name=None,
    ):
        await message.answer(text("handler.admin_required"))
        return
    await message.answer(f"Admin role granted to telegram_id={target_telegram_id}.")


async def handle_admin_add_user(message, *, workflow) -> None:
    admin_telegram_id = int(message.from_user.id)
    parsed = _parse_target_user_command(str(getattr(message, "text", "")))
    if parsed is None:
        await message.answer("Usage: /admin_add_user <telegram_id> [username] [first_name]")
        return
    target_telegram_id, username, first_name = parsed
    user_id = workflow.create_manual_user(
        admin_telegram_id=admin_telegram_id,
        target_telegram_id=target_telegram_id,
        username=username,
        first_name=first_name,
        last_name=None,
    )
    if user_id is None:
        await message.answer(text("handler.admin_required"))
        return
    await message.answer(f"User was added: #{user_id}, telegram_id={target_telegram_id}.")


async def handle_admin_create_order(message, *, workflow) -> None:
    admin_telegram_id = int(message.from_user.id)
    parsed = _parse_create_order_command(str(getattr(message, "text", "")))
    if parsed is None:
        await message.answer(
            "Usage: /admin_create_order <telegram_id> <config_version> [plan_id]"
        )
        return
    target_telegram_id, config_version, plan_id = parsed
    result = workflow.create_manual_access_request(
        admin_telegram_id=admin_telegram_id,
        target_telegram_id=target_telegram_id,
        username=None,
        first_name=None,
        last_name=None,
        config_version=config_version,
        plan_id=plan_id,
    )
    if result is None:
        await message.answer(text("handler.admin_required"))
        return
    await message.answer(result.text)


async def handle_admin_issue_config(message, *, workflow) -> None:
    admin_telegram_id = int(message.from_user.id)
    if not workflow.is_configured_admin(admin_telegram_id):
        await message.answer("Admin access required.")
        return
    try:
        parsed = parse_admin_issue_config_command(
            str(getattr(message, "text", ""))
        )
    except ValueError:
        await message.answer("Invalid recipient, device, or platform.")
        return
    if parsed is None:
        await message.answer(
            "Usage: /admin_issue_config recipient | device | platform"
        )
        return
    recipient_label, device_label, platform = parsed
    try:
        request_id = _telegram_message_request_id(message)
        result = workflow.issue_admin_config(
            admin_telegram_id=admin_telegram_id,
            request_id=request_id,
            recipient_label=recipient_label,
            device_label=device_label,
            platform=platform,
        )
    except ValueError:
        await message.answer("Invalid recipient, device, or platform.")
        return
    except RuntimeError as exc:
        if str(exc) != "VPS writes are disabled":
            raise
        await message.answer("Config issuance is disabled.")
        return
    if result is None:
        await message.answer("Admin access required.")
        return
    await _send_admin_config_handoff(
        message,
        workflow=workflow,
        admin_telegram_id=admin_telegram_id,
        result=result,
        success_text=f"Config for device #{result.device_id} delivered to admin.",
        failure_text=(
            "Config delivery failed. Safely resend the existing device with "
            f"/admin_resend_issued_config {result.device_id}."
        ),
    )


def _telegram_message_request_id(message) -> str:
    message_id = getattr(message, "message_id", None)
    chat_id = getattr(getattr(message, "chat", None), "id", None)
    if (
        isinstance(message_id, bool)
        or not isinstance(message_id, int)
        or message_id <= 0
        or isinstance(chat_id, bool)
        or not isinstance(chat_id, int)
    ):
        raise ValueError("Telegram message identity is unavailable")
    return f"telegram-{chat_id}-{message_id}"


async def handle_admin_resend_issued_config(message, *, workflow) -> None:
    admin_telegram_id = int(message.from_user.id)
    if not workflow.is_configured_admin(admin_telegram_id):
        await message.answer("Admin access required.")
        return
    parts = str(getattr(message, "text", "")).split()
    if len(parts) != 2:
        await message.answer("Usage: /admin_resend_issued_config device_id")
        return
    try:
        device_id = int(parts[1])
    except ValueError:
        await message.answer("Usage: /admin_resend_issued_config device_id")
        return
    try:
        result = workflow.build_admin_config_handoff_for_device(
            admin_telegram_id=admin_telegram_id,
            device_id=device_id,
        )
    except ConfigMaterialUnavailable:
        await message.answer("Config is unavailable for this device.")
        return
    if result is None:
        await message.answer("Admin access required.")
        return
    await _send_admin_config_handoff(
        message,
        workflow=workflow,
        admin_telegram_id=admin_telegram_id,
        result=result,
        success_text=f"Config for existing device #{device_id} delivered to admin.",
        failure_text=(
            f"Config resend failed. Retry /admin_resend_issued_config {device_id}."
        ),
    )


async def _send_admin_config_handoff(
    message,
    *,
    workflow,
    admin_telegram_id: int,
    result,
    success_text: str,
    failure_text: str,
) -> None:
    try:
        telegram_message = await message.bot.send_document(
            chat_id=admin_telegram_id,
            document=BufferedInputFile(result.config_bytes, filename=result.filename),
            caption=None,
        )
    except Exception as exc:
        workflow.record_admin_config_delivery(
            admin_telegram_id=admin_telegram_id,
            passport_device_id=result.passport_device_id,
            delivered=False,
            reference=f"telegram_error:{type(exc).__name__}",
        )
        await message.answer(failure_text)
        return
    message_id = getattr(telegram_message, "message_id", None)
    workflow.record_admin_config_delivery(
        admin_telegram_id=admin_telegram_id,
        passport_device_id=result.passport_device_id,
        delivered=True,
        reference=(
            f"telegram_message:{message_id}"
            if message_id is not None
            else "telegram_document:confirmed"
        ),
    )
    await message.answer(success_text)


def is_request_config_callback(data: str) -> bool:
    return data == REQUEST_CONFIG_PREFIX


def is_awg3_select_callback(data: str) -> bool:
    return data.startswith(f"{AWG3_SELECT_PREFIX}:")


def is_awg3_confirm_callback(data: str) -> bool:
    return data.startswith(f"{AWG3_CONFIRM_PREFIX}:")


def is_language_callback(data: str) -> bool:
    return data.startswith(f"{LANGUAGE_CALLBACK_PREFIX}:")


def is_config_version_callback(data: str) -> bool:
    return data.startswith(f"{REQUEST_CONFIG_PREFIX}:")


def is_plan_request_callback(data: str) -> bool:
    return data.startswith(f"{REQUEST_PLAN_PREFIX}:")


def is_my_traffic_callback(data: str) -> bool:
    return data == MY_TRAFFIC_CALLBACK


def is_my_tariff_callback(data: str) -> bool:
    return data == MY_TARIFF_CALLBACK


def is_my_devices_callback(data: str) -> bool:
    return data == MY_DEVICES_CALLBACK


def is_user_resend_callback(data: str) -> bool:
    return data.startswith(f"{USER_RESEND_PREFIX}:")


def is_user_revoke_callback(data: str) -> bool:
    return data.startswith(f"{USER_REVOKE_PREFIX}:")


def is_user_revoke_confirm_callback(data: str) -> bool:
    return data.startswith(f"{USER_REVOKE_CONFIRM_PREFIX}:")


def is_user_reset_devices_callback(data: str) -> bool:
    return data == USER_RESET_DEVICES_CALLBACK


def is_user_reset_devices_confirm_callback(data: str) -> bool:
    return data == USER_RESET_DEVICES_CONFIRM_CALLBACK


def is_admin_pending_callback(data: str) -> bool:
    return data == ADMIN_PENDING_CALLBACK


def is_admin_status_callback(data: str) -> bool:
    return data == ADMIN_STATUS_CALLBACK


def is_admin_approve_callback(data: str) -> bool:
    return data.startswith(f"{ADMIN_APPROVE_PREFIX}:")


def is_admin_template_callback(data: str) -> bool:
    return data == ADMIN_TEMPLATES_CALLBACK


def is_admin_users_callback(data: str) -> bool:
    return data == ADMIN_USERS_CALLBACK


def is_admin_template_reset_callback(data: str) -> bool:
    return data == ADMIN_TEMPLATE_RESET_CALLBACK


def is_admin_resend_callback(data: str) -> bool:
    return data.startswith(f"{ADMIN_RESEND_PREFIX}:")


async def _send_delivery(bot, result) -> None:
    await bot.send_message(
        chat_id=result.user_telegram_id,
        text=result.delivery.message_text,
    )
    if getattr(result.delivery, "vpn_import_link_text", ""):
        await bot.send_message(
            chat_id=result.user_telegram_id,
            text=result.delivery.vpn_import_link_text,
            reply_markup=_build_vpn_import_link_copy_markup(result.delivery),
        )
    if getattr(result.delivery, "app_links_text", ""):
        await bot.send_message(
            chat_id=result.user_telegram_id,
            text=result.delivery.app_links_text,
        )
    await bot.send_document(
        chat_id=result.user_telegram_id,
        document=BufferedInputFile(
            result.delivery.config_bytes,
            filename=result.delivery.config_filename,
        ),
        caption=result.delivery.config_caption,
    )
    await bot.send_photo(
        chat_id=result.user_telegram_id,
        photo=BufferedInputFile(
            result.delivery.qr_png_bytes,
            filename=result.delivery.qr_filename,
        ),
        caption=result.delivery.qr_caption,
    )


async def _send_awg3_delivery(bot, *, chat_id: int, delivery) -> None:
    await bot.send_document(
        chat_id=chat_id,
        document=BufferedInputFile(
            delivery.config_bytes,
            filename=delivery.config_filename,
        ),
        caption=delivery.config_caption,
    )
    await bot.send_photo(
        chat_id=chat_id,
        photo=BufferedInputFile(
            delivery.qr_png_bytes,
            filename=delivery.qr_filename,
        ),
        caption=delivery.qr_caption,
    )


def _parse_awg3_select_callback(data: str) -> str | None:
    match = _AWG3_SELECT_RE.fullmatch(data)
    return match.group(1) if match is not None else None


def _parse_awg3_confirm_callback(data: str) -> str | None:
    match = _AWG3_CONFIRM_RE.fullmatch(data)
    return match.group(1) if match is not None else None


def _is_private_callback(callback) -> bool:
    return getattr(getattr(callback.message, "chat", None), "type", None) == "private"


def _awg2_offer_markup() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=text("button.awg2_choose"),
                    callback_data=f"{REQUEST_CONFIG_PREFIX}:amneziawg_v2",
                )
            ]
        ]
    )


def _build_vpn_import_link_copy_markup(delivery) -> InlineKeyboardMarkup | None:
    copy_text = getattr(delivery, "vpn_import_link_copy_text", None)
    button_text = getattr(delivery, "vpn_import_link_copy_button_text", "")
    if not copy_text or not button_text:
        return None
    if len(copy_text) > TELEGRAM_COPY_TEXT_MAX_LENGTH:
        return None
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=button_text,
                    copy_text=CopyTextButton(text=copy_text),
                )
            ]
        ]
    )


def _order_requested_config_version(order) -> str | None:
    try:
        config_version = order["requested_config_version"]
    except (KeyError, IndexError):
        return None
    if config_version is None:
        return None
    return str(config_version)


def _parse_int_suffix(data: str, prefix: str) -> int | None:
    marker = f"{prefix}:"
    if not data.startswith(marker):
        return None
    try:
        return int(data.removeprefix(marker))
    except ValueError:
        return None


def _device_config_material_status(device) -> str:
    try:
        return str(device["config_material_status"])
    except (KeyError, IndexError):
        return "available"


def _peer_apply_failure_message(
    *,
    headline: str,
    exc: PeerApplyError,
    next_checks: str,
) -> str:
    details = redact(str(exc)).strip() or "<empty>"
    return (
        f"{headline}\n"
        f"Error type: {type(exc).__name__}\n"
        f"Details: {details}\n"
        f"{next_checks}"
    )


def _parse_plan_callback(data: str) -> tuple[str, str] | None:
    marker = f"{REQUEST_PLAN_PREFIX}:"
    if not data.startswith(marker):
        return None
    parts = data.removeprefix(marker).split(":", maxsplit=1)
    if len(parts) != 2:
        return None
    return parts[0], parts[1]


def _parse_target_user_command(text: str) -> tuple[int, str | None, str | None] | None:
    parts = text.split()
    if len(parts) < 2:
        return None
    try:
        target_telegram_id = int(parts[1])
    except ValueError:
        return None
    username = parts[2] if len(parts) >= 3 else None
    first_name = parts[3] if len(parts) >= 4 else None
    return target_telegram_id, username, first_name


def _parse_create_order_command(text: str) -> tuple[int, str, str | None] | None:
    parts = text.split()
    if len(parts) < 3:
        return None
    try:
        target_telegram_id = int(parts[1])
    except ValueError:
        return None
    plan_id = parts[3] if len(parts) >= 4 else None
    return target_telegram_id, parts[2], plan_id


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
