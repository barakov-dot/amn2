from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from app.bot.texts import DEFAULT_LOCALE, text
from app.db.repositories import user_display_label
from app.services.device_passports import DEVICE_PLATFORMS
from app.services.operator_credential_status import OperatorCredentialStatusView
from app.services.operator_server_status import OperatorServerStatusView
from app.services.traffic import DeviceTrafficView
from app.vpn.config_templates import SUPPORTED_CLIENT_CONFIG_VERSIONS


REQUEST_CONFIG_PREFIX = "user:request_config"
REQUEST_PLAN_PREFIX = "user:request_plan"
LANGUAGE_CALLBACK_PREFIX = "user:language"
MY_TARIFF_CALLBACK = "user:tariff"
MY_TRAFFIC_CALLBACK = "user:traffic"
MY_DEVICES_CALLBACK = "user:devices"
USER_RESEND_PREFIX = "user:resend"
USER_REVOKE_PREFIX = "user:revoke"
USER_REVOKE_CONFIRM_PREFIX = "user:revoke_confirm"
USER_RESET_DEVICES_CALLBACK = "user:reset_devices"
USER_RESET_DEVICES_CONFIRM_CALLBACK = "user:reset_devices_confirm"
ADMIN_PENDING_CALLBACK = "admin:pending"
ADMIN_STATUS_CALLBACK = "admin:status"
ADMIN_SERVERS_CALLBACK = "admin:servers"
ADMIN_INTEGRATIONS_CALLBACK = "admin:integrations"
ADMIN_TRAFFIC_CALLBACK = "admin:traffic"
ADMIN_TEMPLATES_CALLBACK = "admin:templates"
ADMIN_USERS_CALLBACK = "admin:users"
ADMIN_TEMPLATE_RESET_CALLBACK = "admin:template:reset"
ADMIN_APPROVE_PREFIX = "admin:approve"
ADMIN_RESEND_PREFIX = "admin:resend"
ADMIN_ISSUE_CONFIG_COMMAND = "/admin_issue_config"
ADMIN_CONFIG_LABEL_MAX_LENGTH = 120

VERSION_LABELS = {
    "amneziawg_v1_5": "AmneziaWG 1.5",
    "amneziawg_v2": "AmneziaWG 2.0",
}
PREFERRED_CONFIG_VERSION = "amneziawg_v2"
SUPPORTED_LOCALES = ("ru", "en")


def render_language_prompt() -> str:
    return "🌐 Выберите язык / Choose your language:"


def build_language_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🇷🇺 Русский",
                    callback_data=f"{LANGUAGE_CALLBACK_PREFIX}:ru",
                ),
                InlineKeyboardButton(
                    text="🇬🇧 English",
                    callback_data=f"{LANGUAGE_CALLBACK_PREFIX}:en",
                ),
            ]
        ]
    )


def build_main_menu(*, is_admin: bool, locale: str = DEFAULT_LOCALE) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(
                text=text("button.request_config", locale=locale),
                callback_data=REQUEST_CONFIG_PREFIX,
            )
        ],
        [
            InlineKeyboardButton(
                text=text("button.my_tariff", locale=locale),
                callback_data=MY_TARIFF_CALLBACK,
            )
        ],
        [
            InlineKeyboardButton(
                text=text("button.my_traffic", locale=locale),
                callback_data=MY_TRAFFIC_CALLBACK,
            )
        ],
        [
            InlineKeyboardButton(
                text=text("button.my_devices", locale=locale),
                callback_data=MY_DEVICES_CALLBACK,
            )
        ],
    ]
    if is_admin:
        rows.append(
            [
                InlineKeyboardButton(
                    text=text("button.admin", locale=locale),
                    callback_data=ADMIN_PENDING_CALLBACK,
                )
            ]
        )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def build_config_version_keyboard(*, prefix: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=VERSION_LABELS[version],
                    callback_data=f"{prefix}:{version}",
                )
            ]
            for version in _ordered_config_versions(PREFERRED_CONFIG_VERSION)
        ]
    )


def build_plan_keyboard(
    *,
    config_version: str,
    plans: Iterable[Mapping[str, object]],
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=str(plan["name"]),
                    callback_data=f"{REQUEST_PLAN_PREFIX}:{config_version}:{plan['id']}",
                )
            ]
            for plan in plans
        ]
    )


def build_admin_order_keyboard(
    *,
    order_id: int,
    requested_config_version: str | None = None,
    locale: str = DEFAULT_LOCALE,
) -> InlineKeyboardMarkup:
    prefix = f"{ADMIN_APPROVE_PREFIX}:{order_id}"
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=f"{text('button.approve', locale=locale)}: {VERSION_LABELS[version]}",
                    callback_data=f"{prefix}:{version}",
                )
            ]
            for version in _ordered_config_versions(requested_config_version)
        ]
    )


def build_admin_resend_keyboard(
    *,
    device_id: int,
    locale: str = DEFAULT_LOCALE,
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=text("button.resend_config", locale=locale),
                    callback_data=f"{ADMIN_RESEND_PREFIX}:{device_id}",
                )
            ]
        ]
    )


def build_user_device_keyboard(
    *,
    device_id: int,
    can_resend: bool = True,
    can_delete: bool = True,
    locale: str = DEFAULT_LOCALE,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if can_resend:
        rows.append(
            [
                InlineKeyboardButton(
                    text=text("button.resend_config", locale=locale),
                    callback_data=f"{USER_RESEND_PREFIX}:{device_id}",
                )
            ]
        )
    if can_delete:
        rows.append(
            [
                InlineKeyboardButton(
                    text=text("button.delete_device", locale=locale),
                    callback_data=f"{USER_REVOKE_PREFIX}:{device_id}",
                )
            ],
        )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def parse_admin_issue_config_command(text_value: str) -> tuple[str, str, str] | None:
    command, separator, arguments = text_value.strip().partition(" ")
    if command.split("@", maxsplit=1)[0] != ADMIN_ISSUE_CONFIG_COMMAND or not separator:
        return None
    parts = tuple(part.strip() for part in arguments.split("|"))
    if len(parts) != 3 or any(not part for part in parts):
        return None
    if any(len(part) > ADMIN_CONFIG_LABEL_MAX_LENGTH for part in parts):
        raise ValueError("admin config label is too long")
    platform = parts[2].lower()
    if platform not in DEVICE_PLATFORMS:
        raise ValueError("unsupported device platform")
    return parts[0], parts[1], platform


def build_user_devices_reset_keyboard(
    *,
    locale: str = DEFAULT_LOCALE,
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=text("button.reset_all_devices", locale=locale),
                    callback_data=USER_RESET_DEVICES_CALLBACK,
                )
            ]
        ]
    )


def build_user_revoke_confirm_keyboard(
    *,
    device_id: int,
    locale: str = DEFAULT_LOCALE,
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=text("button.confirm_delete", locale=locale),
                    callback_data=f"{USER_REVOKE_CONFIRM_PREFIX}:{device_id}",
                )
            ]
        ]
    )


def build_user_reset_confirm_keyboard(
    *,
    locale: str = DEFAULT_LOCALE,
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=text("button.confirm_reset", locale=locale),
                    callback_data=USER_RESET_DEVICES_CONFIRM_CALLBACK,
                )
            ]
        ]
    )


def build_admin_navigation_keyboard(
    *,
    locale: str = DEFAULT_LOCALE,
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=text("button.pending_orders", locale=locale),
                    callback_data=ADMIN_PENDING_CALLBACK,
                )
            ],
            [
                InlineKeyboardButton(
                    text=text("button.status", locale=locale),
                    callback_data=ADMIN_STATUS_CALLBACK,
                )
            ],
            [
                InlineKeyboardButton(
                    text=text("button.servers", locale=locale),
                    callback_data=ADMIN_SERVERS_CALLBACK,
                )
            ],
            [
                InlineKeyboardButton(
                    text=text("button.integrations", locale=locale),
                    callback_data=ADMIN_INTEGRATIONS_CALLBACK,
                )
            ],
            [
                InlineKeyboardButton(
                    text=text("button.traffic", locale=locale),
                    callback_data=ADMIN_TRAFFIC_CALLBACK,
                )
            ],
            [
                InlineKeyboardButton(
                    text=text("button.templates", locale=locale),
                    callback_data=ADMIN_TEMPLATES_CALLBACK,
                )
            ],
            [
                InlineKeyboardButton(
                    text=text("button.users", locale=locale),
                    callback_data=ADMIN_USERS_CALLBACK,
                )
            ],
        ]
    )


def render_start_text(
    *,
    first_name: str | None,
    is_admin: bool,
    locale: str = DEFAULT_LOCALE,
) -> str:
    greeting = (
        text("start.hello_name", first_name=first_name, locale=locale)
        if first_name
        else text("start.hello", locale=locale)
    )
    role = (
        text("start.admin_role", locale=locale)
        if is_admin
        else text("start.user_role", locale=locale)
    )
    return f"{greeting}\n{role}\n{text('start.choose_action', locale=locale)}"


def render_config_version_prompt() -> str:
    return text("prompt.config_version")


def render_plan_prompt(*, config_version: str) -> str:
    return text(
        "prompt.plan",
        config_version_label=_version_label(config_version),
    )


def render_access_request_created(
    *,
    order_id: int,
    config_version: str,
    plan_name: str | None = None,
) -> str:
    lines = [
        text("access.created", order_id=order_id),
        text("access.requested_config", config_version_label=_version_label(config_version)),
    ]
    if plan_name is not None:
        lines.append(text("access.plan", plan_name=plan_name))
    lines.append(text("access.admin_notice"))
    return "\n".join(lines)


def render_my_tariff(devices: Iterable[Mapping[str, object]], *, now: str) -> str:
    lines = [text("my_tariff.title")]
    has_devices = False
    for device in devices:
        has_devices = True
        duration_days = int(device["duration_days"])
        expires_at = str(device["expires_at"]) if device["expires_at"] is not None else None
        lines.extend(
            [
                "",
                str(device["name"]),
                f"{text('common.status')}: {device['status']}",
                f"{text('common.tariff')}: {_format_days_ru(duration_days)}",
                f"{text('common.expires')}: {expires_at or 'unknown'}",
                f"{text('common.days_left')}: {_days_left(expires_at, now) if expires_at else 'unknown'}",
            ]
        )
    if not has_devices:
        lines.append(text("my_tariff.empty"))
    return "\n".join(lines)


def render_my_devices(devices: Iterable[Mapping[str, object]], *, now: str) -> str:
    lines = [text("my_devices.title")]
    has_devices = False
    for device in devices:
        has_devices = True
        expires_at = str(device["expires_at"]) if device["expires_at"] is not None else None
        connected = bool(_row_get(device, "first_connected_at") or _row_get(device, "last_connected_at"))
        lines.extend(
            [
                "",
                f"#{device['id']} {device['name']}",
                f"{text('common.config')}: {_version_label(str(device['config_version']))}",
                f"{text('common.status')}: {device['status']}",
                f"{text('common.tariff')}: {_format_days_ru(int(device['duration_days']))}",
                f"{text('common.days_left')}: {_days_left(expires_at, now) if expires_at else 'unknown'}",
                f"{text('common.connected')}: {text('common.yes') if connected else text('common.no')}",
            ]
        )
        if _row_get(device, "config_material_status") == "external_only":
            lines.append(text("my_devices.external_only"))
    if not has_devices:
        lines.append(text("my_devices.empty"))
    return "\n".join(lines)


def render_admin_template(template_text: str) -> tuple[str, InlineKeyboardMarkup]:
    body = (
        "Шаблон сообщения с конфигом\n\n"
        f"{template_text}\n\n"
        "Редактирование идет через workflow шаблонов; сброс доступен ниже."
    )
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Сбросить шаблон",
                    callback_data=ADMIN_TEMPLATE_RESET_CALLBACK,
                )
            ]
        ]
    )
    return body, keyboard


def _days_left(expires_at: str, now: str) -> int:
    expires_dt = _parse_datetime(expires_at)
    now_dt = _parse_datetime(now)
    seconds_left = (expires_dt - now_dt).total_seconds()
    if seconds_left <= 0:
        return 0
    return int((seconds_left + 86399) // 86400)


def _format_days_ru(days: int) -> str:
    if days % 10 == 1 and days % 100 != 11:
        unit = "день"
    elif 2 <= days % 10 <= 4 and not 12 <= days % 100 <= 14:
        unit = "дня"
    else:
        unit = "дней"
    return f"{days} {unit}"


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def render_admin_approval(
    *,
    order_id: int,
    device_id: int,
    user_telegram_id: int,
    config_version: str,
) -> str:
    return (
        f"Заявка #{order_id} одобрена.\n"
        f"Создано устройство #{device_id} для telegram_id={user_telegram_id}.\n"
        f"Конфиг: {_version_label(config_version)}."
    )


def render_user_config_ready(*, config_version: str) -> str:
    return f"Ваш VPN-конфиг {_version_label(config_version)} готов."


def render_user_traffic(views: Iterable[DeviceTrafficView]) -> str:
    lines = [text("traffic.user_title")]
    has_devices = False
    for view in views:
        has_devices = True
        lines.extend(_render_device_traffic_lines(view))
    if not has_devices:
        lines.append(text("my_devices.empty"))
    return "\n".join(lines)


def render_admin_pending_orders(orders: Iterable[Mapping[str, object]]) -> str:
    lines = [text("admin.pending_title")]
    has_orders = False
    for order in orders:
        has_orders = True
        lines.append(
            "#"
            f"{order['id']}: "
            f"{_format_user_identity(order)} "
            f"({order['status']}, {order['created_at']})"
            f"{_format_requested_config_version(order)}"
        )
    if not has_orders:
        lines.append(text("admin.no_pending"))
    return "\n".join(lines)


def render_admin_traffic(
    views: Iterable[DeviceTrafficView],
    *,
    locale: str = DEFAULT_LOCALE,
) -> tuple[str, InlineKeyboardMarkup]:
    lines = [text("traffic.admin_title", locale=locale)]
    has_devices = False
    for view in views:
        has_devices = True
        lines.extend(_render_device_traffic_lines(view, locale=locale))
    if not has_devices:
        lines.append(text("my_devices.empty", locale=locale))
    return "\n".join(lines), build_admin_navigation_keyboard(locale=locale)


def render_admin_status(
    status,
    *,
    locale: str = DEFAULT_LOCALE,
) -> tuple[str, InlineKeyboardMarkup]:
    def state(value: bool) -> str:
        key = "common.enabled" if value else "common.disabled"
        return text(key, locale=locale)

    lines = [
        text("admin.status_title", locale=locale),
        text("admin.status_mode", locale=locale),
        "",
        text(
            "admin.status_users",
            locale=locale,
            active=status.users_active,
            blocked=status.users_blocked,
        ),
        text(
            "admin.status_servers",
            locale=locale,
            active=status.servers_active,
            degraded=status.servers_degraded,
        ),
        text(
            "admin.status_devices",
            locale=locale,
            active=status.devices_active,
            disabled=status.devices_disabled,
        ),
        text("admin.status_pending", locale=locale, count=status.pending_orders),
        text(
            "admin.status_credentials",
            locale=locale,
            active=status.credentials_active,
            due=status.credentials_rotation_due,
            expired=status.credentials_expired,
            revoked=status.credentials_revoked,
        ),
        "",
        text(
            "admin.status_vps_write",
            locale=locale,
            state=state(status.vps_writes_enabled),
        ),
        text(
            "admin.status_config_delivery",
            locale=locale,
            state=state(status.public_config_delivery_enabled),
        ),
        text(
            "admin.status_public",
            locale=locale,
            state=state(status.public_exposure_enabled),
        ),
    ]
    return "\n".join(lines), build_admin_navigation_keyboard(locale=locale)


def render_admin_servers(
    statuses: Iterable[OperatorServerStatusView],
    *,
    locale: str = DEFAULT_LOCALE,
) -> tuple[str, InlineKeyboardMarkup]:
    lines = [text("admin.servers_title", locale=locale)]
    has_servers = False
    for status in statuses:
        has_servers = True
        lines.extend(
            [
                "",
                status.name,
                text("admin.server_status", locale=locale, status=status.status),
                text("admin.server_runtime", locale=locale, runtime=status.runtime),
                text(
                    "admin.server_devices",
                    locale=locale,
                    active=status.active_device_count,
                    total=status.total_device_count,
                ),
                text(
                    "admin.server_health",
                    locale=locale,
                    health=(
                        status.health_status
                        or text("common.unknown", locale=locale)
                    ),
                ),
                text(
                    "admin.server_latency",
                    locale=locale,
                    latency=(
                        f"{status.health_latency_ms} ms"
                        if status.health_latency_ms is not None
                        else text("common.unknown", locale=locale)
                    ),
                ),
                text(
                    "admin.server_checked",
                    locale=locale,
                    checked_at=(
                        status.health_checked_at
                        or text("common.unknown", locale=locale)
                    ),
                ),
                text(
                    "admin.server_probes",
                    locale=locale,
                    ssh=_probe_state(status.health_ssh_ok, locale=locale),
                    awg=_probe_state(status.health_awg_ok, locale=locale),
                    udp=_probe_state(status.health_udp_port_ok, locale=locale),
                ),
            ]
        )
    if not has_servers:
        lines.append(text("admin.no_servers", locale=locale))
    return "\n".join(lines), build_admin_navigation_keyboard(locale=locale)


def render_admin_integrations(
    statuses: Iterable[OperatorCredentialStatusView],
    *,
    locale: str = DEFAULT_LOCALE,
) -> tuple[str, InlineKeyboardMarkup]:
    unknown = text("common.unknown", locale=locale)
    lines = [text("admin.integrations_title", locale=locale)]
    has_credentials = False
    for status in statuses:
        has_credentials = True
        lines.extend(
            [
                "",
                status.name,
                text("admin.integration_owner", locale=locale, owner=status.owner_label),
                text(
                    "admin.integration_kind",
                    locale=locale,
                    kind=status.integration_kind,
                ),
                text(
                    "admin.integration_purpose",
                    locale=locale,
                    purpose=status.purpose,
                ),
                text(
                    "admin.integration_scopes",
                    locale=locale,
                    scopes=", ".join(status.scopes),
                ),
                text(
                    "admin.integration_status",
                    locale=locale,
                    status=status.status,
                ),
                text(
                    "admin.integration_expires",
                    locale=locale,
                    expires_at=status.expires_at or unknown,
                ),
                text(
                    "admin.integration_last_used",
                    locale=locale,
                    last_used_at=status.last_used_at or unknown,
                ),
            ]
        )
    if not has_credentials:
        lines.append(text("admin.no_integrations", locale=locale))
    return "\n".join(lines), build_admin_navigation_keyboard(locale=locale)


def render_admin_users(
    users: Iterable[Mapping[str, object]],
) -> tuple[str, InlineKeyboardMarkup]:
    lines = [text("admin.users_title")]
    has_users = False
    for user in users:
        has_users = True
        lines.extend(
            [
                "",
                _format_user_identity(user),
                f"{text('common.status')}: {user['status']}",
                f"{text('admin.flag')}: {text('common.yes') if int(user['is_admin']) == 1 else text('common.no')}",
                f"{text('admin.active_devices')}: {int(user['active_device_count'])}",
                f"{text('admin.total_devices')}: {int(user['total_device_count'])}",
            ]
        )
    if not has_users:
        lines.append(text("admin.no_users"))
    return "\n".join(lines), build_admin_navigation_keyboard()


def parse_config_version_callback(data: str, *, prefix: str) -> str | None:
    marker = f"{prefix}:"
    if not data.startswith(marker):
        return None
    return data.removeprefix(marker)


def parse_language_callback(data: str) -> str | None:
    marker = f"{LANGUAGE_CALLBACK_PREFIX}:"
    if not data.startswith(marker):
        return None
    locale = data.removeprefix(marker)
    if locale not in SUPPORTED_LOCALES:
        return None
    return locale


def parse_admin_approve_callback(data: str) -> tuple[int, str] | None:
    marker = f"{ADMIN_APPROVE_PREFIX}:"
    if not data.startswith(marker):
        return None
    parts = data.removeprefix(marker).split(":", maxsplit=1)
    if len(parts) != 2:
        return None
    return int(parts[0]), parts[1]


def _render_device_traffic_lines(
    view: DeviceTrafficView,
    *,
    locale: str = DEFAULT_LOCALE,
) -> list[str]:
    connected_key = (
        "common.yes" if getattr(view, "is_connected", False) else "common.no"
    )
    lines = [
        "",
        f"{view.device_name} ({_version_label(view.config_version)})",
        f"{text('common.status', locale=locale)}: {view.status}",
        f"{text('common.connected', locale=locale)}: "
        f"{text(connected_key, locale=locale)}",
    ]
    if not view.is_available:
        lines.append(text("traffic.no_data", locale=locale))
        return lines

    lines.extend(
        [
            f"{text('common.received', locale=locale)}: {view.rx}",
            f"{text('common.sent', locale=locale)}: {view.tx}",
            f"{text('common.total', locale=locale)}: {view.total}",
            f"{text('common.updated', locale=locale)}: {view.collected_at}",
        ]
    )
    if view.is_stale:
        lines.append(text("traffic.stale", locale=locale))
    return lines


def _probe_state(value: bool | None, *, locale: str) -> str:
    if value is None:
        return text("common.unknown", locale=locale)
    return text("common.yes" if value else "common.no", locale=locale)


def _format_user_identity(row: Mapping[str, object]) -> str:
    return user_display_label(row)


def _row_get(row: Mapping[str, object], key: str, default: object = None) -> object:
    get = getattr(row, "get", None)
    if get is not None:
        return get(key, default)
    try:
        return row[key]
    except (KeyError, IndexError):
        return default


def _format_requested_config_version(row: Mapping[str, object]) -> str:
    config_version = _row_get(row, "requested_config_version")
    if not config_version:
        return ""
    return f", config={_version_label(str(config_version))}"


def _ordered_config_versions(preferred: str | None) -> tuple[str, ...]:
    versions = list(SUPPORTED_CLIENT_CONFIG_VERSIONS)
    if preferred in versions:
        versions.remove(preferred)
        versions.insert(0, preferred)
    return tuple(versions)


def _version_label(config_version: str) -> str:
    return VERSION_LABELS.get(config_version, config_version)
