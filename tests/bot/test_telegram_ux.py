import sqlite3

from app.bot.ux import (
    ADMIN_PENDING_CALLBACK,
    ADMIN_RESEND_PREFIX,
    ADMIN_TEMPLATES_CALLBACK,
    ADMIN_TEMPLATE_RESET_CALLBACK,
    ADMIN_TRAFFIC_CALLBACK,
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
    VERSION_LABELS,
    build_admin_order_keyboard,
    build_admin_resend_keyboard,
    build_config_version_keyboard,
    build_language_keyboard,
    build_main_menu,
    build_plan_keyboard,
    build_user_device_keyboard,
    build_user_reset_confirm_keyboard,
    build_user_revoke_confirm_keyboard,
    build_user_devices_reset_keyboard,
    parse_language_callback,
    render_admin_approval,
    render_admin_pending_orders,
    render_admin_template,
    render_admin_traffic,
    render_admin_users,
    render_my_devices,
    render_my_tariff,
    render_language_prompt,
    render_user_traffic,
)
from app.services.traffic import DeviceTrafficView


def test_main_menu_shows_user_actions_and_admin_entry_for_admins():
    user_menu = build_main_menu(is_admin=False)
    admin_menu = build_main_menu(is_admin=True)

    assert _button_texts(user_menu) == [
        ["Получить конфиг"],
        ["Мой тариф"],
        ["Мой трафик"],
        ["Мои устройства"],
    ]
    assert _callback_data(user_menu) == [
        [REQUEST_CONFIG_PREFIX],
        [MY_TARIFF_CALLBACK],
        [MY_TRAFFIC_CALLBACK],
        [MY_DEVICES_CALLBACK],
    ]
    assert _button_texts(admin_menu)[-1] == ["Админ"]
    assert _callback_data(admin_menu)[-1] == [ADMIN_PENDING_CALLBACK]


def test_main_menu_can_render_english_button_labels():
    menu = build_main_menu(is_admin=True, locale="en")

    assert _button_texts(menu) == [
        ["Request config"],
        ["My tariff"],
        ["My traffic"],
        ["My devices"],
        ["Admin"],
    ]


def test_language_keyboard_defaults_to_russian_and_offers_english():
    keyboard = build_language_keyboard()

    assert render_language_prompt() == "🌐 Выберите язык / Choose your language:"
    assert _button_texts(keyboard) == [["🇷🇺 Русский", "🇬🇧 English"]]
    assert _callback_data(keyboard) == [
        [f"{LANGUAGE_CALLBACK_PREFIX}:ru", f"{LANGUAGE_CALLBACK_PREFIX}:en"]
    ]
    assert parse_language_callback(f"{LANGUAGE_CALLBACK_PREFIX}:ru") == "ru"
    assert parse_language_callback(f"{LANGUAGE_CALLBACK_PREFIX}:en") == "en"
    assert parse_language_callback(f"{LANGUAGE_CALLBACK_PREFIX}:de") is None


def test_config_version_keyboard_offers_amnezia_2_0_first():
    keyboard = build_config_version_keyboard(prefix=REQUEST_CONFIG_PREFIX)

    assert _button_texts(keyboard) == [
        [VERSION_LABELS["amneziawg_v2"]],
        [VERSION_LABELS["amneziawg_v1_5"]],
    ]
    assert _callback_data(keyboard) == [
        [f"{REQUEST_CONFIG_PREFIX}:amneziawg_v2"],
        [f"{REQUEST_CONFIG_PREFIX}:amneziawg_v1_5"],
    ]


def test_plan_keyboard_uses_selected_config_version_and_plan_ids():
    keyboard = build_plan_keyboard(
        config_version="amneziawg_v2",
        plans=[
            {"id": "days_7", "name": "7 days"},
            {"id": "days_30", "name": "30 days"},
        ],
    )

    assert _button_texts(keyboard) == [["7 days"], ["30 days"]]
    assert _callback_data(keyboard) == [
        [f"{REQUEST_PLAN_PREFIX}:amneziawg_v2:days_7"],
        [f"{REQUEST_PLAN_PREFIX}:amneziawg_v2:days_30"],
    ]


def test_render_user_traffic_lists_devices_and_marks_stale_stats():
    views = [
        DeviceTrafficView(
            device_id=1,
            device_name="phone",
            config_version="amneziawg_v1_5",
            status="active",
            expires_at="2026-06-27T12:00:00Z",
            rx="1.0 KiB",
            tx="2.0 KiB",
            total="3.0 KiB",
            collected_at="2026-05-27T12:00:00Z",
            is_available=True,
            is_stale=False,
            first_connected_at="2026-05-27T12:00:00Z",
            last_connected_at="2026-05-27T12:30:00Z",
            is_connected=True,
        ),
        DeviceTrafficView(
            device_id=2,
            device_name="laptop",
            config_version="amneziawg_v2",
            status="active",
            expires_at=None,
            rx="unavailable",
            tx="unavailable",
            total="unavailable",
            collected_at=None,
            is_available=False,
            is_stale=True,
            first_connected_at=None,
            last_connected_at=None,
            is_connected=False,
        ),
    ]

    text = render_user_traffic(views)

    assert "Мой трафик" in text
    assert "phone" in text
    assert "AmneziaWG 1.5" in text
    assert "Всего: 3.0 KiB" in text
    assert "Подключался: да" in text
    assert "laptop" in text
    assert "Подключался: нет" in text
    assert "Данных о трафике пока нет" in text


def test_admin_pending_orders_render_with_per_order_version_keyboard():
    orders = [
        {
            "id": 11,
            "telegram_id": 1001,
            "username": "alice",
            "first_name": "Alice",
            "last_name": None,
            "status": "manual_review",
            "created_at": "2026-05-27 12:00:00",
        }
    ]

    text = render_admin_pending_orders(orders)
    keyboard = build_admin_order_keyboard(order_id=11)

    assert "Заявки" in text
    assert "#11" in text
    assert "@alice" in text
    assert _button_texts(keyboard) == [
        [f"Одобрить: {VERSION_LABELS['amneziawg_v1_5']}"],
        [f"Одобрить: {VERSION_LABELS['amneziawg_v2']}"],
    ]
    assert _callback_data(keyboard) == [
        ["admin:approve:11:amneziawg_v1_5"],
        ["admin:approve:11:amneziawg_v2"],
    ]


def test_admin_order_keyboard_prioritizes_requested_config_version():
    keyboard = build_admin_order_keyboard(
        order_id=11,
        requested_config_version="amneziawg_v2",
    )

    assert _callback_data(keyboard) == [
        ["admin:approve:11:amneziawg_v2"],
        ["admin:approve:11:amneziawg_v1_5"],
    ]


def test_admin_pending_orders_render_requested_config_version():
    text = render_admin_pending_orders(
        [
            {
                "id": 11,
                "telegram_id": 1001,
                "username": "alice",
                "first_name": "Alice",
                "last_name": None,
                "status": "manual_review",
                "created_at": "2026-05-27 12:00:00",
                "requested_config_version": "amneziawg_v2",
            }
        ]
    )

    assert VERSION_LABELS["amneziawg_v2"] in text


def test_admin_pending_orders_accept_sqlite_rows_from_repository():
    row = _sqlite_row(
        {
            "id": 11,
            "telegram_id": 1001,
            "username": "alice",
            "first_name": "Alice",
            "last_name": None,
            "status": "manual_review",
            "created_at": "2026-05-27 12:00:00",
        }
    )

    text = render_admin_pending_orders([row])

    assert "#11" in text
    assert "@alice" in text


def test_admin_traffic_keyboard_links_pending_orders_and_traffic():
    text, keyboard = render_admin_traffic(
        [
            DeviceTrafficView(
                device_id=7,
                device_name="tablet",
                config_version="amneziawg_v2",
                status="active",
                expires_at=None,
                rx="4.0 KiB",
                tx="8.0 KiB",
                total="12.0 KiB",
                collected_at="2026-05-27T12:00:00Z",
                is_available=True,
                is_stale=False,
            )
        ]
    )

    assert "Трафик пользователей" in text
    assert "tablet" in text
    assert "12.0 KiB" in text
    assert _callback_data(keyboard) == [
        [ADMIN_PENDING_CALLBACK],
        [ADMIN_TRAFFIC_CALLBACK],
        [ADMIN_TEMPLATES_CALLBACK],
        [ADMIN_USERS_CALLBACK],
    ]


def test_admin_navigation_includes_templates_and_traffic_actions():
    from app.bot.ux import build_admin_navigation_keyboard

    keyboard = build_admin_navigation_keyboard()

    assert _button_texts(keyboard) == [["Заявки"], ["Трафик"], ["Шаблоны"], ["Пользователи"]]
    assert _callback_data(keyboard) == [
        [ADMIN_PENDING_CALLBACK],
        [ADMIN_TRAFFIC_CALLBACK],
        [ADMIN_TEMPLATES_CALLBACK],
        [ADMIN_USERS_CALLBACK],
    ]


def test_render_admin_users_lists_users_and_device_counts():
    text, keyboard = render_admin_users(
        [
            {
                "telegram_id": 1001,
                "username": "alice",
                "first_name": "Alice",
                "last_name": None,
                "status": "active",
                "is_admin": 1,
                "active_device_count": 1,
                "total_device_count": 2,
                "created_at": "2026-05-27 12:00:00",
            }
        ]
    )

    assert "Пользователи" in text
    assert "@alice" in text
    assert "админ: да" in text
    assert "активных устройств: 1" in text
    assert "всего устройств: 2" in text
    assert _callback_data(keyboard) == [
        [ADMIN_PENDING_CALLBACK],
        [ADMIN_TRAFFIC_CALLBACK],
        [ADMIN_TEMPLATES_CALLBACK],
        [ADMIN_USERS_CALLBACK],
    ]


def test_render_admin_template_shows_reset_action():
    text, keyboard = render_admin_template("Hello {device_id}")

    assert "Шаблон сообщения с конфигом" in text
    assert "Hello {device_id}" in text
    assert _button_texts(keyboard) == [["Сбросить шаблон"]]
    assert _callback_data(keyboard) == [[ADMIN_TEMPLATE_RESET_CALLBACK]]


def test_build_admin_resend_keyboard_targets_device():
    keyboard = build_admin_resend_keyboard(device_id=7)

    assert _button_texts(keyboard) == [["Отправить конфиг"]]
    assert _callback_data(keyboard) == [[f"{ADMIN_RESEND_PREFIX}:7"]]


def test_render_admin_approval_mentions_order_device_and_user():
    text = render_admin_approval(
        order_id=11,
        device_id=7,
        user_telegram_id=1001,
        config_version="amneziawg_v2",
    )

    assert "Заявка #11 одобрена" in text
    assert "устройство #7" in text
    assert "telegram_id=1001" in text
    assert "AmneziaWG 2.0" in text


def test_render_my_tariff_shows_device_expiration_and_days_left():
    text = render_my_tariff(
        [
            {
                "name": "phone",
                "duration_days": 30,
                "expires_at": "2026-06-26T12:00:00Z",
                "status": "active",
            }
        ],
        now="2026-05-27T12:00:00Z",
    )

    assert "Мой тариф" in text
    assert "phone" in text
    assert "30 дней" in text
    assert "Дней осталось: 30" in text


def test_render_my_devices_lists_devices_with_tariff_and_connection_state():
    text = render_my_devices(
        [
            {
                "id": 7,
                "name": "phone",
                "duration_days": 30,
                "expires_at": "2026-06-26T12:00:00Z",
                "status": "active",
                "config_version": "amneziawg_v2",
                "first_connected_at": "2026-05-27T12:00:00Z",
                "last_connected_at": "2026-05-27T12:30:00Z",
            }
        ],
        now="2026-05-27T12:00:00Z",
    )

    assert "Мои устройства" in text
    assert "#7 phone" in text
    assert "AmneziaWG 2.0" in text
    assert "Тариф: 30 дней" in text
    assert "Дней осталось: 30" in text
    assert "Подключался: да" in text


def test_render_my_devices_accepts_sqlite_rows_from_repository():
    row = _sqlite_row(
        {
            "id": 7,
            "name": "phone",
            "duration_days": 30,
            "expires_at": "2026-06-26T12:00:00Z",
            "status": "active",
            "config_version": "amneziawg_v2",
            "first_connected_at": "2026-05-27T12:00:00Z",
            "last_connected_at": "2026-05-27T12:30:00Z",
        }
    )

    text = render_my_devices([row], now="2026-05-27T12:00:00Z")

    assert "#7 phone" in text
    assert "AmneziaWG 2.0" in text


def test_render_my_devices_marks_external_only_imports():
    text = render_my_devices(
        [
            {
                "id": 4,
                "name": "Neobyatnaya-AMNZ-4",
                "duration_days": 30,
                "expires_at": "2026-06-26T12:00:00Z",
                "status": "revoked",
                "config_version": "amneziawg_v2",
                "config_material_status": "external_only",
                "first_connected_at": None,
                "last_connected_at": None,
            }
        ],
        now="2026-05-27T12:00:00Z",
    )

    assert "#4 Neobyatnaya-AMNZ-4" in text
    assert "ранее импортировано" in text
    assert "Конфиг недоступен для повторной отправки" in text


def test_user_device_keyboard_offers_resend_and_revoke_actions():
    keyboard = build_user_device_keyboard(device_id=7)

    assert _button_texts(keyboard) == [["Отправить конфиг"], ["Удалить устройство"]]
    assert _callback_data(keyboard) == [
        [f"{USER_RESEND_PREFIX}:7"],
        [f"{USER_REVOKE_PREFIX}:7"],
    ]


def test_user_device_keyboard_can_hide_resend_for_external_only_device():
    keyboard = build_user_device_keyboard(device_id=4, can_resend=False)

    assert _button_texts(keyboard) == [["Удалить устройство"]]
    assert _callback_data(keyboard) == [[f"{USER_REVOKE_PREFIX}:4"]]


def test_user_revoke_confirm_keyboard_targets_confirmed_device_delete():
    keyboard = build_user_revoke_confirm_keyboard(device_id=7)

    assert _button_texts(keyboard) == [["Подтвердить удаление"]]
    assert _callback_data(keyboard) == [[f"{USER_REVOKE_CONFIRM_PREFIX}:7"]]


def test_user_devices_reset_keyboard_targets_all_user_devices():
    keyboard = build_user_devices_reset_keyboard()

    assert _button_texts(keyboard) == [["Сбросить все устройства"]]
    assert _callback_data(keyboard) == [[USER_RESET_DEVICES_CALLBACK]]


def test_user_reset_confirm_keyboard_targets_confirmed_reset():
    keyboard = build_user_reset_confirm_keyboard()

    assert _button_texts(keyboard) == [["Подтвердить сброс"]]
    assert _callback_data(keyboard) == [[USER_RESET_DEVICES_CONFIRM_CALLBACK]]


def _button_texts(markup):
    return [[button.text for button in row] for row in markup.inline_keyboard]


def _callback_data(markup):
    return [[button.callback_data for button in row] for row in markup.inline_keyboard]


def _sqlite_row(values: dict[str, object]) -> sqlite3.Row:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    columns = ", ".join(f"? AS {name}" for name in values)
    return conn.execute(f"SELECT {columns}", tuple(values.values())).fetchone()
