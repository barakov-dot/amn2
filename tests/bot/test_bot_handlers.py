import asyncio
from types import SimpleNamespace

from app.bot.handlers import (
    handle_admin_approve,
    handle_admin_pending,
    handle_admin_resend_config,
    handle_admin_reset_template,
    handle_admin_template,
    handle_admin_add_user,
    handle_admin_create_order,
    handle_admin_grant,
    handle_config_request,
    handle_admin_users,
    handle_language_choice,
    handle_my_devices,
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
from app.server.peer_apply import PeerApplyError
from app.services.config_delivery import ConfigMaterialUnavailable


def test_handle_start_sends_header_and_language_choices_with_russian_default():
    message = FakeMessage(user_id=9001, first_name="Admin")
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_start(message, workflow=workflow))

    assert workflow.registered_users == [9001]
    assert message.answers == []
    assert message.photos[0]["caption"] == "🌐 Выберите язык / Choose your language:"
    assert message.photos[0]["photo"].path.endswith("NEOBYATNAYA-AMNZ-BOT.png")
    assert _button_texts(message.photos[0]["reply_markup"]) == [
        ["🇷🇺 Русский", "🇬🇧 English"]
    ]


def test_handle_language_choice_persists_locale_and_renders_selected_menu():
    callback = FakeCallback(
        data=f"{LANGUAGE_CALLBACK_PREFIX}:en",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_language_choice(callback, workflow=workflow))

    assert workflow.locales == [(1001, "en")]
    assert "Hello, Alice." in callback.message.answers[0]["text"]
    assert _button_texts(callback.message.answers[0]["reply_markup"]) == [
        ["Request config"],
        ["My tariff"],
        ["My traffic"],
        ["My devices"],
    ]
    assert callback.answered is True


def test_handle_request_config_prompt_shows_version_choices():
    callback = FakeCallback(
        data=REQUEST_CONFIG_PREFIX,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )

    asyncio.run(handle_request_config_prompt(callback))

    assert "Выберите версию AmneziaWG" in callback.message.answers[0]["text"]
    assert _button_texts(callback.message.answers[0]["reply_markup"]) == [
        ["AmneziaWG 2.0"],
        ["AmneziaWG 1.5"],
    ]
    assert callback.answered is True


def test_handle_config_request_shows_tariff_choices_for_selected_version():
    callback = FakeCallback(
        data=f"{REQUEST_CONFIG_PREFIX}:amneziawg_v1_5",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_config_request(callback, workflow=workflow))

    assert workflow.requests == []
    assert "Выберите тариф" in callback.message.answers[0]["text"]
    assert _button_texts(callback.message.answers[0]["reply_markup"]) == [
        ["7 days"],
        ["30 days"],
    ]
    assert callback.answered is True


def test_handle_plan_request_creates_order_for_selected_version_and_plan():
    callback = FakeCallback(
        data=f"{REQUEST_PLAN_PREFIX}:amneziawg_v1_5:days_30",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_plan_request(callback, workflow=workflow))

    assert workflow.requests == [("alice", "amneziawg_v1_5", "days_30")]
    assert "request #42" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_my_traffic_renders_user_traffic():
    callback = FakeCallback(
        data=MY_TRAFFIC_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001}, traffic_text_marker="phone")

    asyncio.run(handle_my_traffic(callback, workflow=workflow))

    assert "Мой трафик" in callback.message.answers[0]["text"]
    assert "phone" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_my_tariff_renders_user_tariff():
    callback = FakeCallback(
        data=MY_TARIFF_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_my_tariff(callback, workflow=workflow))

    assert "Мой тариф" in callback.message.answers[0]["text"]
    assert "phone" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_my_devices_renders_device_actions_and_reset():
    callback = FakeCallback(
        data=MY_DEVICES_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_my_devices(callback, workflow=workflow))

    assert "Мои устройства" in callback.message.answers[0]["text"]
    assert callback.message.answers[1]["text"] == "Device #7"
    assert _button_texts(callback.message.answers[1]["reply_markup"]) == [
        ["Отправить конфиг"],
        ["Удалить устройство"],
    ]
    assert _button_texts(callback.message.answers[2]["reply_markup"]) == [
        ["Сбросить все устройства"]
    ]
    assert callback.answered is True


def test_handle_my_devices_hides_resend_for_external_only_device():
    callback = FakeCallback(
        data=MY_DEVICES_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(
        admin_ids={9001},
        devices=[
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
    )

    asyncio.run(handle_my_devices(callback, workflow=workflow))

    assert "ранее импортировано" in callback.message.answers[0]["text"]
    assert _button_texts(callback.message.answers[1]["reply_markup"]) == [
        ["Удалить устройство"]
    ]


def test_handle_user_resend_config_sends_owned_config_to_user():
    callback = FakeCallback(
        data=f"{USER_RESEND_PREFIX}:7",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_user_resend_config(callback, workflow=workflow))

    assert workflow.user_resends == [7]
    assert callback.bot.sent_messages[0]["chat_id"] == 1001
    assert callback.bot.sent_documents[0]["document"].filename.endswith(".conf")
    assert callback.bot.sent_photos[0]["photo"].filename.endswith(".qr.png")
    assert "отправлен повторно" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_user_resend_config_reports_external_only_device():
    callback = FakeCallback(
        data=f"{USER_RESEND_PREFIX}:4",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(
        admin_ids={9001},
        user_resend_error=ConfigMaterialUnavailable("external-only"),
    )

    asyncio.run(handle_user_resend_config(callback, workflow=workflow))

    assert workflow.user_resends == [4]
    assert "недоступен для повторной отправки" in callback.message.answers[0]["text"]
    assert callback.bot.sent_messages == []
    assert callback.bot.sent_documents == []
    assert callback.bot.sent_photos == []
    assert callback.answered is True


def test_handle_user_revoke_device_revokes_owned_device():
    callback = FakeCallback(
        data=f"{USER_REVOKE_PREFIX}:7",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_user_revoke_device(callback, workflow=workflow))

    assert workflow.revoked_devices == []
    assert "Подтвердите удаление" in callback.message.answers[0]["text"]
    assert _button_texts(callback.message.answers[0]["reply_markup"]) == [
        ["Подтвердить удаление"]
    ]
    assert callback.answered is True


def test_handle_user_revoke_device_confirm_revokes_owned_device():
    callback = FakeCallback(
        data=f"{USER_REVOKE_CONFIRM_PREFIX}:7",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_user_revoke_device_confirm(callback, workflow=workflow))

    assert workflow.revoked_devices == [7]
    assert "удалено" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_user_revoke_device_confirm_reports_server_remove_error():
    callback = FakeCallback(
        data=f"{USER_REVOKE_CONFIRM_PREFIX}:7",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(
        admin_ids={9001},
        revoke_error=PeerApplyError(
            "Docker revoke failed: PresharedKey = secret-psk"
        ),
    )

    asyncio.run(handle_user_revoke_device_confirm(callback, workflow=workflow))

    assert workflow.revoked_devices == [7]
    assert "failed" in callback.message.answers[0]["text"]
    assert "Details: Docker revoke failed" in callback.message.answers[0]["text"]
    assert "revoke-peer --dry-run" in callback.message.answers[0]["text"]
    assert "secret-psk" not in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_user_revoke_confirm_answers_callback_before_peer_revoke():
    events = []

    class OrderingCallback(FakeCallback):
        async def answer(self):
            events.append("answer")
            await super().answer()

    class OrderingWorkflow(FakeWorkflow):
        def revoke_user_device(self, *, telegram_id, device_id, revoked_at=None):
            events.append("revoke_user_device")
            return super().revoke_user_device(
                telegram_id=telegram_id,
                device_id=device_id,
                revoked_at=revoked_at,
            )

    callback = OrderingCallback(
        data=f"{USER_REVOKE_CONFIRM_PREFIX}:7",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = OrderingWorkflow(admin_ids={9001})

    asyncio.run(handle_user_revoke_device_confirm(callback, workflow=workflow))

    assert events[:2] == ["answer", "revoke_user_device"]


def test_handle_user_reset_devices_asks_for_confirmation():
    callback = FakeCallback(
        data=USER_RESET_DEVICES_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_user_reset_devices(callback, workflow=workflow))

    assert workflow.reset_requests == []
    assert "Подтвердите сброс" in callback.message.answers[0]["text"]
    assert _button_texts(callback.message.answers[0]["reply_markup"]) == [
        ["Подтвердить сброс"]
    ]
    assert callback.answered is True


def test_handle_user_reset_devices_confirm_revokes_all_owned_devices():
    callback = FakeCallback(
        data=USER_RESET_DEVICES_CONFIRM_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_user_reset_devices_confirm(callback, workflow=workflow))

    assert workflow.reset_requests == [1001]
    assert "Удалено устройств: 2" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_user_reset_devices_confirm_reports_server_remove_error():
    callback = FakeCallback(
        data=USER_RESET_DEVICES_CONFIRM_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(
        admin_ids={9001},
        revoke_error=PeerApplyError(
            "Docker reset failed: PresharedKey = secret-psk"
        ),
    )

    asyncio.run(handle_user_reset_devices_confirm(callback, workflow=workflow))

    assert workflow.reset_requests == [1001]
    assert "failed" in callback.message.answers[0]["text"]
    assert "Details: Docker reset failed" in callback.message.answers[0]["text"]
    assert "revoke-peer --dry-run" in callback.message.answers[0]["text"]
    assert "secret-psk" not in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_user_reset_devices_confirm_answers_callback_before_peer_revoke():
    events = []

    class OrderingCallback(FakeCallback):
        async def answer(self):
            events.append("answer")
            await super().answer()

    class OrderingWorkflow(FakeWorkflow):
        def reset_user_devices(self, *, telegram_id, revoked_at=None):
            events.append("reset_user_devices")
            return super().reset_user_devices(
                telegram_id=telegram_id,
                revoked_at=revoked_at,
            )

    callback = OrderingCallback(
        data=USER_RESET_DEVICES_CONFIRM_CALLBACK,
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = OrderingWorkflow(admin_ids={9001})

    asyncio.run(handle_user_reset_devices_confirm(callback, workflow=workflow))

    assert events[:2] == ["answer", "reset_user_devices"]


def test_handle_admin_pending_rejects_non_admin():
    callback = FakeCallback(
        data="admin:pending",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_pending(callback, workflow=workflow))

    assert callback.message.answers[0]["text"] == "Нужны права администратора."
    assert callback.answered is True


def test_handle_admin_pending_renders_approve_buttons_for_each_order():
    callback = FakeCallback(
        data="admin:pending",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_pending(callback, workflow=workflow))

    assert "Заявки" in callback.message.answers[0]["text"]
    assert callback.message.answers[1]["text"] == "Order #11"
    assert _button_texts(callback.message.answers[1]["reply_markup"]) == [
        ["Одобрить: AmneziaWG 1.5"],
        ["Одобрить: AmneziaWG 2.0"],
    ]
    assert callback.answered is True


def test_handle_admin_pending_prioritizes_requested_config_version():
    class RequestedVersionWorkflow(FakeWorkflow):
        def list_pending_orders(self, *, admin_telegram_id):
            orders = super().list_pending_orders(admin_telegram_id=admin_telegram_id)
            orders[0]["requested_config_version"] = "amneziawg_v2"
            return orders

    callback = FakeCallback(
        data="admin:pending",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = RequestedVersionWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_pending(callback, workflow=workflow))

    assert _callback_data(callback.message.answers[1]["reply_markup"]) == [
        ["admin:approve:11:amneziawg_v2"],
        ["admin:approve:11:amneziawg_v1_5"],
    ]


def test_handle_admin_pending_answers_callback_before_listing_orders():
    events = []

    class OrderingCallback(FakeCallback):
        async def answer(self):
            events.append("answer")
            await super().answer()

    class OrderingWorkflow(FakeWorkflow):
        def list_pending_orders(self, *, admin_telegram_id):
            events.append("list_pending")
            return super().list_pending_orders(admin_telegram_id=admin_telegram_id)

    callback = OrderingCallback(
        data="admin:pending",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = OrderingWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_pending(callback, workflow=workflow))

    assert events[:2] == ["answer", "list_pending"]


def test_handle_admin_users_renders_service_users_for_admin():
    callback = FakeCallback(
        data="admin:users",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_users(callback, workflow=workflow))

    assert "Пользователи" in callback.message.answers[0]["text"]
    assert "@alice" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_admin_users_rejects_non_admin():
    callback = FakeCallback(
        data="admin:users",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_users(callback, workflow=workflow))

    assert callback.message.answers[0]["text"] == "Нужны права администратора."
    assert callback.answered is True


def test_handle_admin_approve_calls_workflow_and_returns_config_preview():
    callback = FakeCallback(
        data="admin:approve:11:amneziawg_v1_5",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_approve(callback, workflow=workflow))

    assert workflow.approvals == [(11, "amneziawg_v1_5")]
    assert "одобрена" in callback.message.answers[0]["text"]
    assert callback.bot.sent_messages[0]["chat_id"] == 1001
    assert "VPN-конфиг" in callback.bot.sent_messages[0]["text"]
    assert callback.bot.sent_messages[1]["text"].startswith("Ссылка для импорта:")
    assert "DefaultVPN" in callback.bot.sent_messages[2]["text"]
    assert callback.bot.sent_documents[0]["chat_id"] == 1001
    assert callback.bot.sent_documents[0]["document"].filename.endswith(".conf")
    assert callback.bot.sent_documents[0]["caption"] == "VPN-конфиг (.conf)"
    assert callback.bot.sent_photos[0]["chat_id"] == 1001
    assert callback.bot.sent_photos[0]["photo"].filename.endswith(".qr.png")
    assert callback.bot.sent_photos[0]["caption"] == "QR-код import-ссылки vpn://"
    assert callback.answered is True


def test_handle_admin_approve_answers_callback_before_peer_apply():
    events = []

    class OrderingCallback(FakeCallback):
        async def answer(self):
            events.append("answer")
            await super().answer()

    class OrderingWorkflow(FakeWorkflow):
        def approve_order(self, *, admin_telegram_id, order_id, config_version):
            events.append("approve_order")
            return super().approve_order(
                admin_telegram_id=admin_telegram_id,
                order_id=order_id,
                config_version=config_version,
            )

    callback = OrderingCallback(
        data="admin:approve:11:amneziawg_v1_5",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = OrderingWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_approve(callback, workflow=workflow))

    assert events[:2] == ["answer", "approve_order"]


def test_handle_admin_approve_reports_apply_error_without_sending_config():
    callback = FakeCallback(
        data="admin:approve:11:amneziawg_v1_5",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = FakeWorkflow(
        admin_ids={9001},
        approval_error=PeerApplyError(
            "Docker config read failed: PresharedKey = secret-psk"
        ),
    )

    asyncio.run(handle_admin_approve(callback, workflow=workflow))

    assert workflow.approvals == [(11, "amneziawg_v1_5")]
    assert "failed" in callback.message.answers[0]["text"]
    assert "Details: Docker config read failed" in callback.message.answers[0]["text"]
    assert "server check" in callback.message.answers[0]["text"]
    assert "apply-peer --dry-run" in callback.message.answers[0]["text"]
    assert "secret-psk" not in callback.message.answers[0]["text"]
    assert callback.bot.sent_messages == []
    assert callback.bot.sent_documents == []
    assert callback.bot.sent_photos == []
    assert callback.answered is True


def test_handle_admin_approve_rejects_non_admin():
    callback = FakeCallback(
        data="admin:approve:11:amneziawg_v1_5",
        user_id=1001,
        username="alice",
        first_name="Alice",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_approve(callback, workflow=workflow))

    assert callback.message.answers[0]["text"] == "Нужны права администратора."
    assert workflow.approvals == []
    assert callback.answered is True


def test_handle_admin_template_shows_editable_template_and_reset_button():
    callback = FakeCallback(
        data="admin:templates",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_template(callback, workflow=workflow))

    assert "Config ready template" in callback.message.answers[0]["text"]
    assert "DefaultVPN" in callback.message.answers[0]["text"]
    assert _button_texts(callback.message.answers[0]["reply_markup"]) == [
        ["Reset template"]
    ]
    assert callback.answered is True


def test_handle_admin_reset_template_resets_template():
    callback = FakeCallback(
        data="admin:template:reset",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_reset_template(callback, workflow=workflow))

    assert workflow.template_reset is True
    assert "сброшен" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_admin_resend_config_sends_delivery_to_user():
    callback = FakeCallback(
        data="admin:resend:7",
        user_id=9001,
        username="admin",
        first_name="Admin",
    )
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_resend_config(callback, workflow=workflow))

    assert workflow.resends == [7]
    assert callback.bot.sent_messages[0]["chat_id"] == 1001
    assert callback.bot.sent_documents[0]["document"].filename.endswith(".conf")
    assert callback.bot.sent_photos[0]["photo"].filename.endswith(".qr.png")
    assert "отправлен повторно" in callback.message.answers[0]["text"]
    assert callback.answered is True


def test_handle_admin_grant_delegates_admin_role_by_telegram_id():
    message = FakeMessage(user_id=9001, username="admin", first_name="Admin")
    message.text = "/admin_grant 1001 alice"
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_grant(message, workflow=workflow))

    assert workflow.grants == [1001]
    assert "Admin role granted" in message.answers[0]["text"]


def test_handle_admin_add_user_creates_manual_user_record():
    message = FakeMessage(user_id=9001, username="admin", first_name="Admin")
    message.text = "/admin_add_user 1001 alice Alice"
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_add_user(message, workflow=workflow))

    assert workflow.manual_users == [1001]
    assert "User was added" in message.answers[0]["text"]


def test_handle_admin_create_order_creates_manual_access_request():
    message = FakeMessage(user_id=9001, username="admin", first_name="Admin")
    message.text = "/admin_create_order 1001 amneziawg_v2 days_30"
    workflow = FakeWorkflow(admin_ids={9001})

    asyncio.run(handle_admin_create_order(message, workflow=workflow))

    assert workflow.manual_orders == [(1001, "amneziawg_v2", "days_30")]
    assert "request #77" in message.answers[0]["text"]


class FakeMessage:
    def __init__(self, *, user_id, username=None, first_name=None, last_name=None):
        self.from_user = SimpleNamespace(
            id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        self.answers = []
        self.photos = []
        self.text = ""

    async def answer(self, text, reply_markup=None):
        self.answers.append({"text": text, "reply_markup": reply_markup})

    async def answer_photo(self, photo, caption=None, reply_markup=None):
        self.photos.append(
            {"photo": photo, "caption": caption, "reply_markup": reply_markup}
        )


class FakeCallback:
    def __init__(self, *, data, user_id, username=None, first_name=None, last_name=None):
        self.data = data
        self.from_user = SimpleNamespace(
            id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        self.message = FakeMessage(
            user_id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        self.bot = FakeBot()
        self.answered = False

    async def answer(self):
        self.answered = True


class FakeWorkflow:
    def __init__(
        self,
        *,
        admin_ids,
        traffic_text_marker=None,
        approval_error=None,
        revoke_error=None,
        user_resend_error=None,
        devices=None,
    ):
        self._admin_ids = admin_ids
        self._traffic_text_marker = traffic_text_marker
        self._approval_error = approval_error
        self._revoke_error = revoke_error
        self._user_resend_error = user_resend_error
        self._devices = devices
        self.requests = []
        self.approvals = []
        self.resends = []
        self.user_resends = []
        self.revoked_devices = []
        self.reset_requests = []
        self.template_reset = False
        self.grants = []
        self.manual_users = []
        self.manual_orders = []
        self.registered_users = []
        self.locales = []

    def is_admin(self, telegram_id):
        return telegram_id in self._admin_ids

    def register_user(self, *, telegram_id, username, first_name, last_name):
        self.registered_users.append(telegram_id)
        return 1

    def set_user_locale(self, *, telegram_id, username, first_name, last_name, locale):
        self.locales.append((telegram_id, locale))
        return True

    def request_access(
        self,
        *,
        telegram_id,
        username,
        first_name,
        last_name,
        config_version,
        plan_id=None,
    ):
        self.requests.append((username, config_version, plan_id))
        return SimpleNamespace(order_id=42, text="Access request #42 was created.")

    def list_active_plans(self):
        return [
            {"id": "days_7", "name": "7 days"},
            {"id": "days_30", "name": "30 days"},
        ]

    def build_user_traffic_views(self, *, telegram_id, now=None):
        return [
            SimpleNamespace(
                device_id=1,
                device_name=self._traffic_text_marker,
                config_version="amneziawg_v2",
                status="active",
                expires_at=None,
                rx="1.0 KiB",
                tx="2.0 KiB",
                total="3.0 KiB",
                collected_at="2026-05-27T12:00:00Z",
                is_available=True,
                is_stale=False,
            )
        ]

    def list_user_devices(self, *, telegram_id):
        if self._devices is not None:
            return self._devices
        return [
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
        ]

    def build_user_resend_delivery(self, *, telegram_id, device_id):
        self.user_resends.append(device_id)
        if self._user_resend_error is not None:
            raise self._user_resend_error
        return SimpleNamespace(
            device_id=device_id,
            user_telegram_id=telegram_id,
            config_text="[Interface]\nPrivateKey = test",
            delivery=SimpleNamespace(
                message_text="Ваш VPN-конфиг готов.",
                vpn_import_link_text="Ссылка для импорта:\nvpn://import/test",
                app_links_text="DefaultVPN:\nhttps://github.com/amnezia-vpn/DefaultVPN",
                config_filename=f"Neobyatnaya-AMNZ-{device_id}.conf",
                config_bytes=b"[Interface]\nPrivateKey = test",
                config_caption="VPN-конфиг (.conf)",
                qr_filename=f"Neobyatnaya-AMNZ-{device_id}.qr.png",
                qr_png_bytes=b"\x89PNG\r\n\x1a\n",
                qr_caption="QR-код import-ссылки vpn://",
            ),
        )

    def revoke_user_device(self, *, telegram_id, device_id, revoked_at=None):
        self.revoked_devices.append(device_id)
        if self._revoke_error is not None:
            raise self._revoke_error
        return True

    def reset_user_devices(self, *, telegram_id, revoked_at=None):
        self.reset_requests.append(telegram_id)
        if self._revoke_error is not None:
            raise self._revoke_error
        return 2

    def grant_admin(
        self,
        *,
        admin_telegram_id,
        target_telegram_id,
        username,
        first_name,
        last_name,
    ):
        if not self.is_admin(admin_telegram_id):
            return False
        self.grants.append(target_telegram_id)
        return True

    def create_manual_user(
        self,
        *,
        admin_telegram_id,
        target_telegram_id,
        username,
        first_name,
        last_name,
    ):
        if not self.is_admin(admin_telegram_id):
            return None
        self.manual_users.append(target_telegram_id)
        return 123

    def create_manual_access_request(
        self,
        *,
        admin_telegram_id,
        target_telegram_id,
        username,
        first_name,
        last_name,
        config_version,
        plan_id,
    ):
        if not self.is_admin(admin_telegram_id):
            return None
        self.manual_orders.append((target_telegram_id, config_version, plan_id))
        return SimpleNamespace(order_id=77, text="Access request #77 was created.")

    def list_pending_orders(self, *, admin_telegram_id):
        if not self.is_admin(admin_telegram_id):
            return []
        return [
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

    def list_users(self, *, admin_telegram_id):
        if not self.is_admin(admin_telegram_id):
            return []
        return [
            {
                "telegram_id": 1001,
                "username": "alice",
                "first_name": "Alice",
                "last_name": None,
                "status": "active",
                "is_admin": 0,
                "active_device_count": 1,
                "total_device_count": 1,
                "created_at": "2026-05-27 12:00:00",
            }
        ]

    def approve_order(self, *, admin_telegram_id, order_id, config_version):
        if not self.is_admin(admin_telegram_id):
            return None
        self.approvals.append((order_id, config_version))
        if self._approval_error is not None:
            raise self._approval_error
        return SimpleNamespace(
            device_id=7,
            user_telegram_id=1001,
            admin_text="Заявка #11 одобрена.",
            user_text="Ваш VPN-конфиг готов.",
            config_text="[Interface]\nPrivateKey = test",
            delivery=SimpleNamespace(
                message_text="Ваш VPN-конфиг готов.",
                vpn_import_link_text="Ссылка для импорта:\nvpn://import/test",
                app_links_text="DefaultVPN:\nhttps://github.com/amnezia-vpn/DefaultVPN",
                config_filename="Neobyatnaya-AMNZ-7.conf",
                config_bytes=b"[Interface]\nPrivateKey = test",
                config_caption="VPN-конфиг (.conf)",
                qr_filename="Neobyatnaya-AMNZ-7.qr.png",
                qr_png_bytes=b"\x89PNG\r\n\x1a\n",
                qr_caption="QR-код import-ссылки vpn://",
            ),
        )

    def get_config_ready_template(self, *, admin_telegram_id):
        if not self.is_admin(admin_telegram_id):
            return None
        return "DefaultVPN template {device_id}"

    def reset_config_ready_template(self, *, admin_telegram_id):
        if not self.is_admin(admin_telegram_id):
            return False
        self.template_reset = True
        return True

    def build_resend_delivery(self, *, admin_telegram_id, device_id):
        if not self.is_admin(admin_telegram_id):
            return None
        self.resends.append(device_id)
        return SimpleNamespace(
            device_id=device_id,
            user_telegram_id=1001,
            config_text="[Interface]\nPrivateKey = test",
            delivery=SimpleNamespace(
                message_text="Ваш VPN-конфиг готов.",
                vpn_import_link_text="Ссылка для импорта:\nvpn://import/test",
                app_links_text="DefaultVPN:\nhttps://github.com/amnezia-vpn/DefaultVPN",
                config_filename=f"Neobyatnaya-AMNZ-{device_id}.conf",
                config_bytes=b"[Interface]\nPrivateKey = test",
                config_caption="VPN-конфиг (.conf)",
                qr_filename=f"Neobyatnaya-AMNZ-{device_id}.qr.png",
                qr_png_bytes=b"\x89PNG\r\n\x1a\n",
                qr_caption="QR-код import-ссылки vpn://",
            ),
        )


class FakeBot:
    def __init__(self):
        self.sent_messages = []
        self.sent_documents = []
        self.sent_photos = []

    async def send_message(self, chat_id, text, reply_markup=None):
        self.sent_messages.append(
            {"chat_id": chat_id, "text": text, "reply_markup": reply_markup}
        )

    async def send_document(self, chat_id, document, caption=None):
        self.sent_documents.append(
            {"chat_id": chat_id, "document": document, "caption": caption}
        )

    async def send_photo(self, chat_id, photo, caption=None):
        self.sent_photos.append(
            {"chat_id": chat_id, "photo": photo, "caption": caption}
        )


def _button_texts(markup):
    return [[button.text for button in row] for row in markup.inline_keyboard]


def _callback_data(markup):
    return [[button.callback_data for button in row] for row in markup.inline_keyboard]
