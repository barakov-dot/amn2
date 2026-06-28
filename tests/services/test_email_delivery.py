from email import policy
from email.parser import BytesParser

from app.bot.delivery import ConfigDeliveryPackage
from app.services.email_delivery import EmailDeliveryService
from app.services.email_delivery import build_smtp_sender


def test_config_email_contains_vpn_link_and_optional_conf_attachment():
    sender = RecordingSender()
    service = EmailDeliveryService(
        sender=sender,
        from_address="vpn@example.com",
        base_url="https://admin.example.com",
        attach_config=True,
    )
    delivery = _delivery(config_text="PRIVATE_CONFIG_TEXT_SHOULD_NOT_BE_IN_BODY")

    service.send_config_email(
        to_address="alice@example.com",
        user_id=11,
        device_id=22,
        delivery=delivery,
    )

    message = _parsed(sender.messages[0])
    assert message["To"] == "alice@example.com"
    assert message["From"] == "vpn@example.com"
    body = message.get_body(preferencelist=("plain",)).get_content()
    assert "vpn://import/test" in body
    assert "PRIVATE_CONFIG_TEXT_SHOULD_NOT_BE_IN_BODY" not in body
    attachments = list(message.iter_attachments())
    assert [part.get_filename() for part in attachments] == ["Neobyatnaya-AMNZ-N.conf"]
    assert (
        attachments[0].get_payload(decode=True).strip()
        == b"PRIVATE_CONFIG_TEXT_SHOULD_NOT_BE_IN_BODY"
    )


def test_config_email_can_omit_conf_attachment():
    sender = RecordingSender()
    service = EmailDeliveryService(
        sender=sender,
        from_address="vpn@example.com",
        base_url="https://admin.example.com",
        attach_config=False,
    )

    service.send_config_email(
        to_address="alice@example.com",
        user_id=11,
        device_id=22,
        delivery=_delivery(config_text="SECRET_CONFIG"),
    )

    message = _parsed(sender.messages[0])
    assert list(message.iter_attachments()) == []
    assert "SECRET_CONFIG" not in message.get_body(preferencelist=("plain",)).get_content()


def test_verification_and_recovery_messages_include_links_without_raw_token_in_metadata():
    sender = RecordingSender()
    service = EmailDeliveryService(
        sender=sender,
        from_address="vpn@example.com",
        base_url="https://admin.example.com",
        attach_config=True,
    )

    verify_metadata = service.send_verification_email(
        to_address="alice@example.com",
        user_id=11,
        token="RAW_VERIFY_TOKEN",
    )
    recovery_metadata = service.send_recovery_start_email(
        to_address="alice@example.com",
        user_id=11,
        device_id=22,
        token="RAW_RECOVERY_TOKEN",
    )

    verify_body = _parsed(sender.messages[0]).get_body(preferencelist=("plain",)).get_content()
    recovery_body = _parsed(sender.messages[1]).get_body(preferencelist=("plain",)).get_content()
    assert "https://admin.example.com/email/verify" in verify_body
    assert "https://admin.example.com/email/recover" in recovery_body
    assert "/email/verify?token=" not in verify_body
    assert "/email/recover?token=" not in recovery_body
    assert "RAW_VERIFY_TOKEN" in verify_body
    assert "RAW_RECOVERY_TOKEN" in recovery_body
    assert "RAW_VERIFY_TOKEN" not in str(verify_metadata)
    assert "RAW_RECOVERY_TOKEN" not in str(recovery_metadata)
    assert verify_metadata == {"channel": "email", "status": "sent", "purpose": "verify_email"}
    assert recovery_metadata == {
        "channel": "email",
        "status": "sent",
        "purpose": "recover_config",
    }


def test_build_smtp_sender_uses_injected_factory_without_connecting_in_unit_tests():
    smtp = RecordingSmtp()
    sender = build_smtp_sender(
        host="smtp.example.com",
        port=587,
        username="smtp-user",
        password="smtp-password",
        use_tls=True,
        smtp_factory=smtp,
    )

    sender("alice@example.com", b"Subject: Test\r\n\r\nBody")

    assert smtp.host == "smtp.example.com"
    assert smtp.port == 587
    assert smtp.started_tls is True
    assert smtp.login_calls == [("smtp-user", "smtp-password")]
    assert smtp.sent == [("alice@example.com", b"Subject: Test\r\n\r\nBody")]
    assert smtp.closed is True


class RecordingSender:
    def __init__(self):
        self.messages = []

    def __call__(self, to_address: str, message_bytes: bytes) -> None:
        self.messages.append(message_bytes)


class RecordingSmtp:
    def __init__(self):
        self.host = None
        self.port = None
        self.started_tls = False
        self.login_calls = []
        self.sent = []
        self.closed = False

    def __call__(self, host, port):
        self.host = host
        self.port = port
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def starttls(self):
        self.started_tls = True

    def login(self, username, password):
        self.login_calls.append((username, password))

    def sendmail(self, from_address, to_address, message_bytes):
        self.sent.append((to_address, message_bytes))


def _delivery(*, config_text: str) -> ConfigDeliveryPackage:
    return ConfigDeliveryPackage(
        template_key="config_ready",
        message_text="Your config is ready",
        config_filename="Neobyatnaya-AMNZ-N.conf",
        config_bytes=config_text.encode("utf-8"),
        qr_filename="amneziya-device-22.qr.png",
        qr_png_bytes=b"png",
        vpn_import_link="vpn://import/test",
    )


def _parsed(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)
