import base64

import pytest

from app.bot.delivery import (
    APP_LINKS,
    CONFIG_READY_TEMPLATE_KEY,
    DEFAULT_CONFIG_READY_TEMPLATE,
    build_config_delivery,
    render_template,
)
from app.security.redaction import redact


TELEGRAM_COPY_TEXT_MAX_LENGTH = 256


def _decode_vpn_link(link: str) -> str:
    payload = link.removeprefix("vpn://")
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload + padding).decode("utf-8")


def test_build_config_delivery_creates_conf_and_qr_png_bytes():
    package = build_config_delivery(
        device_id=7,
        device_name="Neobyatnaya-AMNZ-7",
        config_version="amneziawg_v2",
        config_text="[Interface]\nPrivateKey = test\n[Peer]",
        template_text=(
            "Access for device #{device_id}: {config_version_label}\n"
            "{android_amnezia}\n{ios_russia_defaultvpn}\n"
            "Import link: {vpn_link}"
        ),
    )

    assert package.template_key == CONFIG_READY_TEMPLATE_KEY
    assert package.vpn_import_link.startswith("vpn://")
    assert "PrivateKey" not in package.vpn_import_link
    assert "PrivateKey" not in package.message_text
    assert package.vpn_import_link in package.message_text
    assert package.config_filename == "Neobyatnaya.NET-7.conf"
    assert package.config_bytes.startswith(b"[Interface]")
    assert package.qr_filename == "Neobyatnaya.NET-7.qr.png"
    assert package.qr_png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert "Access for device #7" in package.message_text
    assert "AmneziaWG 2.0" in package.message_text
    assert APP_LINKS["ios_russia_defaultvpn"] in package.message_text
    assert package.vpn_import_link in package.vpn_import_link_text
    assert "кнопку ниже" in package.vpn_import_link_text
    assert APP_LINKS["ios_russia_defaultvpn"] in package.app_links_text
    assert "основной способ установки" in package.config_caption
    assert "сканера внутри VPN-клиента" in package.qr_caption
    assert "Камера телефона" in package.qr_caption
    assert package.qr_payload_text == "[Interface]\nPrivateKey = test\n[Peer]"


def test_build_config_delivery_marks_short_import_link_copyable():
    package = build_config_delivery(
        device_id=1,
        config_version="amneziawg_v2",
        config_text="short",
        template_text="VPN готов.",
    )

    assert len(package.vpn_import_link) <= TELEGRAM_COPY_TEXT_MAX_LENGTH
    assert package.vpn_import_link_copy_button_text == "Скопировать ссылку"
    assert package.vpn_import_link_copy_text == package.vpn_import_link


def test_build_config_delivery_does_not_mark_long_import_link_copyable():
    package = build_config_delivery(
        device_id=2,
        config_version="amneziawg_v2",
        config_text="x" * TELEGRAM_COPY_TEXT_MAX_LENGTH,
        template_text="VPN готов.",
    )

    assert len(package.vpn_import_link) > TELEGRAM_COPY_TEXT_MAX_LENGTH
    assert package.vpn_import_link_copy_button_text == ""
    assert package.vpn_import_link_copy_text is None
    assert "слишком длинная для кнопки копирования Telegram" in package.vpn_import_link_text
    assert "Основной способ установки" in package.vpn_import_link_text
    assert "обычной камеры телефона" in package.vpn_import_link_text


def test_render_template_leaves_unknown_placeholders_visible_for_admins_to_fix():
    text = render_template("Hello {name}. {unknown}", {"name": "Alice"})

    assert text == "Hello Alice. {unknown}"


def test_default_config_ready_template_mentions_all_delivery_options():
    assert ".conf" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "QR" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "Ваш VPN-конфиг готов" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "iPhone в РФ" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "DefaultVPN" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "Android" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "AmneziaWG" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "ссылку vpn://" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "Обычная камера телефона" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "не всегда дает кнопку копирования" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "Ниже бот отправит" in DEFAULT_CONFIG_READY_TEMPLATE


def test_app_links_text_includes_client_compatibility_guidance():
    package = build_config_delivery(
        device_id=10,
        config_version="amneziawg_v2",
        config_text="[Interface]\nPrivateKey = test\n[Peer]",
        template_text="VPN готов.",
    )

    assert APP_LINKS["android_amnezia"] in package.app_links_text
    assert "Приложения для импорта VPN-профиля" in package.app_links_text
    assert "Файл .conf" in package.app_links_text
    assert "iPhone / iPad: DefaultVPN" in package.app_links_text
    assert "Android: AmneziaWG" in package.app_links_text
    assert "Windows: AmneziaWG" in package.app_links_text
    assert "Android 9+" in package.app_links_text
    assert "macOS 13+" in package.app_links_text
    assert "PrivateKey" not in package.app_links_text


def test_build_config_delivery_preserves_utf8_secret_artifacts():
    config_text = (
        "[Interface]\n"
        "# Profile = телефон-Ф\n"
        "PrivateKey = client-private\n"
        "Address = 10.8.0.2/32\n"
        "[Peer]\n"
        "Endpoint = vpn.example.com:30001\n"
    )

    package = build_config_delivery(
        device_id=8,
        config_version="amneziawg_v2",
        config_text=config_text,
        template_text="Import link: {vpn_link}",
    )

    assert package.config_bytes == config_text.encode("utf-8")
    assert package.qr_payload_text == config_text
    assert package.config_secret_class == "client-config-secret"
    assert package.config_content_encoding == "utf-8"
    assert package.vpn_import_link_encoding == "base64-url-no-padding"
    assert _decode_vpn_link(package.vpn_import_link) == config_text
    assert "client-private" not in package.vpn_import_link


def test_build_config_delivery_uses_canonical_standalone_awg_import_filename():
    package = build_config_delivery(
        device_id=17,
        device_name="Neobyatnaya-AMNZ-17",
        config_version="amneziawg_v2",
        config_text="[Interface]\nPrivateKey = test\n[Peer]",
        template_text="Устройство: {device_name}",
    )

    assert package.config_filename == "Neobyatnaya.NET-17.conf"
    assert package.qr_filename == "Neobyatnaya.NET-17.qr.png"
    assert "Neobyatnaya-AMNZ-17" in package.message_text


def test_build_config_delivery_accepts_canonical_admin_attachment_filename():
    package = build_config_delivery(
        device_id=17,
        device_name="NEOBYATNAYA.NET — Иван — Pixel 8",
        config_version="amneziawg_v2",
        config_text="[Interface]\nPrivateKey = test\n[Peer]",
        template_text="Устройство: {device_name}",
        attachment_filename="NEOBYATNAYA.NET-Ivan-Pixel-8-d17.conf",
    )

    assert package.config_filename == "NEOBYATNAYA.NET-Ivan-Pixel-8-d17.conf"
    assert package.qr_filename == "Neobyatnaya.NET-17.qr.png"
    assert "NEOBYATNAYA.NET — Иван — Pixel 8" in package.message_text


@pytest.mark.parametrize(
    "attachment_filename",
    [
        "../device.conf",
        "folder/device.conf",
        "folder\\device.conf",
        "device.conf:stream.conf",
        f"{'a' * 92}.conf",
        "device.txt",
    ],
)
def test_build_config_delivery_rejects_unsafe_attachment_filename(
    attachment_filename,
):
    with pytest.raises(ValueError, match="attachment_filename"):
        build_config_delivery(
            device_id=17,
            config_version="amneziawg_v2",
            config_text="[Interface]\nPrivateKey = test\n[Peer]",
            template_text="ready",
            attachment_filename=attachment_filename,
        )


def test_build_config_delivery_owner_shared_uses_brand_filename_and_unbounded_scope():
    package = build_config_delivery(
        device_id=8,
        device_name="Owner shared",
        config_version="amneziawg_v2",
        config_text="[Interface]\nPrivateKey = test\n[Peer]",
        template_text="Устройство: {device_name}",
        assignment_mode="owner_shared",
    )

    assert package.config_filename == "Neobyatnaya.NET.conf"
    assert package.assignment_mode == "owner_shared"
    assert package.physical_device_limit is None
    assert package.physical_device_count_enforceable is False


def test_config_delivery_artifacts_redact_when_rendered_as_text():
    config_text = (
        "[Interface]\n"
        "PrivateKey = client-private\n"
        "Address = 10.8.0.2/32\n"
        "[Peer]\n"
        "PublicKey = server-public\n"
        "PresharedKey = client-psk\n"
        "Endpoint = vpn.example.com:30001\n"
    )
    package = build_config_delivery(
        device_id=9,
        config_version="amneziawg_v2",
        config_text=config_text,
        template_text="Import link: {vpn_link}",
    )

    unsafe_text = "\n".join(
        [
            package.message_text,
            package.vpn_import_link,
            package.vpn_import_link_text,
            package.app_links_text,
            package.qr_payload_text,
            package.config_bytes.decode("utf-8"),
        ]
    )
    safe = redact(unsafe_text)

    for unsafe_value in [
        "vpn://",
        "client-private",
        "client-psk",
        "[Interface]",
        "[Peer]",
    ]:
        assert unsafe_value not in safe
    assert "[CONFIG REDACTED]" in safe
    assert "[REDACTED]" in safe
