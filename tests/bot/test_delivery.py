import base64

from app.bot.delivery import (
    APP_LINKS,
    CONFIG_READY_TEMPLATE_KEY,
    DEFAULT_CONFIG_READY_TEMPLATE,
    build_config_delivery,
    render_template,
)


def _decode_vpn_link(link: str) -> str:
    payload = link.removeprefix("vpn://")
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload + padding).decode("utf-8")


def test_build_config_delivery_creates_conf_and_qr_png_bytes():
    package = build_config_delivery(
        device_id=7,
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
    assert package.config_filename == "amneziya-device-7.conf"
    assert package.config_bytes.startswith(b"[Interface]")
    assert package.qr_filename == "amneziya-device-7.qr.png"
    assert package.qr_png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert "AmneziaWG 2.0" in package.message_text
    assert APP_LINKS["ios_russia_defaultvpn"] in package.message_text


def test_render_template_leaves_unknown_placeholders_visible_for_admins_to_fix():
    text = render_template("Hello {name}. {unknown}", {"name": "Alice"})

    assert text == "Hello Alice. {unknown}"


def test_default_config_ready_template_mentions_all_delivery_options():
    assert ".conf" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "QR" in DEFAULT_CONFIG_READY_TEMPLATE
    assert "{vpn_link}" in DEFAULT_CONFIG_READY_TEMPLATE


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
