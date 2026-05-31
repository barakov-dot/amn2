import base64

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.security.redaction import redact
from app.services.config_delivery import build_device_config_delivery
import app.vpn.amneziawg_v2.config as awg_config


def _decode_vpn_link(link: str) -> str:
    payload = link.removeprefix("vpn://")
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload + padding).decode("utf-8")


def test_device_config_delivery_uses_client_config_defaults(tmp_path):
    conn = connect(tmp_path / "delivery.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    secret_box = SecretBox.from_app_secret("test-secret-for-config-delivery-123456")
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.2",
        peer_public_key="client-public",
        peer_private_key_encrypted=secret_box.encrypt_text("client-private"),
        preshared_key_encrypted=secret_box.encrypt_text("client-psk"),
        config_version="amneziawg_v2",
    )

    result = build_device_config_delivery(
        repo=repo,
        secret_box=secret_box,
        device=repo.get_device(device_id),
        client_config_defaults=awg_config.ClientConfigDefaults(
            dns="9.9.9.9",
            allowed_ips="10.0.0.0/8",
            persistent_keepalive=15,
            jc=8,
            jmin=12,
            jmax=42,
            s1=11,
            s2=22,
            h1=101,
            h2=202,
            h3=303,
            h4=404,
        ),
    )

    assert "DNS = 9.9.9.9" in result.config_text
    assert "AllowedIPs = 10.0.0.0/8" in result.config_text
    assert "PersistentKeepalive = 15" in result.config_text
    assert "Jc = 8" in result.config_text
    assert "Jmin = 12" in result.config_text
    assert "Jmax = 42" in result.config_text
    assert "S1 = 11" in result.config_text
    assert "S2 = 22" in result.config_text
    assert "H1 = 101" in result.config_text
    assert "H2 = 202" in result.config_text
    assert "H3 = 303" in result.config_text
    assert "H4 = 404" in result.config_text


def test_device_config_delivery_preserves_utf8_artifacts_from_template(tmp_path):
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "amneziawg_v2.conf.tpl").write_text(
        (
            "# Profile = телефон-Ф\n"
            "[Interface]\n"
            "PrivateKey = {private_key}\n"
            "Address = {address}\n"
            "DNS = {dns}\n"
            "[Peer]\n"
            "PublicKey = {server_public_key}\n"
            "PresharedKey = {preshared_key}\n"
            "Endpoint = {endpoint}\n"
            "AllowedIPs = {allowed_ips}\n"
            "PersistentKeepalive = {persistent_keepalive}\n"
            "Jc = {jc}\n"
            "Jmin = {jmin}\n"
            "Jmax = {jmax}\n"
            "S1 = {s1}\n"
            "S2 = {s2}\n"
            "H1 = {h1}\n"
            "H2 = {h2}\n"
            "H3 = {h3}\n"
            "H4 = {h4}\n"
        ),
        encoding="utf-8",
    )
    conn = connect(tmp_path / "delivery.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    secret_box = SecretBox.from_app_secret("test-secret-for-config-delivery-123456")
    user_id = repo.upsert_user(
        telegram_id=1002,
        username="ivan",
        first_name="Иван",
        last_name="Тест",
    )
    server_id = repo.ensure_default_server(name="moscow", network_cidr="10.8.0.0/24")
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="телефон-Ф",
        duration_days=7,
        vpn_ip="10.8.0.3",
        peer_public_key="client-public",
        peer_private_key_encrypted=secret_box.encrypt_text("client-private"),
        preshared_key_encrypted=secret_box.encrypt_text("client-psk"),
        config_version="amneziawg_v2",
    )

    result = build_device_config_delivery(
        repo=repo,
        secret_box=secret_box,
        device=repo.get_device(device_id),
        client_config_template_dir=str(template_dir),
    )

    assert "# Profile = телефон-Ф" in result.config_text
    assert result.delivery.config_bytes == result.config_text.encode("utf-8")
    assert result.delivery.qr_payload_text == result.config_text
    assert _decode_vpn_link(result.delivery.vpn_import_link) == result.config_text
    assert result.delivery.config_secret_class == "client-config-secret"
    redacted_delivery_text = redact(
        "\n".join(
            [
                result.delivery.message_text,
                result.delivery.vpn_import_link,
                result.delivery.qr_payload_text,
            ]
        )
    )
    assert "vpn://" not in redacted_delivery_text
    assert "client-private" not in redacted_delivery_text
    assert "client-psk" not in redacted_delivery_text
    assert "[Interface]" not in redacted_delivery_text
