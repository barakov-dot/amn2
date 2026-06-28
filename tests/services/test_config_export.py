from app.bot.delivery import build_config_delivery
from app.services.config_delivery import DeviceConfigDelivery
from app.services.config_export import (
    ConfigExportRequest,
    export_device_config_delivery,
    run_config_exporter,
)


CONFIG_TEXT = (
    "[Interface]\n"
    "PrivateKey = client-private\n"
    "Address = 10.8.0.2/32\n"
    "[Peer]\n"
    "PresharedKey = client-psk\n"
    "Endpoint = vpn.example.com:30001\n"
)


def test_device_config_delivery_exports_typed_secret_artifacts():
    delivery = _device_delivery()
    result = export_device_config_delivery(delivery, _request())

    assert result.status == "success"
    assert result.secret_class == "client-config-secret"
    assert [artifact.kind for artifact in result.artifacts] == [
        "wireguard_conf",
        "qr_payload",
        "qr_png",
        "amnezia_import_uri",
        "delivery_message",
    ]
    assert result.artifacts[0].payload == CONFIG_TEXT.encode("utf-8")
    assert result.artifacts[1].payload == CONFIG_TEXT
    assert result.artifacts[2].payload.startswith(b"\x89PNG\r\n\x1a\n")
    assert result.artifacts[3].payload.startswith("vpn://")
    assert result.artifacts[4].payload == delivery.delivery.message_text
    assert result.artifacts[1].safe_metadata()["qr_payload_kind"] == "wireguard_conf"


def test_config_export_safe_metadata_excludes_secret_payloads():
    result = export_device_config_delivery(_device_delivery(), _request())

    safe_text = str(result.safe_metadata())
    for unsafe in [
        "client-private",
        "client-psk",
        "[Interface]",
        "vpn://",
        "PrivateKey",
        "PresharedKey",
    ]:
        assert unsafe not in safe_text
    assert result.safe_metadata() == {
        "status": "success",
        "protocol_id": "amneziawg",
        "config_version": "amneziawg_v2",
        "target_client": "amnezia_generic",
        "device_id": 7,
        "user_id": 42,
        "server_id": 3,
        "secret_class": "client-config-secret",
        "artifact_kinds": [
            "wireguard_conf",
            "qr_payload",
            "qr_png",
            "amnezia_import_uri",
            "delivery_message",
        ],
        "warnings": [],
    }
    assert result.artifacts[0].safe_metadata() == {
        "kind": "wireguard_conf",
        "target_client": "amnezia_generic",
        "filename": "Neobyatnaya-AMNZ-N.conf",
        "media_type": "text/plain",
        "content_encoding": "utf-8",
        "secret_class": "client-config-secret",
        "payload_size": len(CONFIG_TEXT.encode("utf-8")),
    }


def test_unsupported_artifact_returns_safe_category_without_payload():
    request = _request(requested_artifacts=("subscription_uri",))

    result = export_device_config_delivery(_device_delivery(), request)

    assert result.status == "unsupported_artifact"
    assert result.artifacts == ()
    assert result.safe_metadata()["warnings"] == ["unsupported_artifact"]
    assert "subscription_uri" not in str(result.safe_metadata())
    assert "client-private" not in str(result.safe_metadata())


def test_unsupported_target_client_returns_safe_category_without_payload():
    request = _request(target_client="unknown_client")

    result = export_device_config_delivery(_device_delivery(), request)

    assert result.status == "unsupported_target_client"
    assert result.artifacts == ()
    assert result.safe_metadata()["warnings"] == ["unsupported_target_client"]
    assert "unknown_client" not in str(result.safe_metadata())
    assert "client-private" not in str(result.safe_metadata())


def test_exporter_signature_mismatch_becomes_safe_export_failed_result():
    class MismatchedExporter:
        def export_config(self):
            raise AssertionError("must be called through the contract")

    result = run_config_exporter(MismatchedExporter(), _request())

    assert result.status == "export_failed"
    assert result.artifacts == ()
    assert result.safe_metadata()["warnings"] == ["export_failed"]
    assert "TypeError" not in str(result.safe_metadata())
    assert "export_config" not in str(result.safe_metadata())


def _device_delivery() -> DeviceConfigDelivery:
    package = build_config_delivery(
        device_id=7,
        config_version="amneziawg_v2",
        config_text=CONFIG_TEXT,
        template_text="Import link: {vpn_link}",
    )
    return DeviceConfigDelivery(
        device_id=7,
        user_telegram_id=1001,
        config_text=CONFIG_TEXT,
        delivery=package,
    )


def _request(**overrides) -> ConfigExportRequest:
    values = {
        "actor_type": "web-admin",
        "actor_id": "root",
        "device_id": 7,
        "user_id": 42,
        "server_id": 3,
        "protocol_id": "amneziawg",
        "config_version": "amneziawg_v2",
        "target_client": "amnezia_generic",
        "requested_artifacts": (
            "wireguard_conf",
            "qr_payload",
            "qr_png",
            "amnezia_import_uri",
            "delivery_message",
        ),
        "delivery_channel": "web",
    }
    values.update(overrides)
    return ConfigExportRequest(**values)
