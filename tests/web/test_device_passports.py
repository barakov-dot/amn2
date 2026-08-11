from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.bot.delivery import ConfigDeliveryPackage
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.device_passports import create_device_passport
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.vpn.protocol_versions import ProtocolVersion
from app.web.app import create_web_app
from app.web.auth import create_password_hash

TEST_APP_SECRET = "test-secret-for-device-passports-1234567890"


def test_device_passport_routes_redirect_when_unauthenticated(tmp_path: Path):
    client = _client(tmp_path)

    for path in (
        "/device-passports",
        "/device-passports/dev_missing",
        "/device-passports/dev_missing/config",
        "/device-passports/dev_missing/qr",
    ):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_device_passport_list_and_detail_render_safe_read_only_metadata(
    tmp_path: Path,
):
    settings, passport_id = _seed_database(tmp_path)
    client = _authenticated_client(settings)
    before = _database_dump(Path(settings.database_path))

    listing = client.get("/device-passports")
    detail = client.get(f"/device-passports/{passport_id}")
    after = _database_dump(Path(settings.database_path))

    assert listing.status_code == 200
    assert "Паспорта устройств" in listing.text
    assert passport_id in listing.text
    assert "passport-web-owner" in listing.text
    assert "Последние 100 записей" in listing.text
    assert detail.status_code == 200
    assert "Жизненный цикл" in detail.text
    assert "Возможности и ограничения" in detail.text
    assert "collect_fresh_observation" in detail.text
    assert "hardware_fingerprint" in detail.text
    assert "false" in detail.text.lower()
    assert "AWG2" in detail.text
    assert "AWG3" in detail.text
    assert "rt-spain-awg3" in detail.text
    assert "5.0.0.5" in detail.text
    assert "win-5005-stable" in detail.text
    assert "compat-win-5005-awg3" in detail.text
    assert re.search(
        rf'data-protocol="awg2"[\s\S]*?href="/device-passports/{passport_id}/config\?protocol=awg2"',
        detail.text,
    )
    assert re.search(
        rf'data-protocol="awg3"[\s\S]*?href="/device-passports/{passport_id}/config\?protocol=awg3"',
        detail.text,
    )
    for forbidden in (
        "never-render-this-private-config",
        "encrypted-web-private-key",
        "encrypted-web-psk",
        "amn2_enroll_",
    ):
        assert forbidden not in listing.text
        assert forbidden not in detail.text
    assert after == before


def test_device_passport_secret_config_and_qr_are_admin_only_and_audited(tmp_path: Path):
    settings, passport_id = _seed_database(tmp_path)
    client = _authenticated_client(settings)

    config = client.get(f"/device-passports/{passport_id}/config")
    qr = client.get(f"/device-passports/{passport_id}/qr")

    assert config.status_code == 200
    assert config.headers["content-type"].startswith("application/octet-stream")
    assert config.headers["content-disposition"].endswith('.conf"')
    assert qr.status_code == 200
    assert qr.headers["content-type"].startswith("image/png")
    assert qr.content.startswith(b"\x89PNG\r\n\x1a\n")
    conn = connect(Path(settings.database_path))
    try:
        rows = conn.execute(
            "SELECT event_type, protocol_version, local_device_id, metadata_json "
            "FROM protocol_config_events "
            "WHERE event_type = 'config_secret_viewed' ORDER BY id"
        ).fetchall()
        awg2_profile = conn.execute(
            "SELECT local_device_id FROM device_protocol_profiles "
            "WHERE passport_device_id = ? AND protocol_version = 'awg2'",
            (passport_id,),
        ).fetchone()
    finally:
        conn.close()
    assert [row["event_type"] for row in rows] == [
        "config_secret_viewed",
        "config_secret_viewed",
    ]
    assert [(row["protocol_version"], row["local_device_id"]) for row in rows] == [
        ("awg2", int(awg2_profile["local_device_id"])),
        ("awg2", int(awg2_profile["local_device_id"])),
    ]
    assert [set(json.loads(row["metadata_json"])) for row in rows] == [
        {"passport_device_id", "local_device_id"},
        {"passport_device_id", "local_device_id"},
    ]


def test_device_passport_secret_routes_select_exact_protocol_profiles(
    tmp_path: Path,
    monkeypatch,
):
    settings, passport_id = _seed_database(tmp_path)
    conn = connect(Path(settings.database_path))
    try:
        profiles = {
            str(row["protocol_version"]): int(row["local_device_id"])
            for row in conn.execute(
                "SELECT protocol_version, local_device_id "
                "FROM device_protocol_profiles WHERE passport_device_id = ?",
                (passport_id,),
            ).fetchall()
        }
    finally:
        conn.close()
    selected_device_ids = []

    def synthetic_delivery(**kwargs):
        device_id = int(kwargs["device"]["id"])
        selected_device_ids.append(device_id)
        return SimpleNamespace(
            delivery=ConfigDeliveryPackage(
                template_key="config_ready",
                message_text="synthetic profile delivery",
                config_filename=f"synthetic-{device_id}.conf",
                config_bytes=f"synthetic-config-{device_id}".encode(),
                qr_filename=f"synthetic-{device_id}.qr.png",
                qr_png_bytes=b"\x89PNG\r\n\x1a\n" + str(device_id).encode(),
                vpn_import_link="synthetic-import-reference",
            )
        )

    monkeypatch.setattr("app.web.app.build_device_config_delivery", synthetic_delivery)
    client = _authenticated_client(settings)

    awg2_default = client.get(f"/device-passports/{passport_id}/config")
    awg3_config = client.get(
        f"/device-passports/{passport_id}/config?protocol=awg3"
    )
    awg2_qr = client.get(f"/device-passports/{passport_id}/qr?protocol=awg2")
    awg3_qr = client.get(f"/device-passports/{passport_id}/qr?protocol=awg3")

    assert awg2_default.content == f"synthetic-config-{profiles['awg2']}".encode()
    assert awg3_config.content == f"synthetic-config-{profiles['awg3']}".encode()
    assert awg2_qr.content.endswith(str(profiles["awg2"]).encode())
    assert awg3_qr.content.endswith(str(profiles["awg3"]).encode())
    assert selected_device_ids == [
        profiles["awg2"],
        profiles["awg3"],
        profiles["awg2"],
        profiles["awg3"],
    ]
    conn = connect(Path(settings.database_path))
    try:
        audited = conn.execute(
            "SELECT protocol_version, local_device_id, metadata_json "
            "FROM protocol_config_events WHERE event_type = 'config_secret_viewed' "
            "ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert [(row["protocol_version"], row["local_device_id"]) for row in audited] == [
        ("awg2", profiles["awg2"]),
        ("awg3", profiles["awg3"]),
        ("awg2", profiles["awg2"]),
        ("awg3", profiles["awg3"]),
    ]
    assert all(
        set(json.loads(row["metadata_json"]))
        == {"passport_device_id", "local_device_id"}
        for row in audited
    )


def test_device_passport_secret_routes_fail_closed_without_exact_active_profile(
    tmp_path: Path,
    monkeypatch,
):
    settings, passport_id = _seed_database(tmp_path)
    delivery_calls = []

    def unexpected_delivery(**kwargs):
        device_id = int(kwargs["device"]["id"])
        delivery_calls.append(device_id)
        return SimpleNamespace(delivery=ConfigDeliveryPackage(
            template_key="config_ready",
            message_text="synthetic unexpected delivery",
            config_filename="synthetic-unexpected.conf",
            config_bytes=b"synthetic-unexpected-config",
            qr_filename="synthetic-unexpected.qr.png",
            qr_png_bytes=b"\x89PNG\r\n\x1a\nsynthetic-unexpected",
            vpn_import_link="synthetic-import-reference",
        ))

    monkeypatch.setattr(
        "app.web.app.build_device_config_delivery",
        unexpected_delivery,
    )
    client = _authenticated_client(settings)

    invalid = client.get(
        f"/device-passports/{passport_id}/config?protocol=not-a-protocol"
    )
    conn = connect(Path(settings.database_path))
    try:
        awg3_profile = conn.execute(
            "SELECT id FROM device_protocol_profiles "
            "WHERE passport_device_id = ? AND protocol_version = 'awg3'",
            (passport_id,),
        ).fetchone()
        Repository(conn).update_device_protocol_profile(
            profile_id=int(awg3_profile["id"]),
            lifecycle_state="review_required",
            replacement_device_id=None,
        )
    finally:
        conn.close()
    inactive = client.get(
        f"/device-passports/{passport_id}/config?protocol=awg3"
    )
    conn = connect(Path(settings.database_path))
    try:
        conn.execute(
            "DELETE FROM device_protocol_profiles "
            "WHERE passport_device_id = ? AND protocol_version = 'awg3'",
            (passport_id,),
        )
        conn.commit()
    finally:
        conn.close()
    missing = client.get(f"/device-passports/{passport_id}/qr?protocol=awg3")

    assert (invalid.status_code, inactive.status_code, missing.status_code) == (
        400,
        400,
        400,
    )
    assert delivery_calls == []


def test_device_passport_detail_returns_fixed_not_found(tmp_path: Path):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)

    response = client.get("/device-passports/dev_reflect_me")

    assert response.status_code == 404
    assert response.text == "Device passport not found"
    assert "dev_reflect_me" not in response.text


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key=TEST_APP_SECRET,
        database_path=str(tmp_path / "amneziya.sqlite3"),
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
        vps_apply_enabled=False,
        server_config_path=str(tmp_path / "servers.yml"),
    )


def _client(
    tmp_path: Path | None = None,
    *,
    settings: Settings | None = None,
) -> TestClient:
    actual_settings = settings or _settings(tmp_path or Path("."))
    return TestClient(
        create_web_app(actual_settings),
        base_url="https://testserver",
    )


def _authenticated_client(settings: Settings) -> TestClient:
    client = _client(settings=settings)
    login_page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": "root",
            "password": "correct-password",
            "csrf_token": _csrf_token(login_page.text),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    return client


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _seed_database(tmp_path: Path) -> tuple[Settings, str]:
    settings = _settings(tmp_path)
    conn = connect(Path(settings.database_path))
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        user_id = repo.upsert_user(
            telegram_id=18002,
            username="passport-web-owner",
            first_name="Passport",
            last_name="Web",
        )
        server_id = repo.ensure_default_server(
            name="local",
            network_cidr="10.8.0.0/24",
        )
        local_device_id = repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="web-phone",
            duration_days=30,
            vpn_ip="10.8.0.24",
            peer_public_key="web-passport-public-key",
            peer_private_key_encrypted=SecretBox.from_app_secret(
                TEST_APP_SECRET
            ).encrypt_text("synthetic-web-private-key"),
            preshared_key_encrypted=SecretBox.from_app_secret(
                TEST_APP_SECRET
            ).encrypt_text("synthetic-web-psk"),
            config_version="amneziawg_v2",
            protocol_version="awg2",
            runtime_instance_id="rt-spain-awg2",
            compatibility_evidence_id="compat-android-awg2",
            client_identity_evidence_status="verified",
        )
        passport = create_device_passport(
            repo,
            owner_user_id=user_id,
            local_device_id=local_device_id,
            platform="android",
            official_client_type="amnezia_vpn",
            import_method="standard_conf",
            config_schema_version="amneziawg_v2",
            config_text="never-render-this-private-config",
        )
        profiles = DualProtocolProfileService(repo)
        profiles.attach_active(
            passport.device_id, ProtocolVersion.AWG2, local_device_id
        )
        attempt = repo.reserve_protocol_issuance_attempt(
            passport_device_id=passport.device_id,
            protocol_version="awg3",
            request_fingerprint="sha256:" + "b" * 64,
            actor_kind="user",
            actor_id=18002,
            client_application="amnezia_vpn",
            client_platform="windows",
            client_version="5.0.0.5",
            client_build="win-5005-stable",
            runtime_instance_id="rt-spain-awg3",
            compatibility_evidence_id="compat-win-5005-awg3",
        )
        assert attempt is not None
        awg3_device_id = repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="web-phone-awg3",
            duration_days=30,
            vpn_ip="10.8.0.25",
            peer_public_key="web-passport-awg3-public-key",
            peer_private_key_encrypted=SecretBox.from_app_secret(
                TEST_APP_SECRET
            ).encrypt_text("synthetic-web-awg3-private-key"),
            preshared_key_encrypted=SecretBox.from_app_secret(
                TEST_APP_SECRET
            ).encrypt_text("synthetic-web-awg3-psk"),
            config_version="amneziawg_v3",
            protocol_version="awg3",
            runtime_instance_id="rt-spain-awg3",
            compatibility_evidence_id="compat-win-5005-awg3",
            client_identity_evidence_status="verified",
        )
        with repo.transaction():
            profiles.attach_active(
                passport.device_id, ProtocolVersion.AWG3, awg3_device_id
            )
            repo.complete_protocol_issuance_attempt(
                int(attempt["id"]), local_device_id=awg3_device_id
            )
        return settings, passport.device_id
    finally:
        conn.close()


def _database_dump(database_path: Path) -> str:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        return "\n".join(conn.iterdump())
    finally:
        conn.close()
