import hashlib
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.web.app import create_web_app
from app.web.auth import create_password_hash


SECRET = "web-email-secret-value-with-more-than-32-chars"


def test_email_verification_start_stores_hashed_token_and_public_verify_is_one_time(
    tmp_path: Path,
):
    sender = RecordingSender()
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1001,
        email="alice@example.com",
    )
    client = _authenticated_client(settings, sender)
    detail = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/email/verify/start",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    verify_body = _plain_body(sender.messages[0])
    token = _plain_token(verify_body, "One-time verification code:")
    expected_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert token
    assert "/email/verify?token=" not in verify_body
    with _repo(Path(settings.database_path)) as repo:
        row = _email_token_row(repo, purpose="verify_email")
        assert row["token_hash"] == expected_hash
        assert row["token_hash"] != token
        actions = repo.list_admin_actions_for_target_user(user_id)
        assert actions[0]["action"] == "web_email_verify_start"
        metadata = actions[0]["metadata_json"]
        assert token not in metadata
        assert SECRET not in metadata

    form = client.get("/email/verify")
    verify = client.post("/email/verify", data={"token": token})
    second_verify = client.post("/email/verify", data={"token": token})

    assert form.status_code == 200
    assert "Verification code" in form.text
    assert verify.status_code == 200
    assert "Email verified" in verify.text
    assert second_verify.status_code == 400
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        token_row = _email_token_row(repo, purpose="verify_email")
        assert user["email_verified_at"] is not None
        assert token_row["used_at"] is not None


def test_config_email_rejects_unverified_email_when_required(tmp_path: Path):
    sender = RecordingSender()
    settings = _settings(tmp_path, email_require_verification=True)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1001,
        email="alice@example.com",
    )
    device_id = _seed_device(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings, sender)
    detail = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/devices/{device_id}/email-config",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "Email is not verified" in response.text
    assert sender.messages == []


def test_config_email_rejects_unverified_email_even_when_legacy_flag_is_disabled(
    tmp_path: Path,
):
    sender = RecordingSender()
    settings = _settings(tmp_path, email_require_verification=False)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1001,
        email="alice@example.com",
    )
    device_id = _seed_device(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings, sender)
    detail = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/devices/{device_id}/email-config",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "Email is not verified" in response.text
    assert sender.messages == []


def test_verified_user_device_config_email_sends_without_exposing_encrypted_secrets(
    tmp_path: Path,
):
    sender = RecordingSender()
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1001,
        email="alice@example.com",
        email_verified_at="2026-05-29T10:00:00Z",
    )
    device_id = _seed_device(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings, sender)
    detail = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/devices/{device_id}/email-config",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "ENCRYPTED_PRIVATE_SHOULD_NOT_APPEAR" not in response.text
    assert "ENCRYPTED_PSK_SHOULD_NOT_APPEAR" not in response.text
    body = _plain_body(sender.messages[0])
    assert "vpn://" in body
    assert "ENCRYPTED_PRIVATE_SHOULD_NOT_APPEAR" not in body
    with _repo(Path(settings.database_path)) as repo:
        actions = repo.list_admin_actions_for_target_user(user_id)
        assert actions[0]["action"] == "web_email_config_send"
        metadata = actions[0]["metadata_json"]
        assert "ENCRYPTED_PRIVATE_SHOULD_NOT_APPEAR" not in metadata
        assert "private-phone" not in metadata
        assert "vpn://" not in metadata
        assert "psk-phone" not in metadata
        assert "PrivateKey" not in metadata
        assert "PresharedKey" not in metadata


def test_recovery_start_link_sends_config_to_verified_email_and_is_one_time(
    tmp_path: Path,
):
    sender = RecordingSender()
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1001,
        email="alice@example.com",
        email_verified_at="2026-05-29T10:00:00Z",
    )
    device_id = _seed_device(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings, sender)
    detail = client.get(f"/users/{user_id}")

    start = client.post(
        f"/users/{user_id}/devices/{device_id}/email-recovery/start",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert start.status_code == 303
    recovery_body = _plain_body(sender.messages[0])
    token = _plain_token(recovery_body, "One-time recovery code:")
    assert "/email/recover?token=" not in recovery_body
    with _repo(Path(settings.database_path)) as repo:
        row = _email_token_row(repo, purpose="recover_config")
        assert row["token_hash"] == hashlib.sha256(token.encode("utf-8")).hexdigest()
        assert row["device_id"] == device_id

    form = client.get("/email/recover")
    recover = client.post("/email/recover", data={"token": token})
    second_recover = client.post("/email/recover", data={"token": token})

    assert form.status_code == 200
    assert "Recovery code" in form.text
    assert recover.status_code == 200
    assert "Config recovery email sent" in recover.text
    assert second_recover.status_code == 400
    assert len(sender.messages) == 2
    config_body = _plain_body(sender.messages[1])
    assert "vpn://" in config_body
    assert "private-phone" not in config_body
    with _repo(Path(settings.database_path)) as repo:
        row = _email_token_row(repo, purpose="recover_config")
        assert row["used_at"] is not None
    with _repo(Path(settings.database_path)) as repo:
        actions = repo.list_admin_actions_for_target_user(user_id)
        serialized_actions = "\n".join(str(action["metadata_json"]) for action in actions)
        assert token not in serialized_actions
        assert "vpn://" not in serialized_actions
        assert "private-phone" not in serialized_actions
        assert "psk-phone" not in serialized_actions


def test_recovery_start_rejects_unverified_email(tmp_path: Path):
    sender = RecordingSender()
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1001,
        email="alice@example.com",
    )
    device_id = _seed_device(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings, sender)
    detail = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/devices/{device_id}/email-recovery/start",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "Email is not verified" in response.text
    assert sender.messages == []
    with _repo(Path(settings.database_path)) as repo:
        row = _email_token_row(repo, purpose="recover_config")
        assert row is None


def test_recovery_link_does_not_send_when_email_delivery_is_disabled(tmp_path: Path):
    sender = RecordingSender()
    enabled_settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(enabled_settings.database_path),
        telegram_id=1001,
        email="alice@example.com",
        email_verified_at="2026-05-29T10:00:00Z",
    )
    device_id = _seed_device(Path(enabled_settings.database_path), user_id=user_id)
    enabled_client = _authenticated_client(enabled_settings, sender)
    detail = enabled_client.get(f"/users/{user_id}")
    start = enabled_client.post(
        f"/users/{user_id}/devices/{device_id}/email-recovery/start",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )
    token = _plain_token(_plain_body(sender.messages[0]), "One-time recovery code:")

    disabled_settings = _settings(tmp_path, email_delivery_enabled=False)
    disabled_client = TestClient(
        create_web_app(disabled_settings, email_sender=sender),
        base_url="https://admin.example.com",
    )
    recover = disabled_client.post("/email/recover", data={"token": token})

    assert start.status_code == 303
    assert recover.status_code == 400
    assert "Email delivery is disabled" in recover.text
    assert len(sender.messages) == 1
    with _repo(Path(disabled_settings.database_path)) as repo:
        row = _email_token_row(repo, purpose="recover_config")
        assert row["used_at"] is None


class RecordingSender:
    def __init__(self):
        self.messages = []

    def __call__(self, to_address: str, message_bytes: bytes) -> None:
        self.messages.append(message_bytes)


def _settings(
    tmp_path: Path,
    *,
    email_require_verification: bool = True,
    email_delivery_enabled: bool = True,
) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key=SECRET,
        database_path=str(tmp_path / "amneziya.sqlite3"),
        admin_telegram_ids="9001",
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
        email_delivery_enabled=email_delivery_enabled,
        smtp_host="smtp.example.com",
        smtp_from="vpn@example.com",
        email_require_verification=email_require_verification,
        email_recovery_token_ttl_minutes=30,
        email_config_attachments_enabled=True,
    )


def _authenticated_client(settings: Settings, sender: RecordingSender) -> TestClient:
    client = TestClient(
        create_web_app(settings, email_sender=sender),
        base_url="https://admin.example.com",
    )
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


class _repo:
    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._conn = None

    def __enter__(self) -> Repository:
        self._conn = connect(self._database_path)
        initialize_schema(self._conn)
        return Repository(self._conn)

    def __exit__(self, *args) -> None:
        assert self._conn is not None
        self._conn.close()


def _seed_user(
    database_path: Path,
    *,
    telegram_id: int,
    email: str,
    email_verified_at: str | None = None,
) -> int:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        user_id = repo.upsert_user(
            telegram_id=telegram_id,
            username="alice",
            first_name="Alice",
            last_name=None,
        )
        conn.execute(
            "UPDATE users SET email = ?, email_verified_at = ? WHERE id = ?",
            (email, email_verified_at, user_id),
        )
        conn.commit()
        return user_id
    finally:
        conn.close()


def _seed_device(database_path: Path, *, user_id: int) -> int:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
        secret_box = SecretBox.from_app_secret(SECRET)
        return repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="phone",
            duration_days=30,
            vpn_ip="10.8.0.22",
            peer_public_key="peer-phone",
            peer_private_key_encrypted=secret_box.encrypt_text("private-phone"),
            preshared_key_encrypted=secret_box.encrypt_text("psk-phone"),
            config_version="amneziawg_v2",
        )
    finally:
        conn.close()


def _email_token_row(repo: Repository, *, purpose: str):
    return repo._conn.execute(
        "SELECT * FROM email_recovery_tokens WHERE purpose = ? ORDER BY id DESC LIMIT 1",
        (purpose,),
    ).fetchone()


def _plain_body(raw: bytes) -> str:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    return message.get_body(preferencelist=("plain",)).get_content()


def _plain_token(body: str, label: str) -> str:
    match = re.search(re.escape(label) + r"\s+([A-Za-z0-9_-]+)", body)
    assert match is not None
    return match.group(1)
