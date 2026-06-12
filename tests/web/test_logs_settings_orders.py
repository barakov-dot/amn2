import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_read_log_tail_redacts_secrets_and_limits_depth(tmp_path: Path):
    log_path = tmp_path / "app.log"
    log_path.write_text(
        "\n".join(
            [
                "line 1",
                "TELEGRAM_BOT_TOKEN=123456:secret-token",
                "APP_SECRET_KEY=raw-secret",
                "PrivateKey = raw-private-key",
            ]
        ),
        encoding="utf-8",
    )

    lines = _read_log_tail(log_path, 2)

    assert len(lines) == 2
    assert lines == [
        "APP_SECRET_KEY=[REDACTED]",
        "PrivateKey = [REDACTED]",
    ]
    assert "raw-secret" not in "\n".join(lines)
    assert "raw-private-key" not in "\n".join(lines)


def test_read_log_tail_redacts_multiline_config_blocks(tmp_path: Path):
    log_path = tmp_path / "app.log"
    log_path.write_text(
        "\n".join(
            [
                "before",
                "[Interface]",
                "Address = 10.8.0.2/32",
                "PrivateKey = raw-private-key",
                "[Peer]",
                "PublicKey = raw-public-key",
                "Endpoint = vpn.example.test:30001",
                "AllowedIPs = 0.0.0.0/0",
                "",
                "after",
            ]
        ),
        encoding="utf-8",
    )

    lines = _read_log_tail(log_path, 20)
    text = "\n".join(lines)

    assert "[CONFIG REDACTED]" in text
    assert "[Interface]" not in text
    assert "10.8.0.2" not in text
    assert "raw-private-key" not in text
    assert "raw-public-key" not in text
    assert "vpn.example.test" not in text
    assert "0.0.0.0/0" not in text
    assert "before" in text
    assert "after" in text


def test_read_log_tail_handles_missing_files_and_invalid_max_lines(tmp_path: Path):
    missing_path = tmp_path / "missing.log"
    log_path = tmp_path / "app.log"
    log_path.write_text("first\nsecond\nthird\n", encoding="utf-8")

    assert _read_log_tail(missing_path, 50) == []
    assert _read_log_tail(log_path, 0) == []
    assert _read_log_tail(log_path, -5) == []
    assert _read_log_tail(log_path, "2") == ["second", "third"]
    assert _read_log_tail(log_path, "not-a-number") == []


def test_read_log_tail_caps_excessive_max_lines(tmp_path: Path):
    log_path = tmp_path / "app.log"
    log_path.write_text(
        "\n".join(f"line {index}" for index in range(1, 1204)),
        encoding="utf-8",
    )

    lines = _read_log_tail(log_path, 1_000_000)

    assert len(lines) == 1000
    assert lines[0] == "line 204"
    assert lines[-1] == "line 1203"


def test_orders_redirects_when_unauthenticated(tmp_path: Path):
    client = _client(settings=_settings(tmp_path))

    response = client.get("/orders", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_orders_lists_recent_joined_order_fields_when_authenticated(tmp_path: Path):
    settings = _settings(tmp_path)
    with _repo(Path(settings.database_path)) as repo:
        user_id = repo.upsert_user(
            telegram_id=4242,
            username="casey",
            first_name="Casey",
            last_name="Control",
        )
        server_id = repo.ensure_default_server(
            name="orders-vps",
            network_cidr="10.77.0.0/24",
        )
        device_id = repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="casey-phone",
            duration_days=7,
            vpn_ip="10.77.0.2",
            peer_public_key="casey-public",
            peer_private_key_encrypted="v1:private-secret",
            preshared_key_encrypted="v1:psk-secret",
            config_version="amneziawg_v2",
        )
        order_id = repo.create_order(
            user_id=user_id,
            plan_id=None,
            payment_mode="manual",
            requested_config_version="amneziawg_v1_5",
        )
        repo._conn.execute(
            "UPDATE orders SET status = ?, device_id = ? WHERE id = ?",
            ("fulfilled", device_id, order_id),
        )
        repo._conn.commit()
    client = _authenticated_client(settings)

    response = client.get("/orders")

    assert response.status_code == 200
    assert f"#{order_id}" in response.text
    assert "fulfilled" in response.text
    assert "manual" in response.text
    assert "amneziawg_v1_5" in response.text
    assert "4242" in response.text
    assert "casey" in response.text
    assert "casey-phone" not in response.text
    assert str(device_id) in response.text
    assert "v1:private-secret" not in response.text
    assert "v1:psk-secret" not in response.text


def test_logs_redirects_when_unauthenticated(tmp_path: Path):
    client = _client(settings=_settings(tmp_path))

    response = client.get("/logs", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_logs_show_redacted_tail_and_honor_max_lines(tmp_path: Path):
    log_path = tmp_path / "app.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-05-29 info boot",
                "TELEGRAM_BOT_TOKEN=super-secret-token",
                "SMTP_PASSWORD=smtp-secret",
                "2026-05-29 info ready",
            ]
        ),
        encoding="utf-8",
    )
    settings = _settings(tmp_path, app_log_path=log_path, app_log_max_lines=3)
    client = _authenticated_client(settings)

    response = client.get("/logs")

    assert response.status_code == 200
    assert "Логи приложения" in response.text
    assert str(log_path.parent) not in response.text
    assert log_path.name in response.text
    assert "2026-05-29 info boot" not in response.text
    assert "TELEGRAM_BOT_TOKEN=[REDACTED]" in response.text
    assert "SMTP_PASSWORD=[REDACTED]" in response.text
    assert "2026-05-29 info ready" in response.text
    assert "super-secret-token" not in response.text
    assert "smtp-secret" not in response.text


def test_logs_note_disabled_logging_without_showing_lines(tmp_path: Path):
    log_path = tmp_path / "app.log"
    log_path.write_text("APP_SECRET_KEY=still-secret\n", encoding="utf-8")
    settings = _settings(tmp_path, app_log_enabled=False, app_log_path=log_path)
    client = _authenticated_client(settings)

    response = client.get("/logs")

    assert response.status_code == 200
    assert "Логирование отключено" in response.text
    assert "APP_SECRET_KEY" not in response.text
    assert "still-secret" not in response.text


def test_settings_redirects_when_unauthenticated(tmp_path: Path):
    client = _client(settings=_settings(tmp_path))

    response = client.get("/settings", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_settings_redacts_secrets_and_shows_operational_values(tmp_path: Path):
    settings = _settings(
        tmp_path,
        telegram_bot_token="token-to-hide",
        app_secret_key="app-secret-to-hide",
        web_admin_session_secret="session-secret-to-hide" * 2,
        vps_ssh_password="ssh-secret-to-hide",
        smtp_password="smtp-secret-to-hide",
        app_log_level="DEBUG",
        email_delivery_enabled=True,
        smtp_host="smtp.example.test",
        smtp_from="admin@example.test",
    )
    client = _authenticated_client(settings)

    response = client.get("/settings")

    assert response.status_code == 200
    assert "Настройки" in response.text
    assert "ADMIN_TELEGRAM_IDS" in response.text
    assert "ACCESS_MODE" in response.text
    assert "DATABASE_PATH" in response.text
    assert "CONTROL_PANEL_AUTH_METHODS" in response.text
    assert "CLIENT_CONFIG_TEMPLATE_DIR" in response.text
    assert "WEB_ADMIN_PORT" in response.text
    assert "3030" in response.text
    assert "APP_LOG_LEVEL" in response.text
    assert "DEBUG" in response.text
    assert "EMAIL_DELIVERY_ENABLED" in response.text
    assert "True" in response.text
    assert "SMTP_HOST" in response.text
    assert "smtp.example.test" in response.text
    assert "TELEGRAM_BOT_TOKEN" in response.text
    assert "APP_SECRET_KEY" in response.text
    assert "WEB_ADMIN_PASSWORD_HASH" in response.text
    assert "WEB_ADMIN_SESSION_SECRET" in response.text
    assert "SMTP_PASSWORD" in response.text
    assert "VPS_SSH_PASSWORD" in response.text
    assert str(tmp_path) not in response.text
    assert "token-to-hide" not in response.text
    assert "app-secret-to-hide" not in response.text
    assert "session-secret-to-hide" not in response.text
    assert "ssh-secret-to-hide" not in response.text
    assert "smtp-secret-to-hide" not in response.text
    assert response.text.count("[REDACTED]") >= 6


def _read_log_tail(path: Path, max_lines):
    try:
        from app.web.logs import read_log_tail
    except ModuleNotFoundError as exc:
        raise AssertionError("app.web.logs.read_log_tail is missing") from exc
    return read_log_tail(path, max_lines)


def _settings(
    tmp_path: Path,
    *,
    telegram_bot_token: str = "TEST_TOKEN",
    app_secret_key: str = "test-secret",
    web_admin_session_secret: str = "s" * 32,
    app_log_enabled: bool = True,
    app_log_level: str = "INFO",
    app_log_max_lines: int = 500,
    app_log_path: Path | None = None,
    email_delivery_enabled: bool = False,
    smtp_host: str = "",
    smtp_from: str = "",
    smtp_password: str = "",
    vps_ssh_password: str = "",
) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token=telegram_bot_token,
        app_secret_key=app_secret_key,
        database_path=str(tmp_path / "amneziya.sqlite3"),
        vps_ssh_password=vps_ssh_password,
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret=web_admin_session_secret,
        web_admin_session_cookie_secure=True,
        app_log_enabled=app_log_enabled,
        app_log_level=app_log_level,
        app_log_max_lines=app_log_max_lines,
        app_log_path=str(app_log_path or (tmp_path / "app.log")),
        email_delivery_enabled=email_delivery_enabled,
        smtp_host=smtp_host,
        smtp_from=smtp_from,
        smtp_password=smtp_password,
    )


def _client(*, settings: Settings) -> TestClient:
    return TestClient(create_web_app(settings), base_url="https://testserver")


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
