import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_dashboard_summary_cards_are_centered_two_line_counts(tmp_path: Path):
    settings = _settings(tmp_path)
    _seed_dashboard_data(Path(settings.database_path))
    client = _authenticated_client(settings)

    response = client.get("/")
    stylesheet = client.get("/static/admin.css")

    assert response.status_code == 200
    assert '<article class="metric-card metric-card-centered">' in response.text
    assert '<span class="metric-value">1</span>' in response.text
    assert '<span class="metric-label">пользователь</span>' in response.text
    assert '<span class="metric-label">сервер</span>' in response.text
    assert '<span class="metric-label">заявка</span>' in response.text
    assert '<span class="metric-label">устройство</span>' in response.text
    assert "1 пользователь" not in response.text
    assert "1 сервер" not in response.text
    assert "1 устройство" not in response.text
    assert ".metric-card-centered" in stylesheet.text
    assert "justify-content: center" in stylesheet.text
    assert "text-align: center" in stylesheet.text


def test_topbar_is_russian_first_and_uses_resource_brand(tmp_path: Path):
    client = _authenticated_client(_settings(tmp_path))

    response = client.get("/")

    assert response.status_code == 200
    assert "<title>Панель управления | AmneziyaDA</title>" in response.text
    assert 'class="brand" href="/">AmneziyaDA</a>' in response.text
    for label in [
        "Обзор",
        "Пользователи",
        "Серверы",
        "Интеграция",
        "О системе",
        "Токены",
        "Заявки",
        "Шаблоны",
        "Почта",
        "Логи",
        "Настройки",
    ]:
        assert label in response.text
    for old_label in [
        ">Servers<",
        ">Integration<",
        ">About<",
        ">Tokens<",
        ">Orders<",
        ">Email<",
        ">Logs<",
        ">Settings<",
        "Amneziya Admin",
    ]:
        assert old_label not in response.text


def test_operator_list_pages_show_gated_russian_write_affordances(tmp_path: Path):
    client = _authenticated_client(_settings(tmp_path))

    users = client.get("/users")
    servers = client.get("/servers")
    tokens = client.get("/api-tokens")
    templates = client.get("/config-templates")

    assert users.status_code == 200
    assert "Управление пользователями" in users.text
    assert "Все пользователи" in users.text
    assert "Отключенные устройства" in users.text
    assert "Новый пользователь" in users.text
    assert "Создание пользователя требует named gate" in users.text
    assert 'href="/users/new"' not in users.text
    assert "User management" not in users.text
    assert "New user" not in users.text
    assert "Disabled devices" not in users.text

    assert servers.status_code == 200
    assert "Управление серверами" in servers.text
    assert "Все серверы" in servers.text
    assert "Новый сервер" in servers.text
    assert "Создание сервера требует named gate" in servers.text
    assert 'href="/servers/new"' not in servers.text
    assert "Server management" not in servers.text
    assert "New server" not in servers.text

    assert tokens.status_code == 200
    assert "Токены API" in tokens.text
    assert "Выпуск токена требует named gate" in tokens.text
    assert "Выпустить токен" in tokens.text
    assert 'type="submit" disabled' in tokens.text
    assert "Issue token" not in tokens.text

    assert templates.status_code == 200
    assert "Шаблоны конфигурации" in templates.text
    assert "Редактирование шаблонов требует named gate" in templates.text
    assert "Сохранить шаблон" in templates.text
    assert "Сбросить к встроенному шаблону" in templates.text
    assert 'type="submit" disabled' in templates.text
    assert "Config templates" not in templates.text
    assert "Secret-bearing delivery artifacts" not in templates.text


def test_about_page_is_russian_first_operator_boundary(tmp_path: Path):
    client = _authenticated_client(_settings(tmp_path))

    response = client.get("/about")

    assert response.status_code == 200
    assert "О системе" in response.text
    assert "Статус сборки" in response.text
    assert "Приложение" in response.text
    assert "Среда выполнения" in response.text
    assert "Заблокировано здесь" in response.text
    assert "требуется отдельный gate" in response.text
    for old_label in [
        "Read-only build status",
        ">About<",
        ">Application<",
        ">Runtime<",
        ">Build status<",
        "separate gate required",
    ]:
        assert old_label not in response.text


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret",
        database_path=str(tmp_path / "amneziya.sqlite3"),
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
        client_config_template_dir=str(tmp_path / "templates"),
    )


def _authenticated_client(settings: Settings) -> TestClient:
    client = TestClient(create_web_app(settings), base_url="https://testserver")
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


def _seed_dashboard_data(database_path: Path) -> None:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        user_id = repo.upsert_user(
            telegram_id=1001,
            username="alice",
            first_name="Alice",
            last_name=None,
        )
        server_id = repo.ensure_default_server(
            name="debian-vps-1",
            network_cidr="10.8.0.0/24",
        )
        repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="phone",
            duration_days=7,
            peer_public_key="peer-public-key",
            peer_private_key_encrypted="v1:peer-private-key",
            preshared_key_encrypted="v1:peer-preshared-key",
            vpn_ip="10.8.0.2",
            config_version="amneziawg_v2",
        )
        repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    finally:
        conn.close()
