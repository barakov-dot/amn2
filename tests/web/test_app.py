import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_unauthenticated_dashboard_redirects_to_login(tmp_path: Path):
    client = _client(tmp_path)

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_login_success_shows_dashboard_with_repository_counts(tmp_path: Path):
    settings = _settings(tmp_path)
    _seed_dashboard_data(Path(settings.database_path))
    client = _client(settings=settings)
    login_page = client.get("/login")

    login_response = client.post(
        "/login",
        data={
            "username": "root",
            "password": "correct-password",
            "csrf_token": _csrf_token(login_page.text),
        },
        follow_redirects=False,
    )
    dashboard_response = client.get("/")

    assert login_response.status_code == 303
    assert login_response.headers["location"] == "/"
    assert dashboard_response.status_code == 200
    assert "Панель управления" in dashboard_response.text
    assert '<span class="metric-value">1</span>' in dashboard_response.text
    assert '<span class="metric-label">пользователь</span>' in dashboard_response.text
    assert '<span class="metric-label">сервер</span>' in dashboard_response.text
    assert '<span class="metric-label">заявка</span>' in dashboard_response.text
    assert "alice" in dashboard_response.text
    assert "debian-vps-1" in dashboard_response.text


def test_login_failure_does_not_authenticate(tmp_path: Path):
    client = _client(tmp_path)
    login_page = client.get("/login")

    login_response = client.post(
        "/login",
        data={
            "username": "root",
            "password": "wrong-password",
            "csrf_token": _csrf_token(login_page.text),
        },
    )
    dashboard_response = client.get("/", follow_redirects=False)

    assert login_response.status_code == 200
    assert "Неверное имя пользователя или пароль" in login_response.text
    assert dashboard_response.status_code == 303
    assert dashboard_response.headers["location"] == "/login"


def test_login_page_uses_root_relative_static_assets_for_reverse_proxy(tmp_path: Path):
    client = _client(
        settings=_settings(tmp_path, session_cookie_secure=False),
        base_url="http://pdf.smart-finance.ru",
    )

    response = client.get("/login")
    stylesheet = client.get("/static/admin.css")
    brand_image = client.get("/static/brand-full.jpg")

    assert 'href="/static/admin.css"' in response.text
    assert 'src="/static/brand-full.jpg"' in response.text
    assert 'class="login-visual"' in response.text
    assert 'url("/static/brand' not in stylesheet.text
    assert brand_image.status_code == 200
    assert brand_image.headers["content-type"] == "image/jpeg"
    assert "http://pdf.smart-finance.ru/static/admin.css" not in response.text
    assert "http://pdf.smart-finance.ru/static/brand" not in response.text
    assert "http://pdf.smart-finance.ru/static/brand" not in stylesheet.text


def test_dashboard_uses_full_brand_image_without_cropping(tmp_path: Path):
    client = _client(tmp_path)
    login_page = client.get("/login")
    client.post(
        "/login",
        data={
            "username": "root",
            "password": "correct-password",
            "csrf_token": _csrf_token(login_page.text),
        },
    )

    response = client.get("/")

    assert '<figure class="brand-masthead">' in response.text
    assert 'src="/static/brand-full.jpg"' in response.text
    assert 'width="1180" height="792"' in response.text


def test_login_rejects_missing_csrf_token(tmp_path: Path):
    client = _client(tmp_path)
    client.get("/login")

    response = client.post(
        "/login",
        data={"username": "root", "password": "correct-password"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_logout_clears_session(tmp_path: Path):
    client = _client(tmp_path)
    login_page = client.get("/login")
    client.post(
        "/login",
        data={
            "username": "root",
            "password": "correct-password",
            "csrf_token": _csrf_token(login_page.text),
        },
    )
    dashboard_page = client.get("/")

    logout_response = client.post(
        "/logout",
        data={"csrf_token": _csrf_token(dashboard_page.text)},
        follow_redirects=False,
    )
    dashboard_response = client.get("/", follow_redirects=False)

    assert logout_response.status_code == 303
    assert logout_response.headers["location"] == "/login"
    assert dashboard_response.status_code == 303
    assert dashboard_response.headers["location"] == "/login"


def test_logout_rejects_invalid_csrf_token(tmp_path: Path):
    client = _client(tmp_path)
    login_page = client.get("/login")
    client.post(
        "/login",
        data={
            "username": "root",
            "password": "correct-password",
            "csrf_token": _csrf_token(login_page.text),
        },
    )

    response = client.post(
        "/logout",
        data={"csrf_token": "wrong"},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert client.get("/").status_code == 200


def test_session_cookie_is_secure_by_default(tmp_path: Path):
    client = _client(tmp_path)

    response = client.get("/login")

    assert "secure" in response.headers["set-cookie"].lower()
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=lax" in response.headers["set-cookie"].lower()


def test_session_cookie_secure_flag_can_be_disabled_for_plain_http(tmp_path: Path):
    client = _client(
        settings=_settings(tmp_path, session_cookie_secure=False),
        base_url="http://testserver",
    )

    response = client.get("/login")

    assert "secure" not in response.headers["set-cookie"].lower()


@pytest.mark.parametrize(
    ("password_hash", "session_secret", "message"),
    [
        ("", "s" * 32, "WEB_ADMIN_PASSWORD_HASH"),
        ("not-a-valid-hash", "s" * 32, "WEB_ADMIN_PASSWORD_HASH"),
        (create_password_hash("correct-password"), "short", "WEB_ADMIN_SESSION_SECRET"),
    ],
)
def test_create_web_app_rejects_invalid_web_admin_config(
    tmp_path: Path,
    password_hash: str,
    session_secret: str,
    message: str,
):
    with pytest.raises(ValueError, match=re.escape(message)):
        create_web_app(
            _settings(
                tmp_path,
                password_hash=password_hash,
                session_secret=session_secret,
            )
        )


def _settings(
    tmp_path: Path,
    *,
    password_hash: str | None = None,
    session_secret: str = "s" * 32,
    session_cookie_secure: bool = True,
) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret",
        database_path=str(tmp_path / "amneziya.sqlite3"),
        web_admin_username="root",
        web_admin_password_hash=(
            create_password_hash("correct-password", salt="test-salt")
            if password_hash is None
            else password_hash
        ),
        web_admin_session_secret=session_secret,
        web_admin_session_cookie_secure=session_cookie_secure,
    )


def _client(
    tmp_path: Path | None = None,
    *,
    settings: Settings | None = None,
    base_url: str = "https://testserver",
) -> TestClient:
    actual_settings = settings or _settings(tmp_path or Path("."))
    return TestClient(create_web_app(actual_settings), base_url=base_url)


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
        repo.ensure_default_server(name="debian-vps-1", network_cidr="10.8.0.0/24")
        repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    finally:
        conn.close()
