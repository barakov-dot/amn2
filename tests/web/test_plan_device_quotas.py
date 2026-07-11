import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_plan_quota_page_redirects_when_unauthenticated(tmp_path: Path):
    response = _client(_settings(tmp_path)).get("/plans", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_plan_quota_page_lists_global_and_effective_limits(tmp_path: Path):
    settings = _settings(tmp_path, max_devices_per_user=8)
    _seed_plan(settings, plan_id="family", max_devices=6)
    _seed_plan(settings, plan_id="solo", max_devices=None)
    client = _authenticated_client(settings)

    response = client.get("/plans")

    assert response.status_code == 200
    assert "Тарифы" in response.text
    assert "Глобальный предел: 8" in response.text
    assert 'action="/plans/family/device-quota"' in response.text
    assert 'value="6"' in response.text
    assert 'action="/plans/solo/device-quota"' in response.text
    assert "Настроено: 1" in response.text


def test_plan_quota_update_persists_and_records_audit(tmp_path: Path):
    settings = _settings(tmp_path, max_devices_per_user=8, admin_telegram_ids="9001")
    _seed_plan(settings, plan_id="family", max_devices=None)
    client = _authenticated_client(settings)
    page = client.get("/plans")

    response = client.post(
        "/plans/family/device-quota",
        data={"max_devices": "6", "csrf_token": _csrf_token(page.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/plans"
    plan, action = _load_plan_and_last_action(settings, "family")
    assert plan["max_devices"] == 6
    assert action["admin_telegram_id"] == 9001
    assert action["action"] == "web_plan_device_quota_update"
    metadata = json.loads(action["metadata_json"])
    assert metadata["previous_max_devices"] is None
    assert metadata["max_devices"] == 6
    assert metadata["effective_max_devices"] == 6
    assert metadata["plan_id"] == "family"


def test_plan_quota_blank_clears_to_global_fallback(tmp_path: Path):
    settings = _settings(tmp_path, max_devices_per_user=8)
    _seed_plan(settings, plan_id="family", max_devices=6)
    client = _authenticated_client(settings)
    page = client.get("/plans")

    response = client.post(
        "/plans/family/device-quota",
        data={"max_devices": "", "csrf_token": _csrf_token(page.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    plan, action = _load_plan_and_last_action(settings, "family")
    assert plan["max_devices"] is None
    metadata = json.loads(action["metadata_json"])
    assert metadata["previous_max_devices"] == 6
    assert metadata["max_devices"] is None
    assert metadata["effective_max_devices"] == 8


def test_plan_quota_rejects_non_positive_value_without_mutation(tmp_path: Path):
    settings = _settings(tmp_path)
    _seed_plan(settings, plan_id="family", max_devices=6)
    client = _authenticated_client(settings)
    page = client.get("/plans")

    response = client.post(
        "/plans/family/device-quota",
        data={"max_devices": "0", "csrf_token": _csrf_token(page.text)},
    )

    assert response.status_code == 400
    assert "positive integer or empty" in response.text
    plan, action = _load_plan_and_last_action(settings, "family")
    assert plan["max_devices"] == 6
    assert action is None


def test_plan_quota_rejects_invalid_csrf_without_mutation(tmp_path: Path):
    settings = _settings(tmp_path)
    _seed_plan(settings, plan_id="family", max_devices=6)
    client = _authenticated_client(settings)

    response = client.post(
        "/plans/family/device-quota",
        data={"max_devices": "4", "csrf_token": "wrong"},
    )

    assert response.status_code == 403
    plan, action = _load_plan_and_last_action(settings, "family")
    assert plan["max_devices"] == 6
    assert action is None


def _settings(
    tmp_path: Path,
    *,
    max_devices_per_user: int = 5,
    admin_telegram_ids: str = "",
) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret",
        database_path=str(tmp_path / "amneziya.sqlite3"),
        max_devices_per_user=max_devices_per_user,
        admin_telegram_ids=admin_telegram_ids,
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password", salt="test-salt"
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=False,
    )


def _client(settings: Settings) -> TestClient:
    return TestClient(create_web_app(settings), base_url="http://testserver")


def _authenticated_client(settings: Settings) -> TestClient:
    client = _client(settings)
    login = client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": "root",
            "password": "correct-password",
            "csrf_token": _csrf_token(login.text),
        },
    )
    assert response.status_code == 200
    return client


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _seed_plan(settings: Settings, *, plan_id: str, max_devices: int | None) -> None:
    conn = connect(settings.database_path)
    try:
        initialize_schema(conn)
        Repository(conn).upsert_plan(
            plan_id=plan_id,
            name=plan_id.title(),
            duration_days=30,
            max_devices=max_devices,
        )
    finally:
        conn.close()


def _load_plan_and_last_action(settings: Settings, plan_id: str):
    conn = connect(settings.database_path)
    try:
        initialize_schema(conn)
        plan = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        action = conn.execute(
            "SELECT * FROM admin_actions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return plan, action
    finally:
        conn.close()
