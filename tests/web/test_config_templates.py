import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_config_templates_redirects_when_unauthenticated(tmp_path: Path):
    client = _client(settings=_settings(tmp_path))

    response = client.get("/config-templates", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_config_templates_page_lists_versions_placeholders_and_safe_preview(tmp_path: Path):
    template_dir = tmp_path / "client-templates"
    template_dir.mkdir()
    (template_dir / "amneziawg_v1_5.conf.tpl").write_text(
        "\n".join(
            [
                "[Interface]",
                "  PrivateKey: REAL_PRIVATE_KEY_SHOULD_NOT_APPEAR",
                "Address = {address}",
                "",
                "[Peer]",
                "  PresharedKey: REAL_PSK_SHOULD_NOT_APPEAR",
                "Endpoint = {endpoint}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    settings = _settings(
        tmp_path,
        app_secret_key="production-secret-should-not-appear",
        client_config_template_dir=str(template_dir),
    )
    client = _authenticated_client(settings)

    response = client.get("/config-templates")

    assert response.status_code == 200
    assert "Шаблоны конфигурации" in response.text
    assert "amneziawg_v1_5" in response.text
    assert "amneziawg_v2" in response.text
    assert "override" in response.text
    assert "default" in response.text
    assert "Секретные delivery artifacts" in response.text
    assert "Реальные .conf, QR и vpn:// payloads считаются секретами." in response.text
    assert "iOS DefaultVPN" in response.text
    assert "основной путь в РФ" in response.text
    assert "iOS AmneziaWG" in response.text
    assert "Android AmneziaWG" in response.text
    assert ".conf остается первым fallback" in response.text
    assert "{private_key}" in response.text
    assert "{preshared_key}" in response.text
    assert "vpn://" in response.text
    assert "PrivateKey: &lt;sample-secret&gt;" in response.text
    assert "PresharedKey: &lt;sample-secret&gt;" in response.text
    assert "production-secret-should-not-appear" not in response.text


def test_config_template_editor_saves_override_and_updates_preview(tmp_path: Path):
    template_dir = tmp_path / "client-templates"
    settings = _settings(tmp_path, client_config_template_dir=str(template_dir))
    client = _authenticated_client(settings)
    page = client.get("/config-templates")
    template_text = "\n".join(
        [
            "# edited from admin",
            "[Interface]",
            "PrivateKey = {private_key}",
            "Address = {address}",
            "DNS = 9.9.9.9",
            "Jc = {jc}",
            "Jmin = {jmin}",
            "Jmax = {jmax}",
            "S1 = {s1}",
            "S2 = {s2}",
            "H1 = {h1}",
            "H2 = {h2}",
            "H3 = {h3}",
            "H4 = {h4}",
            "",
            "[Peer]",
            "PublicKey = {server_public_key}",
            "PresharedKey = {preshared_key}",
            "Endpoint = {endpoint}",
            "AllowedIPs = {allowed_ips}",
            "PersistentKeepalive = {persistent_keepalive}",
        ]
    )

    response = client.post(
        "/config-templates/amneziawg_v2/save",
        data={
            "template_text": template_text,
            "csrf_token": _csrf_token(page.text),
        },
        follow_redirects=False,
    )
    saved = template_dir / "amneziawg_v2.conf.tpl"
    updated = client.get("/config-templates")

    assert response.status_code == 303
    assert response.headers["location"] == "/config-templates"
    assert saved.read_text(encoding="utf-8") == template_text + "\n"
    assert "# edited from admin" in updated.text
    assert "DNS = 9.9.9.9" in updated.text
    assert "override" in updated.text


def test_config_templates_preview_uses_client_config_settings(tmp_path: Path):
    settings = _settings(
        tmp_path,
        client_dns="9.9.9.9",
        client_allowed_ips="10.0.0.0/8",
        client_persistent_keepalive=15,
        client_awg_jc=8,
        client_awg_jmin=12,
        client_awg_jmax=42,
        client_awg_s1=11,
        client_awg_s2=22,
        client_awg_h1=101,
        client_awg_h2=202,
        client_awg_h3=303,
        client_awg_h4=404,
    )
    client = _authenticated_client(settings)

    response = client.get("/config-templates")

    assert response.status_code == 200
    assert "DNS = 9.9.9.9" in response.text
    assert "AllowedIPs = 10.0.0.0/8" in response.text
    assert "PersistentKeepalive = 15" in response.text
    assert "Jc = 8" in response.text
    assert "Jmin = 12" in response.text
    assert "Jmax = 42" in response.text
    assert "S1 = 11" in response.text
    assert "S2 = 22" in response.text
    assert "H1 = 101" in response.text
    assert "H2 = 202" in response.text
    assert "H3 = 303" in response.text
    assert "H4 = 404" in response.text


def test_config_template_editor_rejects_unknown_placeholder_without_overwrite(
    tmp_path: Path,
):
    template_dir = tmp_path / "client-templates"
    template_dir.mkdir()
    saved = template_dir / "amneziawg_v2.conf.tpl"
    saved.write_text("Address = {address}\n", encoding="utf-8")
    settings = _settings(tmp_path, client_config_template_dir=str(template_dir))
    client = _authenticated_client(settings)
    page = client.get("/config-templates")

    response = client.post(
        "/config-templates/amneziawg_v2/save",
        data={
            "template_text": "Address = {unknown}\n",
            "csrf_token": _csrf_token(page.text),
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "Unknown client config placeholder" in response.text
    assert saved.read_text(encoding="utf-8") == "Address = {address}\n"


def test_config_template_editor_resets_override_to_default(tmp_path: Path):
    template_dir = tmp_path / "client-templates"
    template_dir.mkdir()
    saved = template_dir / "amneziawg_v2.conf.tpl"
    saved.write_text("Address = {address}\n", encoding="utf-8")
    settings = _settings(tmp_path, client_config_template_dir=str(template_dir))
    client = _authenticated_client(settings)
    page = client.get("/config-templates")

    response = client.post(
        "/config-templates/amneziawg_v2/reset",
        data={"csrf_token": _csrf_token(page.text)},
        follow_redirects=False,
    )
    updated = client.get("/config-templates")

    assert response.status_code == 303
    assert response.headers["location"] == "/config-templates"
    assert not saved.exists()
    assert "default" in updated.text


def _settings(
    tmp_path: Path,
    *,
    app_secret_key: str = "test-secret",
    client_config_template_dir: str | None = None,
    **overrides,
) -> Settings:
    values = dict(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key=app_secret_key,
        database_path=str(tmp_path / "amneziya.sqlite3"),
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
        client_config_template_dir=client_config_template_dir or str(tmp_path / "templates"),
    )
    values.update(overrides)
    return Settings(**values)


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
