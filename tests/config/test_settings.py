import pytest
from pydantic import ValidationError

from app.config.settings import Settings


def test_settings_requires_app_secret_key_in_normal_mode():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            telegram_bot_token="CHANGE_ME",
            admin_telegram_ids="123",
            app_secret_key="",
        )


def test_settings_requires_telegram_bot_token():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            telegram_bot_token="",
            admin_telegram_ids="123",
            app_secret_key="test-secret",
        )


def test_settings_rejects_vpn_port_min_above_valid_range():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            telegram_bot_token="CHANGE_ME",
            app_secret_key="test-secret",
            vpn_port_min=70000,
        )


def test_settings_rejects_vpn_port_min_greater_than_max():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            telegram_bot_token="CHANGE_ME",
            app_secret_key="test-secret",
            vpn_port_min=40000,
            vpn_port_max=30000,
        )


def test_settings_parses_admin_ids_and_notice_days():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        admin_telegram_ids="123,456",
        app_secret_key="test-secret",
        expiration_notice_days="7,5,3,1",
    )

    assert settings.admin_ids == [123, 456]
    assert settings.notice_days == [7, 5, 3, 1]
    assert settings.default_vpn_network_cidr == "10.8.0.0/24"


def test_settings_parses_control_panel_auth_methods():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        admin_telegram_ids="123",
        app_secret_key="test-secret",
        control_panel_auth_methods="password,key",
        control_panel_admin_username="root-admin",
        control_panel_public_key_path="/etc/amneziya/admin.pub",
    )

    assert settings.panel_auth_methods == ["password", "key"]
    assert settings.control_panel_admin_username == "root-admin"
    assert settings.control_panel_public_key_path == "/etc/amneziya/admin.pub"


def test_settings_reads_vps_ssh_password_from_env_settings():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
        vps_ssh_password="secret-password",
    )

    assert settings.vps_ssh_password == "secret-password"


def test_settings_reads_vps_apply_settings():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
        vps_apply_enabled=True,
        server_config_path="server.yml",
        server_name="debian-vps-1",
    )

    assert settings.vps_apply_enabled is True
    assert settings.server_config_path == "server.yml"
    assert settings.server_name == "debian-vps-1"


def test_settings_reads_client_amneziawg_parameters():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
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

    defaults = settings.client_config_defaults

    assert defaults.dns == "9.9.9.9"
    assert defaults.allowed_ips == "10.0.0.0/8"
    assert defaults.persistent_keepalive == 15
    assert defaults.jc == 8
    assert defaults.jmin == 12
    assert defaults.jmax == 42
    assert defaults.s1 == 11
    assert defaults.s2 == 22
    assert defaults.h1 == 101
    assert defaults.h2 == 202
    assert defaults.h3 == 303
    assert defaults.h4 == 404


def test_settings_accepts_client_awg_h_range_values_from_amneziawg():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
        client_awg_h1="1622123045-2053868572",
        client_awg_h2="2065609453-2121973747",
        client_awg_h3="2144678566-2147363193",
        client_awg_h4="2147478675-2147482564",
    )

    defaults = settings.client_config_defaults

    assert defaults.h1 == "1622123045-2053868572"
    assert defaults.h2 == "2065609453-2121973747"
    assert defaults.h3 == "2144678566-2147363193"
    assert defaults.h4 == "2147478675-2147482564"


def test_settings_rejects_invalid_client_amneziawg_parameters():
    with pytest.raises(ValidationError, match="CLIENT_AWG_JMIN"):
        Settings(
            _env_file=None,
            telegram_bot_token="CHANGE_ME",
            app_secret_key="test-secret",
            client_awg_jmin=70,
            client_awg_jmax=40,
        )


def test_settings_reads_telegram_proxy_url():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
        telegram_proxy_url="socks5://127.0.0.1:1080",
    )

    assert settings.telegram_proxy_url == "socks5://127.0.0.1:1080"


def test_settings_reads_web_admin_and_logging_settings():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret",
        web_admin_enabled=True,
        web_admin_host="0.0.0.0",
        web_admin_port=3030,
        web_admin_username="admin",
        web_admin_password_hash="sha256$abc",
        web_admin_session_secret="session-secret-value-with-32-plus-chars",
        app_log_enabled=True,
        app_log_level="DEBUG",
        app_log_max_lines=250,
        app_log_path="logs/app.log",
        client_config_template_dir="config_templates",
        email_delivery_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=2525,
        smtp_username="smtp-user",
        smtp_password="smtp-password",
        smtp_from="admin@example.com",
        smtp_use_tls=False,
        email_require_verification=True,
        email_recovery_token_ttl_minutes=45,
        email_config_attachments_enabled=False,
    )

    assert settings.web_admin_enabled is True
    assert settings.web_admin_host == "0.0.0.0"
    assert settings.web_admin_port == 3030
    assert settings.web_admin_username == "admin"
    assert settings.web_admin_password_hash == "sha256$abc"
    assert settings.web_admin_session_secret.startswith("session-secret")
    assert settings.web_admin_session_cookie_secure is True
    assert settings.app_log_enabled is True
    assert settings.app_log_level == "DEBUG"
    assert settings.app_log_max_lines == 250
    assert settings.app_log_path == "logs/app.log"
    assert settings.client_config_template_dir == "config_templates"
    assert settings.email_delivery_enabled is True
    assert settings.smtp_host == "smtp.example.com"
    assert settings.smtp_port == 2525
    assert settings.smtp_username == "smtp-user"
    assert settings.smtp_password == "smtp-password"
    assert settings.smtp_from == "admin@example.com"
    assert settings.smtp_use_tls is False
    assert settings.email_require_verification is True
    assert settings.email_recovery_token_ttl_minutes == 45
    assert settings.email_config_attachments_enabled is False


def test_settings_defaults_web_admin_to_disabled():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret",
    )

    assert settings.web_admin_enabled is False


def test_settings_strips_and_normalizes_app_log_level():
    settings = Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret",
        app_log_level=" info ",
    )

    assert settings.app_log_level == "INFO"


def test_settings_rejects_invalid_app_log_level():
    with pytest.raises(ValidationError, match="APP_LOG_LEVEL"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            app_log_level="TRACE",
        )


@pytest.mark.parametrize("web_admin_port", [0, 65536])
def test_settings_rejects_web_admin_port_outside_valid_range(web_admin_port):
    with pytest.raises(ValidationError, match="WEB_ADMIN_PORT"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            web_admin_port=web_admin_port,
        )


def test_settings_rejects_non_positive_app_log_max_lines():
    with pytest.raises(ValidationError, match="APP_LOG_MAX_LINES"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            app_log_max_lines=0,
        )


@pytest.mark.parametrize("smtp_port", [0, 65536])
def test_settings_rejects_smtp_port_outside_valid_range(smtp_port):
    with pytest.raises(ValidationError, match="SMTP_PORT"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            smtp_port=smtp_port,
        )


def test_settings_rejects_non_positive_email_recovery_token_ttl():
    with pytest.raises(ValidationError, match="EMAIL_RECOVERY_TOKEN_TTL_MINUTES"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            email_recovery_token_ttl_minutes=0,
        )


def test_settings_requires_smtp_host_and_from_when_email_enabled():
    with pytest.raises(ValidationError, match="SMTP_HOST and SMTP_FROM"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            email_delivery_enabled=True,
            smtp_host="",
            smtp_from="",
        )


@pytest.mark.parametrize("password_hash", ["", "   ", "replace-with-password-hash"])
def test_settings_requires_web_admin_password_hash_when_enabled(password_hash):
    with pytest.raises(ValidationError, match="WEB_ADMIN_PASSWORD_HASH must be set"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            web_admin_enabled=True,
            web_admin_password_hash=password_hash,
            web_admin_session_secret="session-secret-value-with-32-plus-chars",
        )


@pytest.mark.parametrize(
    "session_secret",
    ["", "   ", "replace-with-generated-random-secret-32-plus-chars"],
)
def test_settings_requires_web_admin_session_secret_when_enabled(session_secret):
    with pytest.raises(ValidationError, match="WEB_ADMIN_SESSION_SECRET must be set"):
        Settings(
            _env_file=None,
            telegram_bot_token="TEST_TOKEN",
            app_secret_key="test-secret",
            web_admin_enabled=True,
            web_admin_password_hash="sha256$abc",
            web_admin_session_secret=session_secret,
        )


def test_settings_rejects_unknown_control_panel_auth_method():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            telegram_bot_token="CHANGE_ME",
            app_secret_key="test-secret",
            control_panel_auth_methods="password,magic",
        )
