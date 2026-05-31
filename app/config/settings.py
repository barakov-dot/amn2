from functools import cached_property

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.vpn.amneziawg_v2.config import ClientConfigDefaults


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    telegram_bot_token: str = Field(alias="TELEGRAM_BOT_TOKEN")
    telegram_proxy_url: str = Field(default="", alias="TELEGRAM_PROXY_URL")
    app_secret_key: str = Field(alias="APP_SECRET_KEY")
    admin_telegram_ids: str = Field(default="", alias="ADMIN_TELEGRAM_IDS")
    access_mode: str = Field(default="free_test", alias="ACCESS_MODE")
    free_test_requires_approval: bool = Field(default=True, alias="FREE_TEST_REQUIRES_APPROVAL")
    default_plan_days: int = Field(default=7, alias="DEFAULT_PLAN_DAYS")
    max_devices_per_user: int = Field(default=5, alias="MAX_DEVICES_PER_USER")
    client_dns: str = Field(default="1.1.1.1", alias="CLIENT_DNS")
    client_allowed_ips: str = Field(default="0.0.0.0/0", alias="CLIENT_ALLOWED_IPS")
    client_persistent_keepalive: int = Field(
        default=25,
        alias="CLIENT_PERSISTENT_KEEPALIVE",
    )
    client_awg_jc: int = Field(default=4, alias="CLIENT_AWG_JC")
    client_awg_jmin: int = Field(default=40, alias="CLIENT_AWG_JMIN")
    client_awg_jmax: int = Field(default=70, alias="CLIENT_AWG_JMAX")
    client_awg_s1: int = Field(default=0, alias="CLIENT_AWG_S1")
    client_awg_s2: int = Field(default=0, alias="CLIENT_AWG_S2")
    client_awg_h1: int | str = Field(default=1, alias="CLIENT_AWG_H1")
    client_awg_h2: int | str = Field(default=2, alias="CLIENT_AWG_H2")
    client_awg_h3: int | str = Field(default=3, alias="CLIENT_AWG_H3")
    client_awg_h4: int | str = Field(default=4, alias="CLIENT_AWG_H4")
    expiration_notice_days: str = Field(default="7,5,3,1", alias="EXPIRATION_NOTICE_DAYS")
    vpn_port_min: int = Field(default=30001, alias="VPN_PORT_MIN")
    vpn_port_max: int = Field(default=65535, alias="VPN_PORT_MAX")
    vpn_server_runtime: str = Field(default="host_systemd", alias="VPN_SERVER_RUNTIME")
    default_vpn_network_cidr: str = Field(default="10.8.0.0/24", alias="DEFAULT_VPN_NETWORK_CIDR")
    database_path: str = Field(default="data/amneziya.sqlite3", alias="DATABASE_PATH")
    vps_ssh_password: str = Field(default="", alias="VPS_SSH_PASSWORD")
    vps_apply_enabled: bool = Field(default=False, alias="VPS_APPLY_ENABLED")
    server_config_path: str = Field(default="servers.yml", alias="SERVER_CONFIG_PATH")
    server_name: str = Field(default="debian-vps-1", alias="SERVER_NAME")
    control_panel_auth_methods: str = Field(
        default="telegram_admin,password,key",
        alias="CONTROL_PANEL_AUTH_METHODS",
    )
    control_panel_admin_username: str = Field(
        default="admin",
        alias="CONTROL_PANEL_ADMIN_USERNAME",
    )
    control_panel_password_hash: str = Field(
        default="",
        alias="CONTROL_PANEL_PASSWORD_HASH",
    )
    control_panel_public_key_path: str = Field(
        default="",
        alias="CONTROL_PANEL_PUBLIC_KEY_PATH",
    )
    web_admin_enabled: bool = Field(default=False, alias="WEB_ADMIN_ENABLED")
    web_admin_host: str = Field(default="0.0.0.0", alias="WEB_ADMIN_HOST")
    web_admin_port: int = Field(default=3030, alias="WEB_ADMIN_PORT")
    web_admin_username: str = Field(default="admin", alias="WEB_ADMIN_USERNAME")
    web_admin_password_hash: str = Field(default="", alias="WEB_ADMIN_PASSWORD_HASH")
    web_admin_session_secret: str = Field(default="", alias="WEB_ADMIN_SESSION_SECRET")
    web_admin_session_cookie_secure: bool = Field(
        default=True,
        alias="WEB_ADMIN_SESSION_COOKIE_SECURE",
    )
    app_log_enabled: bool = Field(default=True, alias="APP_LOG_ENABLED")
    app_log_level: str = Field(default="INFO", alias="APP_LOG_LEVEL")
    app_log_max_lines: int = Field(default=500, alias="APP_LOG_MAX_LINES")
    app_log_path: str = Field(default="logs/app.log", alias="APP_LOG_PATH")
    client_config_template_dir: str = Field(
        default="config_templates",
        alias="CLIENT_CONFIG_TEMPLATE_DIR",
    )
    email_delivery_enabled: bool = Field(default=False, alias="EMAIL_DELIVERY_ENABLED")
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_username: str = Field(default="", alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_from: str = Field(default="", alias="SMTP_FROM")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")
    email_require_verification: bool = Field(default=True, alias="EMAIL_REQUIRE_VERIFICATION")
    email_recovery_token_ttl_minutes: int = Field(
        default=30,
        alias="EMAIL_RECOVERY_TOKEN_TTL_MINUTES",
    )
    email_config_attachments_enabled: bool = Field(
        default=True,
        alias="EMAIL_CONFIG_ATTACHMENTS_ENABLED",
    )

    @field_validator("telegram_bot_token", "app_secret_key")
    @classmethod
    def require_non_blank_secret(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("required setting cannot be blank")
        return value

    @model_validator(mode="after")
    def validate_vpn_port_bounds(self) -> "Settings":
        if not 1 <= self.vpn_port_min <= 65535:
            raise ValueError("VPN_PORT_MIN must be in 1..65535")
        if not 1 <= self.vpn_port_max <= 65535:
            raise ValueError("VPN_PORT_MAX must be in 1..65535")
        if self.vpn_port_min > self.vpn_port_max:
            raise ValueError("VPN_PORT_MIN must be less than or equal to VPN_PORT_MAX")
        _validate_non_negative(
            {
                "CLIENT_PERSISTENT_KEEPALIVE": self.client_persistent_keepalive,
                "CLIENT_AWG_JC": self.client_awg_jc,
                "CLIENT_AWG_JMIN": self.client_awg_jmin,
                "CLIENT_AWG_JMAX": self.client_awg_jmax,
                "CLIENT_AWG_S1": self.client_awg_s1,
                "CLIENT_AWG_S2": self.client_awg_s2,
            }
        )
        _validate_awg_h_values(
            {
                "CLIENT_AWG_H1": self.client_awg_h1,
                "CLIENT_AWG_H2": self.client_awg_h2,
                "CLIENT_AWG_H3": self.client_awg_h3,
                "CLIENT_AWG_H4": self.client_awg_h4,
            }
        )
        if self.client_awg_jmin > self.client_awg_jmax:
            raise ValueError("CLIENT_AWG_JMIN must be less than or equal to CLIENT_AWG_JMAX")
        allowed_panel_auth_methods = {"telegram_admin", "password", "key"}
        unknown_methods = set(self.panel_auth_methods) - allowed_panel_auth_methods
        if unknown_methods:
            raise ValueError(
                "CONTROL_PANEL_AUTH_METHODS contains unsupported method(s): "
                + ", ".join(sorted(unknown_methods))
            )
        self.app_log_level = self.app_log_level.strip().upper()
        allowed_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR"}
        if self.app_log_level not in allowed_log_levels:
            raise ValueError("APP_LOG_LEVEL must be DEBUG, INFO, WARNING, or ERROR")
        if not 1 <= self.web_admin_port <= 65535:
            raise ValueError("WEB_ADMIN_PORT must be in 1..65535")
        if self.app_log_max_lines < 1:
            raise ValueError("APP_LOG_MAX_LINES must be positive")
        if self.web_admin_enabled:
            password_hash = self.web_admin_password_hash.strip()
            session_secret = self.web_admin_session_secret.strip()
            if not password_hash or password_hash.startswith("replace-with-"):
                raise ValueError(
                    "WEB_ADMIN_PASSWORD_HASH must be set when WEB_ADMIN_ENABLED=true"
                )
            if not session_secret or session_secret.startswith("replace-with-"):
                raise ValueError(
                    "WEB_ADMIN_SESSION_SECRET must be set when WEB_ADMIN_ENABLED=true"
                )
        if not 1 <= self.smtp_port <= 65535:
            raise ValueError("SMTP_PORT must be in 1..65535")
        if self.email_recovery_token_ttl_minutes < 1:
            raise ValueError("EMAIL_RECOVERY_TOKEN_TTL_MINUTES must be positive")
        if self.email_delivery_enabled and (
            not self.smtp_host.strip() or not self.smtp_from.strip()
        ):
            raise ValueError(
                "SMTP_HOST and SMTP_FROM are required when EMAIL_DELIVERY_ENABLED=true"
            )
        return self

    @cached_property
    def admin_ids(self) -> list[int]:
        if not self.admin_telegram_ids.strip():
            return []
        return [int(part.strip()) for part in self.admin_telegram_ids.split(",") if part.strip()]

    @cached_property
    def notice_days(self) -> list[int]:
        return [int(part.strip()) for part in self.expiration_notice_days.split(",") if part.strip()]

    @cached_property
    def panel_auth_methods(self) -> list[str]:
        return [
            part.strip()
            for part in self.control_panel_auth_methods.split(",")
            if part.strip()
        ]

    @cached_property
    def client_config_defaults(self) -> ClientConfigDefaults:
        return ClientConfigDefaults(
            dns=self.client_dns,
            allowed_ips=self.client_allowed_ips,
            persistent_keepalive=self.client_persistent_keepalive,
            jc=self.client_awg_jc,
            jmin=self.client_awg_jmin,
            jmax=self.client_awg_jmax,
            s1=self.client_awg_s1,
            s2=self.client_awg_s2,
            h1=self.client_awg_h1,
            h2=self.client_awg_h2,
            h3=self.client_awg_h3,
            h4=self.client_awg_h4,
        )


def _validate_non_negative(values: dict[str, int]) -> None:
    for name, value in values.items():
        if value < 0:
            raise ValueError(f"{name} must be non-negative")


def _validate_awg_h_values(values: dict[str, int | str]) -> None:
    for name, value in values.items():
        if isinstance(value, int):
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
            continue
        if not value.strip():
            raise ValueError(f"{name} must be non-blank")
