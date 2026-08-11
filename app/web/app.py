from __future__ import annotations

import json
import sqlite3
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI
from fastapi import Form
from fastapi import Request
from fastapi.responses import PlainTextResponse
from fastapi.responses import RedirectResponse
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

from app.config.settings import Settings
from app.bot.delivery import CONFIG_READY_TEMPLATE_KEY, DEFAULT_CONFIG_READY_TEMPLATE
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.repositories import SERVER_STATUSES
from app.db.repositories import USER_STATUSES
from app.db.repositories import user_display_label
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.security.redaction import redact
from app.server.peer_apply import PeerApplyError
from app.server.peer_apply import ServerConfigPeerApplier
from app.server.ssh import SystemSshClient
from app.server.ssh import SshClient
from app.server_config.loader import ConfigError
from app.server_config.loader import load_server_config
from app.server_config.loader import select_server
from app.services.access import RemoteOperationPartialFailure
from app.services.config_material import ConfigMaterialUnavailable
from app.services.config_delivery import build_device_config_delivery
from app.services.device_revoke import (
    cascade_revoke_physical_device,
    cascade_revoke_protocol_config,
)
from app.services.protocol_config_lifecycle import ProtocolConfigLifecycleService
from app.services.protocol_issuance_barrier import ProtocolIssuanceBarrierService
from app.config_assignment import (
    CONFIG_ASSIGNMENT_MODES,
    DEDICATED_DEVICE,
)
from app.services.email_delivery import EmailDeliveryService
from app.services.email_delivery import EmailSender
from app.services.email_delivery import build_smtp_sender
from app.services.api_tokens import API_TOKEN_FIRST_SLICE_SCOPES
from app.services.api_tokens import API_TOKEN_INTEGRATION_KINDS
from app.services.api_tokens import API_TOKEN_PRODUCTION_MAX_TTL_DAYS
from app.services.api_tokens import API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS
from app.services.api_tokens import ApiTokenRecord
from app.services.api_tokens import create_integration_api_token
from app.services.api_tokens import revoke_api_token
from app.services.api_tokens import rotate_api_token
from app.services.build_status import build_about_status
from app.services.email_tokens import create_email_token
from app.services.email_tokens import hash_email_token
from app.services.email_tokens import utc_now_iso
from app.services.integration_status import build_integration_status
from app.services.drift_diagnostics import DriftDiagnosticsService
from app.services.peer_inventory import AwgDumpPeerInventoryCollector
from app.services.peer_inventory import PeerInventoryService
from app.web.auth import check_password
from app.web.auth import generate_csrf_token
from app.web.auth import require_web_admin_config
from app.web.auth import verify_csrf_token
from app.web.device_passports import (
    build_device_passport_detail_view,
    build_device_passport_list_view,
)
from app.web.logs import read_log_tail
from app.web.server_health import HealthSummary
from app.web.server_health import run_server_health_check
from app.vpn.amneziawg_v2.config import ClientConfigInput
from app.vpn.config_templates import (
    AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS,
    ConfigTemplateError,
    SUPPORTED_CLIENT_CONFIG_VERSIONS,
    build_vpn_import_link,
    client_config_template_source,
    load_client_config_template,
    render_client_config_template,
    reset_client_config_template_override,
    save_client_config_template_override,
)


BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
SESSION_AUTH_KEY = "web_admin_authenticated"
SECRET_CONFIG_LINE_RE = re.compile(
    r"^(\s*(?:PrivateKey|PresharedKey)\s*[:=]\s*).+$",
    re.IGNORECASE | re.MULTILINE,
)

templates = Jinja2Templates(directory=TEMPLATE_DIR)

SETTINGS_SECTIONS = {
    "Core": [
        "telegram_bot_token",
        "telegram_proxy_url",
        "app_secret_key",
        "admin_telegram_ids",
        "access_mode",
        "free_test_requires_approval",
        "default_plan_days",
        "max_devices_per_user",
        "expiration_notice_days",
        "database_path",
    ],
    "Web admin": [
        "web_admin_enabled",
        "web_admin_host",
        "web_admin_port",
        "web_admin_username",
        "web_admin_password_hash",
        "web_admin_session_secret",
        "web_admin_session_cookie_secure",
    ],
    "Logging": [
        "app_log_enabled",
        "app_log_level",
        "app_log_max_lines",
        "app_log_path",
    ],
    "Email": [
        "email_delivery_enabled",
        "smtp_host",
        "smtp_port",
        "smtp_username",
        "smtp_password",
        "smtp_from",
        "smtp_use_tls",
        "email_require_verification",
        "email_recovery_token_ttl_minutes",
        "email_config_attachments_enabled",
    ],
    "VPS": [
        "vps_apply_enabled",
        "operator_device_create_enabled",
        "vps_ssh_password",
        "server_config_path",
        "server_name",
        "vpn_port_min",
        "vpn_port_max",
        "vpn_server_runtime",
        "default_vpn_network_cidr",
        "client_config_template_dir",
        "client_dns",
        "client_allowed_ips",
        "client_persistent_keepalive",
        "client_awg_jc",
        "client_awg_jmin",
        "client_awg_jmax",
        "client_awg_s1",
        "client_awg_s2",
        "client_awg_s3",
        "client_awg_s4",
        "client_awg_h1",
        "client_awg_h2",
        "client_awg_h3",
        "client_awg_h4",
        "client_awg_i1",
        "client_awg_i2",
        "client_awg_i3",
        "client_awg_i4",
        "client_awg_i5",
    ],
    "Control panel": [
        "control_panel_auth_methods",
        "control_panel_admin_username",
        "control_panel_password_hash",
        "control_panel_public_key_path",
    ],
}

PATH_SETTING_FIELDS = {
    "app_log_path",
    "control_panel_public_key_path",
    "database_path",
    "server_config_path",
    "client_config_template_dir",
}

API_READINESS_ALLOWED_SCOPES = tuple(sorted(API_TOKEN_FIRST_SLICE_SCOPES))
API_TOKEN_MAX_TTL_DAYS = API_TOKEN_PRODUCTION_MAX_TTL_DAYS
API_TOKEN_INTEGRATION_KIND_OPTIONS = tuple(sorted(API_TOKEN_INTEGRATION_KINDS))


def create_web_app(
    settings: Settings | None = None,
    *,
    email_sender: EmailSender | None = None,
    operator_command_client: SshClient | None = None,
    operator_config_artifact_writer: Callable[[Path, str], Path] | None = None,
) -> FastAPI:
    actual_settings = settings or Settings()
    require_web_admin_config(
        password_hash=actual_settings.web_admin_password_hash,
        session_secret=actual_settings.web_admin_session_secret,
    )

    app = FastAPI(title="Amneziya Web Admin")
    app.state.settings = actual_settings
    app.state.email_sender = email_sender or build_smtp_sender(
        host=actual_settings.smtp_host,
        port=actual_settings.smtp_port,
        username=actual_settings.smtp_username,
        password=actual_settings.smtp_password,
        use_tls=actual_settings.smtp_use_tls,
    )
    app.state.operator_command_client = operator_command_client
    app.state.operator_config_artifact_writer = operator_config_artifact_writer
    app.add_middleware(
        SessionMiddleware,
        secret_key=actual_settings.web_admin_session_secret,
        same_site="lax",
        https_only=actual_settings.web_admin_session_cookie_secure,
    )
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/login")
    async def login_form(request: Request):
        if _is_authenticated(request):
            return RedirectResponse("/", status_code=303)
        return templates.TemplateResponse(
            request,
            "login.html",
            _template_context(
                request,
                title="Вход",
                error=None,
                username="",
                authenticated=False,
            ),
        )

    @app.post("/login")
    async def login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        csrf_token: str = Form(""),
    ):
        if not verify_csrf_token(request.session, csrf_token):
            request.session.pop(SESSION_AUTH_KEY, None)
            request.session.pop("web_admin_username", None)
            return templates.TemplateResponse(
                request,
                "login.html",
                _template_context(
                    request,
                    title="Вход",
                    error="Сессия формы устарела. Обновите страницу и попробуйте снова.",
                    username=username,
                    authenticated=False,
                ),
                status_code=400,
            )

        if username == actual_settings.web_admin_username and check_password(
            password,
            actual_settings.web_admin_password_hash,
        ):
            request.session[SESSION_AUTH_KEY] = True
            request.session["web_admin_username"] = actual_settings.web_admin_username
            return RedirectResponse("/", status_code=303)

        request.session.pop(SESSION_AUTH_KEY, None)
        request.session.pop("web_admin_username", None)
        return templates.TemplateResponse(
            request,
            "login.html",
            _template_context(
                request,
                title="Вход",
                error="Неверное имя пользователя или пароль",
                username=username,
                authenticated=False,
            ),
            status_code=200,
        )

    @app.get("/")
    async def dashboard(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        dashboard_data = _load_dashboard(actual_settings)
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            _template_context(
                request,
                title="Панель управления",
                authenticated=True,
                **dashboard_data,
            ),
        )

    @app.get("/orders")
    async def orders_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        orders = _load_orders(actual_settings)
        return templates.TemplateResponse(
            request,
            "orders.html",
            _template_context(
                request,
                title="Заявки",
                authenticated=True,
                orders=orders,
            ),
        )

    @app.get("/plans")
    async def plans_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        return templates.TemplateResponse(
            request,
            "plans.html",
            _template_context(
                request,
                title="Тарифы",
                authenticated=True,
                **_load_plans(actual_settings),
            ),
        )

    @app.post("/plans/{plan_id}/device-quota")
    async def update_plan_device_quota(
        request: Request,
        plan_id: str,
        max_devices: str = Form(""),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            normalized_quota = _optional_positive_int(max_devices, "max_devices")
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    plan = repo.get_plan(plan_id)
                    previous_quota = plan["max_devices"]
                    repo.set_plan_device_quota(plan_id, normalized_quota)
                    _record_web_plan_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_plan_device_quota_update",
                        plan_id=plan_id,
                        metadata={
                            "previous_max_devices": previous_quota,
                            "max_devices": normalized_quota,
                            "global_max_devices_per_user": (
                                actual_settings.max_devices_per_user
                            ),
                            "effective_max_devices": min(
                                actual_settings.max_devices_per_user,
                                normalized_quota,
                            ) if normalized_quota is not None else (
                                actual_settings.max_devices_per_user
                            ),
                        },
                    )
        except (LookupError, ValueError) as exc:
            return _plain_error_response(exc)

        return RedirectResponse("/plans", status_code=303)

    @app.get("/logs")
    async def logs_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        log_lines = []
        if actual_settings.app_log_enabled:
            log_lines = read_log_tail(
                actual_settings.app_log_path,
                actual_settings.app_log_max_lines,
            )
        return templates.TemplateResponse(
            request,
            "logs.html",
            _template_context(
                request,
                title="Логи приложения",
                authenticated=True,
                log_enabled=actual_settings.app_log_enabled,
                log_level=actual_settings.app_log_level,
                log_path=_display_setting_value(
                    "APP_LOG_PATH",
                    actual_settings.app_log_path,
                    is_path=True,
                ),
                log_max_lines=actual_settings.app_log_max_lines,
                log_lines=log_lines,
            ),
        )

    @app.get("/settings")
    async def settings_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        return templates.TemplateResponse(
            request,
            "settings.html",
            _template_context(
                request,
                title="Настройки",
                authenticated=True,
                settings_sections=_load_settings_sections(actual_settings),
            ),
        )

    @app.get("/config-templates")
    async def config_templates_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        return templates.TemplateResponse(
            request,
            "config_templates.html",
            _template_context(
                request,
                title="Шаблоны конфигурации",
                authenticated=True,
                template_dir_name=_display_setting_value(
                    "CLIENT_CONFIG_TEMPLATE_DIR",
                    actual_settings.client_config_template_dir,
                    is_path=True,
                ),
                config_templates=_load_client_config_template_views(actual_settings),
                config_placeholders=[
                    f"{{{name}}}" for name in AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS
                ],
                delivery_template={
                    "key": CONFIG_READY_TEMPLATE_KEY,
                    "placeholders": _delivery_template_placeholders(),
                    "preview": DEFAULT_CONFIG_READY_TEMPLATE,
                },
            ),
        )

    @app.get("/api-readiness")
    async def api_readiness_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        readiness = _load_api_readiness(actual_settings)
        return templates.TemplateResponse(
            request,
            "api_readiness.html",
            _template_context(
                request,
                title="API readiness",
                authenticated=True,
                **readiness,
            ),
        )

    @app.get("/integration-status")
    async def integration_status_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        with _open_repository(actual_settings) as (repo, _conn):
            report = build_integration_status(repo)
        return templates.TemplateResponse(
            request,
            "integration_status.html",
            _template_context(
                request,
                title="Integration status",
                authenticated=True,
                report=report,
            ),
        )

    @app.get("/about")
    async def about_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        return templates.TemplateResponse(
            request,
            "about.html",
            _template_context(
                request,
                title="О системе",
                authenticated=True,
                about=build_about_status(),
            ),
        )

    @app.get("/api-tokens")
    async def api_tokens_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        return templates.TemplateResponse(
            request,
            "api_tokens.html",
            _template_context(
                request,
                title="Токены API",
                authenticated=True,
                allowed_scopes=API_READINESS_ALLOWED_SCOPES,
                integration_kinds=API_TOKEN_INTEGRATION_KIND_OPTIONS,
                max_ttl_days=API_TOKEN_MAX_TTL_DAYS,
                tokens=_load_api_tokens(actual_settings),
                issue_form=_api_token_issue_form(),
                issued_token=None,
                issued_raw_token=None,
            ),
        )

    @app.post("/api-tokens/issue")
    async def issue_api_token(
        request: Request,
        name: str = Form(...),
        owner_label: str = Form(...),
        integration_kind: str = Form(...),
        purpose: str = Form(...),
        scope: list[str] = Form(default=[]),
        expires_days: int = Form(...),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        form = _api_token_issue_form(
            name=name,
            owner_label=owner_label,
            integration_kind=integration_kind,
            purpose=purpose,
            scopes=scope,
            expires_days=expires_days,
        )
        try:
            expires_at = _api_token_expiry(expires_days)
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    issue = create_integration_api_token(
                        repo,
                        name=name.strip(),
                        owner_label=owner_label.strip(),
                        integration_kind=integration_kind,
                        purpose=purpose,
                        scopes=set(scope),
                        expires_at=expires_at,
                    )
                    _record_web_api_token_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_api_token_issue",
                        metadata=issue.safe_metadata(),
                    )
            tokens = _load_api_tokens(actual_settings)
        except (ValueError, sqlite3.IntegrityError) as exc:
            return _plain_error_response(exc)

        return templates.TemplateResponse(
            request,
            "api_tokens.html",
            _template_context(
                request,
                title="Токены API",
                authenticated=True,
                allowed_scopes=API_READINESS_ALLOWED_SCOPES,
                integration_kinds=API_TOKEN_INTEGRATION_KIND_OPTIONS,
                max_ttl_days=API_TOKEN_MAX_TTL_DAYS,
                tokens=tokens,
                issue_form=form,
                issued_token=issue.safe_metadata(),
                issued_raw_token=issue.raw_token,
            ),
        )

    @app.post("/api-tokens/{token_id}/rotate")
    async def rotate_api_token_from_web(
        request: Request,
        token_id: str,
        expires_days: int = Form(...),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            rotated_at = datetime.now(timezone.utc)
            expires_at = _api_token_expiry(expires_days, now=rotated_at)
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    row = repo.get_api_token_for_admin(token_id.strip())
                    if row is None or row["revoked_at"] is not None:
                        raise ValueError("active API token is required for rotation")
                    rotation = rotate_api_token(
                        repo,
                        _api_token_record_from_row(row),
                        expires_at=expires_at,
                        rotated_at=rotated_at,
                    )
                    _record_web_api_token_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_api_token_rotate",
                        metadata=rotation.safe_metadata(),
                    )
            tokens = _load_api_tokens(actual_settings)
        except (ValueError, sqlite3.IntegrityError) as exc:
            return _plain_error_response(exc)

        return templates.TemplateResponse(
            request,
            "api_tokens.html",
            _template_context(
                request,
                title="Интеграции API",
                authenticated=True,
                allowed_scopes=API_READINESS_ALLOWED_SCOPES,
                integration_kinds=API_TOKEN_INTEGRATION_KIND_OPTIONS,
                max_ttl_days=API_TOKEN_MAX_TTL_DAYS,
                tokens=tokens,
                issue_form=_api_token_issue_form(),
                issued_token=rotation.issue.safe_metadata(),
                issued_raw_token=rotation.issue.raw_token,
            ),
        )

    @app.post("/api-tokens/{token_id}/revoke")
    async def revoke_api_token_from_web(
        request: Request,
        token_id: str,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    event = revoke_api_token(
                        repo,
                        token_id=token_id.strip(),
                        revoked_at=datetime.now(timezone.utc),
                        reason="web-admin-revoke",
                    )
                    _record_web_api_token_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_api_token_revoke",
                        metadata=event.safe_metadata(),
                    )
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse("/api-tokens", status_code=303)

    @app.post("/config-templates/{config_version}/save")
    async def save_config_template(
        request: Request,
        config_version: str,
        template_text: str = Form(...),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)
        try:
            save_client_config_template_override(
                config_version,
                template_text,
                actual_settings.client_config_template_dir,
            )
        except ConfigTemplateError as exc:
            return _plain_error_response(exc)
        return RedirectResponse("/config-templates", status_code=303)

    @app.post("/config-templates/{config_version}/reset")
    async def reset_config_template(
        request: Request,
        config_version: str,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)
        try:
            reset_client_config_template_override(
                config_version,
                actual_settings.client_config_template_dir,
            )
        except ConfigTemplateError as exc:
            return _plain_error_response(exc)
        return RedirectResponse("/config-templates", status_code=303)

    @app.get("/device-passports")
    async def device_passports_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        try:
            with _open_repository(actual_settings) as (repo, _conn):
                view = build_device_passport_list_view(repo)
        except LookupError:
            return PlainTextResponse("Device passport not found", status_code=404)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return PlainTextResponse(
                "Device passport data is unavailable",
                status_code=500,
            )
        return templates.TemplateResponse(
            request,
            "device_passports.html",
            _template_context(
                request,
                title="Паспорта устройств",
                authenticated=True,
                **view,
            ),
        )

    @app.get("/device-passports/{device_id}")
    async def device_passport_detail(request: Request, device_id: str):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        try:
            with _open_repository(actual_settings) as (repo, _conn):
                view = build_device_passport_detail_view(repo, device_id)
                local_device_id = view["passport"].get("local_device_id")
                view["config_identity"] = (
                    str(repo.get_device(int(local_device_id))["name"])
                    if local_device_id is not None
                    else "не привязан"
                )
        except LookupError:
            return PlainTextResponse("Device passport not found", status_code=404)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return PlainTextResponse(
                "Device passport data is unavailable",
                status_code=500,
            )
        return templates.TemplateResponse(
            request,
            "device_passport_detail.html",
            _template_context(
                request,
                title=f"Паспорт {device_id}",
                authenticated=True,
                **view,
            ),
        )

    @app.get("/device-passports/{device_id}/config")
    async def device_passport_config_secret(
        request: Request,
        device_id: str,
        protocol: str | None = None,
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        try:
            delivery = _build_and_audit_passport_secret(
                actual_settings,
                request,
                passport_device_id=device_id,
                protocol_version=protocol,
            )
        except LookupError:
            return PlainTextResponse("Device passport not found", status_code=404)
        except ConfigMaterialUnavailable:
            return PlainTextResponse("Config material is unavailable", status_code=400)
        return Response(
            content=delivery.config_bytes,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{delivery.config_filename}"'
                )
            },
        )

    @app.get("/device-passports/{device_id}/qr")
    async def device_passport_qr_secret(
        request: Request,
        device_id: str,
        protocol: str | None = None,
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        try:
            delivery = _build_and_audit_passport_secret(
                actual_settings,
                request,
                passport_device_id=device_id,
                protocol_version=protocol,
            )
        except LookupError:
            return PlainTextResponse("Device passport not found", status_code=404)
        except ConfigMaterialUnavailable:
            return PlainTextResponse("Config material is unavailable", status_code=400)
        return Response(content=delivery.qr_png_bytes, media_type="image/png")

    @app.get("/users")
    async def users_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        users = _load_users(actual_settings)
        return templates.TemplateResponse(
            request,
            "users.html",
            _template_context(
                request,
                title="Пользователи",
                authenticated=True,
                users=users,
            ),
        )

    @app.get("/devices/disabled")
    async def disabled_devices_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        devices = _load_disabled_devices(actual_settings)
        return templates.TemplateResponse(
            request,
            "disabled_devices.html",
            _template_context(
                request,
                title="Отключенные устройства",
                authenticated=True,
                devices=devices,
            ),
        )

    @app.get("/users/new")
    async def new_user_form(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        return templates.TemplateResponse(
            request,
            "user_form.html",
            _template_context(
                request,
                title="Новый пользователь",
                authenticated=True,
                action_url="/users/new",
                submit_label="Create user",
                user=_blank_user_form(),
                statuses=sorted(USER_STATUSES),
            ),
        )

    @app.post("/users/new")
    async def create_user(
        request: Request,
        telegram_id: int = Form(...),
        username: str = Form(""),
        first_name: str = Form(""),
        last_name: str = Form(""),
        email: str = Form(""),
        status: str = Form("active"),
        is_admin: str | None = Form(None),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            payload = _user_payload(
                telegram_id=telegram_id,
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                status=status,
                is_admin=is_admin,
            )
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    user_id = repo.create_user_for_admin(**payload)
                    _record_web_user_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_user_create",
                        target_user_id=user_id,
                        metadata={"telegram_id": telegram_id},
                    )
        except (sqlite3.IntegrityError, ValueError) as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.get("/users/{user_id}")
    async def user_detail(request: Request, user_id: int):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        try:
            detail = _load_user_detail(actual_settings, user_id)
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)

        return templates.TemplateResponse(
            request,
            "user_detail.html",
            _template_context(
                request,
                title=f"User {user_id}",
                authenticated=True,
                **detail,
            ),
        )

    @app.post("/users/{user_id}/devices/create-operator")
    async def create_operator_device(
        request: Request,
        user_id: int,
        server_name: str = Form(""),
        device_name: str = Form(""),
        duration_days: int = Form(0),
        config_version: str = Form(""),
        assignment_mode: str = Form(DEDICATED_DEVICE),
        execution_target: str = Form(""),
        mode: str = Form(""),
        confirm_one_device_gate: str = Form(""),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            from app.cli import (
                build_operator_device_create_plan,
                run_operator_device_create,
            )

            if mode not in {"dry-run", "apply"}:
                raise ValueError("Unsupported operator device create mode")
            with _open_repository(actual_settings) as (repo, _conn):
                owner = _row_to_dict(repo.get_user(user_id))
            if str(owner["status"]) != "active":
                raise ValueError("Operator device creation requires an active owner")

            admin_actor_id = _web_admin_actor_id(actual_settings)
            if admin_actor_id <= 0:
                raise PermissionError(
                    "ADMIN_TELEGRAM_IDS must include an authorized operator admin"
                )
            server = select_server(
                load_server_config(Path(actual_settings.server_config_path)),
                server_name,
            )
            output_path = _operator_device_artifact_path(actual_settings, user_id)

            if mode == "dry-run":
                plan = json.loads(
                    build_operator_device_create_plan(
                        owner_user_id=user_id,
                        server_name=server.name,
                        device_name=device_name,
                        duration_days=duration_days,
                        config_version=config_version,
                        assignment_mode=assignment_mode,
                        output_path=output_path,
                        admin_telegram_id=admin_actor_id,
                        execution_target=execution_target,
                    )
                )
                detail = _load_user_detail(actual_settings, user_id)
                return templates.TemplateResponse(
                    request,
                    "user_detail.html",
                    _template_context(
                        request,
                        title=f"User {user_id}",
                        authenticated=True,
                        operator_device_plan=plan,
                        **detail,
                    ),
                )

            if not actual_settings.vps_apply_enabled:
                raise ValueError(
                    "VPS_APPLY_ENABLED must be true before operator device apply"
                )
            if not actual_settings.operator_device_create_enabled:
                raise ValueError(
                    "OPERATOR_DEVICE_CREATE_ENABLED must be true before operator device apply"
                )
            if confirm_one_device_gate != "on":
                raise ValueError("Exact config-assignment gate confirmation is required")

            result = json.loads(
                run_operator_device_create(
                    db_path=Path(actual_settings.database_path),
                    server=server,
                    owner_user_id=user_id,
                    device_name=device_name,
                    duration_days=duration_days,
                    config_version=config_version,
                    assignment_mode=assignment_mode,
                    output_path=output_path,
                    admin_telegram_id=admin_actor_id,
                    app_secret_key=actual_settings.app_secret_key,
                    authorized_admin_telegram_ids=set(actual_settings.admin_ids),
                    max_devices_per_user=actual_settings.max_devices_per_user,
                    vps_ssh_password=actual_settings.vps_ssh_password,
                    client_config_template_dir=actual_settings.client_config_template_dir,
                    client_config_defaults=actual_settings.client_config_defaults,
                    execution_target=execution_target,
                    command_client=request.app.state.operator_command_client,
                    config_artifact_writer=(
                        request.app.state.operator_config_artifact_writer
                    ),
                )
            )
            detail = _load_user_detail(actual_settings, user_id)
            return templates.TemplateResponse(
                request,
                "user_detail.html",
                _template_context(
                    request,
                    title=f"User {user_id}",
                    authenticated=True,
                    operator_device_result=result,
                    **detail,
                ),
            )
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except RemoteOperationPartialFailure as exc:
            _record_web_user_vps_failure(
                actual_settings,
                request,
                action="web_operator_device_create_failed",
                target_user_id=user_id,
                operation="create_operator_device",
                exc=RuntimeError(
                    "remote operation partial failure; manual reconciliation required"
                ),
                metadata={
                    "user_id": user_id,
                    "server_name": server_name,
                    "execution_target": execution_target,
                    "operation_id": exc.result.operation_id,
                    "consistency_status": exc.result.consistency_status,
                    "remote_applied": exc.result.remote_applied,
                    "local_applied": exc.result.local_applied,
                },
            )
            return PlainTextResponse(
                "Operator device creation partially failed after remote apply; "
                "manual reconciliation required",
                status_code=409,
            )
        except (ConfigError, PeerApplyError) as exc:
            _record_web_user_vps_failure(
                actual_settings,
                request,
                action="web_operator_device_create_failed",
                target_user_id=user_id,
                operation="create_operator_device",
                exc=exc,
                metadata={
                    "user_id": user_id,
                    "server_name": server_name,
                    "execution_target": execution_target,
                },
            )
            return _plain_error_response(exc)
        except (FileExistsError, OSError, PermissionError, ValueError) as exc:
            return _plain_error_response(exc)

    @app.post("/users/{user_id}/email/verify/start")
    async def start_email_verification(
        request: Request,
        user_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)
        if not actual_settings.email_delivery_enabled:
            return PlainTextResponse("Email delivery is disabled", status_code=400)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    user = _row_to_dict(repo.get_user(user_id))
                    email = _required_user_email(user)
                    token = create_email_token(
                        ttl_minutes=actual_settings.email_recovery_token_ttl_minutes,
                    )
                    repo.create_email_recovery_token(
                        user_id=user_id,
                        email=email,
                        token_hash=token.token_hash,
                        purpose="verify_email",
                        expires_at=token.expires_at,
                    )
                    metadata = _email_service(request).send_verification_email(
                        to_address=email,
                        user_id=user_id,
                        token=token.raw_token,
                    )
                    _record_web_user_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_email_verify_start",
                        target_user_id=user_id,
                        metadata=metadata,
                    )
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except ConfigMaterialUnavailable:
            return PlainTextResponse("Config material is unavailable", status_code=400)
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.get("/email/verify")
    async def verify_email_form(request: Request):
        return templates.TemplateResponse(
            request,
            "email_result.html",
            _template_context(
                request,
                title="Verify email",
                authenticated=_is_authenticated(request),
                heading="Verify email",
                message="Enter the one-time verification code from the email.",
                form_action="/email/verify",
                token_label="Verification code",
                submit_label="Verify email",
            ),
        )

    @app.post("/email/verify")
    async def verify_email(request: Request, token: str = Form("")):
        if not token:
            return PlainTextResponse("Verification code is invalid or expired", status_code=400)
        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    token_row = repo.get_valid_email_recovery_token(
                        token_hash=hash_email_token(token),
                        purpose="verify_email",
                        now=utc_now_iso(),
                    )
                    if token_row is None:
                        return PlainTextResponse(
                            "Verification code is invalid or expired",
                            status_code=400,
                        )
                    user = repo.get_user(int(token_row["user_id"]))
                    if user["email"] != token_row["email"]:
                        return PlainTextResponse(
                            "Verification code is invalid or expired",
                            status_code=400,
                        )
                    repo.mark_user_email_verified(int(user["id"]), utc_now_iso())
                    if not repo.mark_email_recovery_token_used(
                        int(token_row["id"]),
                        utc_now_iso(),
                    ):
                        return PlainTextResponse(
                            "Verification code is invalid or expired",
                            status_code=400,
                        )
        except LookupError:
            return PlainTextResponse("Verification code is invalid or expired", status_code=400)

        return templates.TemplateResponse(
            request,
            "email_result.html",
            _template_context(
                request,
                title="Email verified",
                authenticated=_is_authenticated(request),
                heading="Email verified",
                message="Email verified. You can close this page.",
            ),
        )

    @app.post("/users/{user_id}/devices/{device_id}/email-config")
    async def send_device_config_email(
        request: Request,
        user_id: int,
        device_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)
        if not actual_settings.email_delivery_enabled:
            return PlainTextResponse("Email delivery is disabled", status_code=400)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    user = _row_to_dict(repo.get_user(user_id))
                    email = _required_user_email(user)
                    if not user["email_verified_at"]:
                        return PlainTextResponse("Email is not verified", status_code=400)
                    device = repo.get_user_device(user_id=user_id, device_id=device_id)
                    if device is None:
                        return PlainTextResponse("Device not found", status_code=404)
                    result = build_device_config_delivery(
                        repo=repo,
                        secret_box=SecretBox.from_app_secret(actual_settings.app_secret_key),
                        device=device,
                        client_config_template_dir=actual_settings.client_config_template_dir,
                        client_config_defaults=actual_settings.client_config_defaults,
                    )
                    metadata = _email_service(request).send_config_email(
                        to_address=email,
                        user_id=user_id,
                        device_id=device_id,
                        delivery=result.delivery,
                    )
                    _record_web_user_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_email_config_send",
                        target_user_id=user_id,
                        target_device_id=device_id,
                        metadata=metadata,
                    )
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.post("/users/{user_id}/devices/{device_id}/email-recovery/start")
    async def start_device_config_recovery(
        request: Request,
        user_id: int,
        device_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)
        if not actual_settings.email_delivery_enabled:
            return PlainTextResponse("Email delivery is disabled", status_code=400)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    user = _row_to_dict(repo.get_user(user_id))
                    email = _required_user_email(user)
                    if not user["email_verified_at"]:
                        return PlainTextResponse("Email is not verified", status_code=400)
                    if repo.get_user_device(user_id=user_id, device_id=device_id) is None:
                        return PlainTextResponse("Device not found", status_code=404)
                    token = create_email_token(
                        ttl_minutes=actual_settings.email_recovery_token_ttl_minutes,
                    )
                    repo.create_email_recovery_token(
                        user_id=user_id,
                        email=email,
                        token_hash=token.token_hash,
                        purpose="recover_config",
                        expires_at=token.expires_at,
                        device_id=device_id,
                    )
                    metadata = _email_service(request).send_recovery_start_email(
                        to_address=email,
                        user_id=user_id,
                        device_id=device_id,
                        token=token.raw_token,
                    )
                    _record_web_user_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_email_recovery_start",
                        target_user_id=user_id,
                        target_device_id=device_id,
                        metadata=metadata,
                    )
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.get("/email/recover")
    async def recover_device_config_form(request: Request):
        if not actual_settings.email_delivery_enabled:
            return PlainTextResponse("Email delivery is disabled", status_code=400)
        return templates.TemplateResponse(
            request,
            "email_result.html",
            _template_context(
                request,
                title="Recover config",
                authenticated=_is_authenticated(request),
                heading="Recover config",
                message="Enter the one-time recovery code from the email.",
                form_action="/email/recover",
                token_label="Recovery code",
                submit_label="Send config email",
            ),
        )

    @app.post("/email/recover")
    async def recover_device_config(request: Request, token: str = Form("")):
        if not actual_settings.email_delivery_enabled:
            return PlainTextResponse("Email delivery is disabled", status_code=400)
        if not token:
            return PlainTextResponse("Recovery code is invalid or expired", status_code=400)
        try:
            send_to_address = ""
            send_user_id = 0
            send_device_id = 0
            send_delivery = None
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    token_row = repo.get_valid_email_recovery_token(
                        token_hash=hash_email_token(token),
                        purpose="recover_config",
                        now=utc_now_iso(),
                    )
                    if token_row is None:
                        return PlainTextResponse(
                            "Recovery code is invalid or expired",
                            status_code=400,
                        )
                    user = _row_to_dict(repo.get_user(int(token_row["user_id"])))
                    if user["email"] != token_row["email"] or not user["email_verified_at"]:
                        return PlainTextResponse(
                            "Recovery code is invalid or expired",
                            status_code=400,
                        )
                    device = repo.get_user_device(
                        user_id=int(user["id"]),
                        device_id=int(token_row["device_id"]),
                    )
                    if device is None:
                        return PlainTextResponse(
                            "Recovery code is invalid or expired",
                            status_code=400,
                        )
                    result = build_device_config_delivery(
                        repo=repo,
                        secret_box=SecretBox.from_app_secret(actual_settings.app_secret_key),
                        device=device,
                        client_config_template_dir=actual_settings.client_config_template_dir,
                        client_config_defaults=actual_settings.client_config_defaults,
                    )
                    if not repo.mark_email_recovery_token_used(
                        int(token_row["id"]),
                        utc_now_iso(),
                    ):
                        return PlainTextResponse(
                            "Recovery code is invalid or expired",
                            status_code=400,
                        )
                    send_to_address = str(token_row["email"])
                    send_user_id = int(user["id"])
                    send_device_id = int(device["id"])
                    send_delivery = result.delivery
            if send_delivery is None:
                return PlainTextResponse("Recovery code is invalid or expired", status_code=400)
            _email_service(request).send_config_email(
                to_address=send_to_address,
                user_id=send_user_id,
                device_id=send_device_id,
                delivery=send_delivery,
            )
        except ConfigMaterialUnavailable:
            return PlainTextResponse("Config material is unavailable", status_code=400)
        except (LookupError, ValueError):
            return PlainTextResponse("Recovery code is invalid or expired", status_code=400)

        return templates.TemplateResponse(
            request,
            "email_result.html",
            _template_context(
                request,
                title="Config recovery email sent",
                authenticated=_is_authenticated(request),
                heading="Config recovery email sent",
                message="Config recovery email sent. You can close this page.",
            ),
        )

    @app.get("/users/{user_id}/edit")
    async def edit_user_form(request: Request, user_id: int):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                user = _row_to_dict(repo.get_user(user_id))
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)

        return templates.TemplateResponse(
            request,
            "user_form.html",
            _template_context(
                request,
                title=f"Edit user {user_id}",
                authenticated=True,
                action_url=f"/users/{user_id}/edit",
                submit_label="Save changes",
                user=user,
                statuses=sorted(USER_STATUSES),
            ),
        )

    @app.post("/users/{user_id}/edit")
    async def update_user(
        request: Request,
        user_id: int,
        telegram_id: int = Form(...),
        username: str = Form(""),
        first_name: str = Form(""),
        last_name: str = Form(""),
        email: str = Form(""),
        status: str = Form("active"),
        is_admin: str | None = Form(None),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            payload = _user_payload(
                telegram_id=telegram_id,
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                status=status,
                is_admin=is_admin,
            )
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    repo.update_user_for_admin(user_id=user_id, **payload)
                    _record_web_user_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_user_update",
                        target_user_id=user_id,
                        metadata={"telegram_id": telegram_id},
                    )
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except (sqlite3.IntegrityError, ValueError) as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.post("/users/{user_id}/block")
    async def block_user(
        request: Request,
        user_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _set_user_status_with_action(
                actual_settings,
                request,
                user_id=user_id,
                status="blocked",
                action="web_user_block",
            )
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.post("/users/{user_id}/delete")
    async def delete_user(
        request: Request,
        user_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _set_user_status_with_action(
                actual_settings,
                request,
                user_id=user_id,
                status="deleted",
                action="web_user_delete",
            )
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.post("/users/{user_id}/disable-vpn")
    async def disable_user_vpn(
        request: Request,
        user_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _disable_user_vpn(actual_settings, request, user_id)
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except (ConfigError, PeerApplyError) as exc:
            _record_web_user_vps_failure(
                actual_settings,
                request,
                action="web_user_disable_vpn_failed",
                target_user_id=user_id,
                operation="disable_user_vpn",
                exc=exc,
                metadata={"user_id": user_id},
            )
            return _plain_error_response(exc)
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.post("/users/{user_id}/enable-vpn")
    async def enable_user_vpn(
        request: Request,
        user_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _enable_user_vpn(actual_settings, request, user_id)
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except (ConfigError, PeerApplyError) as exc:
            _record_web_user_vps_failure(
                actual_settings,
                request,
                action="web_user_enable_vpn_failed",
                target_user_id=user_id,
                operation="enable_user_vpn",
                exc=exc,
                metadata={"user_id": user_id},
            )
            return _plain_error_response(exc)
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.post("/users/{user_id}/devices/{device_id}/secrets")
    async def reveal_device_secrets(
        request: Request,
        user_id: int,
        device_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            revealed_secrets = _reveal_device_secrets(
                actual_settings,
                request,
                user_id=user_id,
                device_id=device_id,
            )
            detail = _load_user_detail(actual_settings, user_id)
        except LookupError:
            return PlainTextResponse("Device not found", status_code=404)
        except ConfigMaterialUnavailable:
            return PlainTextResponse("Config material is unavailable", status_code=400)
        except ValueError as exc:
            return _plain_error_response(exc)

        return templates.TemplateResponse(
            request,
            "user_detail.html",
            _template_context(
                request,
                title=f"User {user_id}",
                authenticated=True,
                revealed_device_id=device_id,
                revealed_secrets=revealed_secrets,
                **detail,
            ),
        )

    @app.post("/users/{user_id}/devices/{device_id}/delete")
    async def delete_user_device(
        request: Request,
        user_id: int,
        device_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _delete_user_device(actual_settings, request, user_id=user_id, device_id=device_id)
        except LookupError:
            return PlainTextResponse("Device not found", status_code=404)
        except (ConfigError, PeerApplyError, RemoteOperationPartialFailure) as exc:
            _record_web_user_vps_failure(
                actual_settings,
                request,
                action="web_device_delete_failed",
                target_user_id=user_id,
                target_device_id=device_id,
                operation="delete_user_device",
                exc=exc,
                metadata={"user_id": user_id, "device_id": device_id},
            )
            return _plain_error_response(exc)
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/users/{user_id}", status_code=303)

    @app.post("/users/{user_id}/destroy")
    async def destroy_user(
        request: Request,
        user_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _destroy_user(actual_settings, request, user_id)
        except LookupError:
            return PlainTextResponse("User not found", status_code=404)
        except (ConfigError, PeerApplyError) as exc:
            _record_web_user_vps_failure(
                actual_settings,
                request,
                action="web_user_destroy_failed",
                target_user_id=user_id,
                operation="destroy_user",
                exc=exc,
                metadata={"user_id": user_id},
            )
            return _plain_error_response(exc)
        except ValueError as exc:
            return _plain_error_response(exc)

        return RedirectResponse("/users", status_code=303)

    @app.get("/servers")
    async def servers_index(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        servers = _load_servers(actual_settings)
        return templates.TemplateResponse(
            request,
            "servers.html",
            _template_context(
                request,
                title="Серверы",
                authenticated=True,
                servers=servers,
            ),
        )

    @app.get("/servers/new")
    async def new_server_form(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        return templates.TemplateResponse(
            request,
            "server_form.html",
            _template_context(
                request,
                title="New server",
                authenticated=True,
                action_url="/servers/new",
                submit_label="Create server",
                server=_blank_server_form(),
                statuses=sorted(SERVER_STATUSES),
            ),
        )

    @app.post("/servers/new")
    async def create_server(
        request: Request,
        name: str = Form(...),
        host: str = Form(...),
        ssh_port: int = Form(...),
        endpoint_host: str = Form(...),
        vpn_port: int = Form(...),
        vpn_network_cidr: str = Form(...),
        server_address: str = Form(...),
        server_public_key: str = Form(""),
        runtime: str = Form(...),
        firewall: str = Form(...),
        status: str = Form("active"),
        max_devices: int = Form(...),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            payload = _server_payload(
                name=name,
                host=host,
                ssh_port=ssh_port,
                endpoint_host=endpoint_host,
                vpn_port=vpn_port,
                vpn_network_cidr=vpn_network_cidr,
                server_address=server_address,
                server_public_key=server_public_key,
                runtime=runtime,
                firewall=firewall,
                status=status,
                max_devices=max_devices,
            )
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    server_id = repo.create_server_for_admin(**payload)
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_create",
                        server_id=server_id,
                        metadata={"name": payload["name"]},
                    )
        except (sqlite3.IntegrityError, ValueError) as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.get("/servers/{server_id}")
    async def server_detail(request: Request, server_id: int):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        try:
            detail = _load_server_detail(actual_settings, server_id)
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)
        peer_sync = _load_peer_sync_from_session(request, server_id)
        detail["server_managed_configs"] = _with_live_peer_sync_status(
            detail["server_managed_configs"],
            peer_sync,
        )

        return templates.TemplateResponse(
            request,
            "server_detail.html",
            _template_context(
                request,
                title=f"Server {server_id}",
                authenticated=True,
                peer_sync=peer_sync,
                vps_readiness=_load_vps_readiness(
                    actual_settings,
                    server=detail["server"],
                    latest_health=detail["latest_health"],
                    peer_sync=peer_sync,
                ),
                vps_retest_commands=_vps_retest_commands(
                    actual_settings,
                    detail["server"],
                ),
                **detail,
            ),
        )

    @app.post("/servers/{server_id}/sync/run")
    async def run_server_peer_sync(
        request: Request,
        server_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            report = _collect_server_peer_sync(actual_settings, server_id)
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_peer_sync_run",
                        server_id=server_id,
                        metadata={
                            "known_count": report["known_count"],
                            "unknown_count": report["unknown_count"],
                            "missing_count": report["missing_count"],
                        },
                    )
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)
        except (ConfigError, ValueError) as exc:
            report = _empty_peer_sync_report(error=str(exc))

        request.session[_peer_sync_session_key(server_id)] = json.dumps(report)
        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.post("/servers/{server_id}/unknown-peers/ignore")
    async def ignore_unknown_remote_peer(
        request: Request,
        server_id: int,
        peer_public_key: str = Form(...),
        allowed_ips: str = Form(""),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    repo.ignore_remote_peer(
                        server_id=server_id,
                        peer_public_key=peer_public_key,
                        allowed_ips=allowed_ips,
                    )
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_peer_ignore",
                        server_id=server_id,
                        metadata={
                            "peer_public_key": peer_public_key,
                            "allowed_ips": allowed_ips,
                        },
                    )
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)

        request.session.pop(_peer_sync_session_key(server_id), None)
        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.post("/servers/{server_id}/amnezia-peers/unmark")
    async def unmark_amnezia_created_peer(
        request: Request,
        server_id: int,
        peer_public_key: str = Form(...),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    repo.get_server(server_id)
                    removed = repo.unignore_remote_peer(
                        server_id=server_id,
                        peer_public_key=peer_public_key,
                    )
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_peer_unmark_amnezia",
                        server_id=server_id,
                        metadata={
                            "peer_public_key": peer_public_key,
                            "removed": removed,
                        },
                    )
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)

        request.session.pop(_peer_sync_session_key(server_id), None)
        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.post("/servers/{server_id}/unknown-peers/remove")
    async def remove_unknown_remote_peer(
        request: Request,
        server_id: int,
        peer_public_key: str = Form(...),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _remove_unknown_remote_peer(actual_settings, server_id, peer_public_key)
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    repo.get_server(server_id)
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_peer_remove",
                        server_id=server_id,
                        metadata={"peer_public_key": peer_public_key},
                    )
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)
        except (ConfigError, PeerApplyError) as exc:
            _record_web_server_vps_failure(
                actual_settings,
                request,
                action="web_server_peer_remove_failed",
                server_id=server_id,
                operation="remove_unknown_remote_peer",
                exc=exc,
                metadata={"peer_public_key": peer_public_key},
            )
            return _plain_error_response(exc)
        except ValueError as exc:
            return _plain_error_response(exc)

        request.session.pop(_peer_sync_session_key(server_id), None)
        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.post("/servers/{server_id}/missing-devices/{device_id}/add")
    async def add_missing_local_device_to_amnezia(
        request: Request,
        server_id: int,
        device_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            _add_missing_local_device_to_amnezia(
                actual_settings,
                request,
                server_id=server_id,
                device_id=device_id,
            )
        except LookupError:
            return PlainTextResponse("Device not found", status_code=404)
        except (ConfigError, PeerApplyError) as exc:
            _record_web_server_vps_failure(
                actual_settings,
                request,
                action="web_server_missing_device_add_failed",
                server_id=server_id,
                operation="add_missing_local_device_to_amnezia",
                exc=exc,
                metadata={"device_id": device_id},
            )
            return _plain_error_response(exc)
        except ValueError as exc:
            return _plain_error_response(exc)

        peer_sync = _refresh_peer_sync_after_missing_device_add(
            actual_settings,
            server_id=server_id,
            device_id=device_id,
        )
        request.session[_peer_sync_session_key(server_id)] = json.dumps(peer_sync)
        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.get("/servers/{server_id}/edit")
    async def edit_server_form(request: Request, server_id: int):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                server = _row_to_dict(repo.get_server(server_id))
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)

        return templates.TemplateResponse(
            request,
            "server_form.html",
            _template_context(
                request,
                title=f"Edit server {server_id}",
                authenticated=True,
                action_url=f"/servers/{server_id}/edit",
                submit_label="Save changes",
                server=server,
                statuses=sorted(SERVER_STATUSES),
            ),
        )

    @app.post("/servers/{server_id}/edit")
    async def update_server(
        request: Request,
        server_id: int,
        name: str = Form(...),
        host: str = Form(...),
        ssh_port: int = Form(...),
        endpoint_host: str = Form(...),
        vpn_port: int = Form(...),
        vpn_network_cidr: str = Form(...),
        server_address: str = Form(...),
        server_public_key: str = Form(""),
        runtime: str = Form(...),
        firewall: str = Form(...),
        status: str = Form("active"),
        max_devices: int = Form(...),
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            payload = _server_payload(
                name=name,
                host=host,
                ssh_port=ssh_port,
                endpoint_host=endpoint_host,
                vpn_port=vpn_port,
                vpn_network_cidr=vpn_network_cidr,
                server_address=server_address,
                server_public_key=server_public_key,
                runtime=runtime,
                firewall=firewall,
                status=status,
                max_devices=max_devices,
            )
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    repo.update_server_for_admin(
                        server_id=server_id,
                        **payload,
                    )
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_update",
                        server_id=server_id,
                        metadata={"name": payload["name"]},
                    )
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)
        except (sqlite3.IntegrityError, ValueError) as exc:
            return _plain_error_response(exc)

        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.post("/servers/{server_id}/disable")
    async def disable_server(
        request: Request,
        server_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    repo.set_server_status_for_admin(server_id, "disabled")
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_disable",
                        server_id=server_id,
                        metadata={"status": "disabled"},
                    )
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)

        return RedirectResponse(f"/servers/{server_id}", status_code=303)

    @app.get("/servers/{server_id}/health")
    async def server_health(request: Request, server_id: int):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)

        try:
            detail = _load_server_detail(actual_settings, server_id)
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)

        return templates.TemplateResponse(
            request,
            "server_health.html",
            _template_context(
                request,
                title=f"Server {server_id} health",
                authenticated=True,
                **detail,
            ),
        )

    @app.post("/servers/{server_id}/health/run")
    async def run_server_health(
        request: Request,
        server_id: int,
        csrf_token: str = Form(""),
    ):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)

        try:
            with _open_repository(actual_settings) as (repo, _conn):
                server = _row_to_dict(repo.get_server(server_id))
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)

        summary = run_server_health_check(actual_settings, str(server["name"]))
        try:
            with _open_repository(actual_settings) as (repo, _conn):
                with repo.transaction():
                    repo.get_server(server_id)
                    _record_health_summary(repo, server_id, summary)
                    _record_web_server_action(
                        repo,
                        actual_settings,
                        request,
                        action="web_server_health_run",
                        server_id=server_id,
                        metadata={
                            "operation_id": summary.operation_id,
                            "risk_class": summary.risk_class,
                            "consistency_status": summary.consistency_status,
                            "status": summary.status,
                            "error": summary.error,
                        },
                    )
        except LookupError:
            return PlainTextResponse("Server not found", status_code=404)

        return RedirectResponse(f"/servers/{server_id}/health", status_code=303)

    @app.post("/logout")
    async def logout(request: Request, csrf_token: str = Form("")):
        if not verify_csrf_token(request.session, csrf_token):
            return PlainTextResponse("Invalid CSRF token", status_code=403)
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    return app


def _is_authenticated(request: Request) -> bool:
    return request.session.get(SESSION_AUTH_KEY) is True


def _template_context(request: Request, **context: Any) -> dict[str, Any]:
    base_context = {
        "request": request,
        "settings": request.app.state.settings,
        "csrf_token": generate_csrf_token(request.session),
    }
    base_context.update(context)
    return base_context


def _plain_error_response(exc: Exception, *, status_code: int = 400) -> PlainTextResponse:
    detail = redact(str(exc)).strip() or type(exc).__name__
    if isinstance(exc, PeerApplyError):
        detail = f"{type(exc).__name__}: {detail}"
    return PlainTextResponse(detail, status_code=status_code)


@contextmanager
def _open_repository(settings: Settings) -> Iterator[tuple[Repository, Any]]:
    conn = connect(settings.database_path)
    try:
        initialize_schema(conn)
        yield Repository(conn), conn
    finally:
        conn.close()


def _load_dashboard(settings: Settings) -> dict[str, Any]:
    with _open_repository(settings) as (repo, conn):
        user_count = _count_rows(conn, "SELECT COUNT(*) AS count FROM users")
        server_count = _count_rows(conn, "SELECT COUNT(*) AS count FROM servers")
        pending_order_count = _count_rows(
            conn,
            """
            SELECT COUNT(*) AS count
            FROM orders
            WHERE status IN ('manual_review', 'approved')
              AND device_id IS NULL
            """,
        )
        active_device_count = _count_rows(
            conn,
            "SELECT COUNT(*) AS count FROM devices WHERE status = 'active'",
        )
        users = [_row_to_dict(row) for row in repo.list_users_for_admin(limit=5)]
        servers = [_row_to_dict(row) for row in repo.list_servers_for_admin(limit=5)]
        pending_orders = [_row_to_dict(row) for row in repo.list_pending_orders(limit=5)]
        active_devices = [
            _row_to_dict(row) for row in repo.list_active_devices_with_users(limit=5)
        ]

    return {
        "metrics": [
            {
                "label": "Пользователи",
                "value": user_count,
                "unit_label": _plural_ru_word(user_count, "пользователь", "пользователя", "пользователей"),
                "caption": _plural_ru(user_count, "пользователь", "пользователя", "пользователей"),
            },
            {
                "label": "Серверы",
                "value": server_count,
                "unit_label": _plural_ru_word(server_count, "сервер", "сервера", "серверов"),
                "caption": _plural_ru(server_count, "сервер", "сервера", "серверов"),
            },
            {
                "label": "Заявки",
                "value": pending_order_count,
                "unit_label": _plural_ru_word(pending_order_count, "заявка", "заявки", "заявок"),
                "caption": _plural_ru(pending_order_count, "заявка", "заявки", "заявок"),
            },
            {
                "label": "Активные устройства",
                "value": active_device_count,
                "unit_label": _plural_ru_word(active_device_count, "устройство", "устройства", "устройств"),
                "caption": _plural_ru(active_device_count, "устройство", "устройства", "устройств"),
            },
        ],
        "users": users,
        "servers": servers,
        "pending_orders": pending_orders,
        "active_devices": active_devices,
    }


def _load_users(settings: Settings) -> list[dict[str, Any]]:
    with _open_repository(settings) as (repo, _conn):
        return [
            _user_presentation(row)
            for row in repo.list_users_for_admin(limit=500)
        ]


def _load_plans(settings: Settings) -> dict[str, Any]:
    with _open_repository(settings) as (repo, _conn):
        plans = []
        for row in repo.list_plans_for_admin():
            plan = _row_to_dict(row)
            configured_quota = plan["max_devices"]
            plan["effective_max_devices"] = (
                min(settings.max_devices_per_user, int(configured_quota))
                if configured_quota is not None
                else settings.max_devices_per_user
            )
            plans.append(plan)
    return {
        "plans": plans,
        "global_max_devices_per_user": settings.max_devices_per_user,
        "configured_plan_quota_count": sum(
            1 for plan in plans if plan["max_devices"] is not None
        ),
    }


def _load_disabled_devices(settings: Settings) -> list[dict[str, Any]]:
    with _open_repository(settings) as (repo, _conn):
        return [
            {
                **_row_to_dict(row),
                "user_display": user_display_label(row),
            }
            for row in repo.list_disabled_devices_with_users(limit=100)
        ]


def _load_servers(settings: Settings) -> list[dict[str, Any]]:
    with _open_repository(settings) as (repo, _conn):
        return [_row_to_dict(row) for row in repo.list_servers_for_admin(limit=500)]


def _load_api_readiness(settings: Settings) -> dict[str, Any]:
    with _open_repository(settings) as (_repo, conn):
        return {
            "allowed_scopes": API_READINESS_ALLOWED_SCOPES,
            "metrics": {
                "servers_total": _count_rows(
                    conn,
                    "SELECT COUNT(*) AS count FROM servers",
                ),
                "users_total": _count_rows(
                    conn,
                    "SELECT COUNT(*) AS count FROM users",
                ),
                "devices_total": _count_rows(
                    conn,
                    "SELECT COUNT(*) AS count FROM devices",
                ),
            },
            "blocked_surfaces": [
                "/api/clients write CRUD",
                "API config:read",
                "public config delivery",
                "live peer apply/revoke",
            ],
        }


def _load_api_tokens(settings: Settings) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    rotation_notice_at = now + timedelta(days=API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS)
    with _open_repository(settings) as (repo, _conn):
        tokens = []
        for row in repo.list_api_tokens_for_admin(limit=200):
            token = _row_to_dict(row)
            token["scopes"] = json.loads(str(token.pop("scopes_json")))
            expires_at = _parse_optional_datetime(token.get("expires_at"))
            if token.get("revoked_at"):
                token["status"] = "revoked"
            elif expires_at is not None and expires_at <= now:
                token["status"] = "expired"
            elif expires_at is not None and expires_at <= rotation_notice_at:
                token["status"] = "rotation-due"
            else:
                token["status"] = "active"
            tokens.append(token)
        return tokens


def _api_token_issue_form(
    *,
    name: str = "",
    owner_label: str = "",
    integration_kind: str = "monitoring",
    purpose: str = "",
    scopes: list[str] | None = None,
    expires_days: int = 7,
) -> dict[str, Any]:
    return {
        "name": name,
        "owner_label": owner_label,
        "integration_kind": integration_kind,
        "purpose": purpose,
        "scopes": scopes or list(API_READINESS_ALLOWED_SCOPES),
        "expires_days": expires_days,
    }


def _api_token_expiry(
    expires_days: int,
    *,
    now: datetime | None = None,
) -> datetime:
    if not 1 <= expires_days <= API_TOKEN_MAX_TTL_DAYS:
        raise ValueError(f"expires_days must be in 1..{API_TOKEN_MAX_TTL_DAYS}")
    return (now or datetime.now(timezone.utc)) + timedelta(days=expires_days)


def _api_token_record_from_row(row: sqlite3.Row) -> ApiTokenRecord:
    return ApiTokenRecord(
        token_id=str(row["id"]),
        token_hash=str(row["token_hash"]),
        name=str(row["name"]),
        owner_label=str(row["owner_label"]),
        integration_kind=str(row["integration_kind"]),
        purpose=str(row["purpose"]),
        owner_user_id=row["owner_user_id"],
        owner_status=row["owner_status"],
        scopes=frozenset(json.loads(str(row["scopes_json"]))),
        expires_at=_parse_optional_datetime(row["expires_at"]),
        revoked_at=_parse_optional_datetime(row["revoked_at"]),
    )


def _parse_optional_datetime(value: object) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_orders(settings: Settings) -> list[dict[str, Any]]:
    with _open_repository(settings) as (repo, _conn):
        return [_row_to_dict(row) for row in repo.list_orders_for_admin(limit=200)]


def _load_settings_sections(settings: Settings) -> list[dict[str, Any]]:
    sections = [
        {
            "title": section_title,
            "items": [
                _setting_entry(settings, field_name)
                for field_name in field_names
            ],
        }
        for section_title, field_names in SETTINGS_SECTIONS.items()
    ]
    grouped_fields = {
        field_name
        for field_names in SETTINGS_SECTIONS.values()
        for field_name in field_names
    }
    other_fields = [
        field_name
        for field_name in Settings.model_fields
        if field_name not in grouped_fields
    ]
    if other_fields:
        sections.append(
            {
                "title": "Other",
                "items": [_setting_entry(settings, field_name) for field_name in other_fields],
            }
        )
    return sections


def _load_client_config_template_views(settings: Settings) -> list[dict[str, str]]:
    sample = _sample_client_config_input(settings)
    template_dir = settings.client_config_template_dir
    views: list[dict[str, str]] = []
    for config_version in SUPPORTED_CLIENT_CONFIG_VERSIONS:
        template_text = ""
        try:
            template_text = load_client_config_template(config_version, template_dir)
            preview = render_client_config_template(template_text, sample)
            safe_preview = _safe_config_preview(preview)
            vpn_import_link = build_vpn_import_link(safe_preview)
            error = ""
        except ConfigTemplateError as exc:
            safe_preview = ""
            vpn_import_link = ""
            error = str(exc)
        views.append(
            {
                "version": config_version,
                "filename": f"{config_version}.conf.tpl",
                "source": client_config_template_source(config_version, template_dir),
                "template_text": template_text,
                "preview": safe_preview,
                "vpn_import_link": vpn_import_link,
                "error": error,
            }
        )
    return views


def _sample_client_config_input(settings: Settings) -> ClientConfigInput:
    defaults = settings.client_config_defaults
    return ClientConfigInput(
        private_key="sample-client-private-key",
        address="10.8.0.2/32",
        dns=defaults.dns,
        server_public_key="sample-server-public-key",
        preshared_key="sample-preshared-key",
        endpoint="vpn.example.com:30001",
        allowed_ips=defaults.allowed_ips,
        persistent_keepalive=defaults.persistent_keepalive,
        jc=defaults.jc,
        jmin=defaults.jmin,
        jmax=defaults.jmax,
        s1=defaults.s1,
        s2=defaults.s2,
        s3=defaults.s3,
        s4=defaults.s4,
        h1=defaults.h1,
        h2=defaults.h2,
        h3=defaults.h3,
        h4=defaults.h4,
        i1=defaults.i1,
        i2=defaults.i2,
        i3=defaults.i3,
        i4=defaults.i4,
        i5=defaults.i5,
    )


def _safe_config_preview(config_text: str) -> str:
    return SECRET_CONFIG_LINE_RE.sub(r"\1<sample-secret>", config_text)


def _delivery_template_placeholders() -> list[str]:
    return [
        "{device_id}",
        "{config_version}",
        "{config_version_label}",
        "{vpn_link}",
        "{android_amnezia}",
        "{android_amneziawg}",
        "{ios_russia_defaultvpn}",
        "{windows_amneziawg}",
        "{defaultvpn_github}",
    ]


def _setting_entry(settings: Settings, field_name: str) -> dict[str, str]:
    field = Settings.model_fields[field_name]
    alias = str(field.alias or field_name).upper()
    value = getattr(settings, field_name)
    return {
        "name": alias,
        "value": _display_setting_value(
            alias,
            value,
            is_path=field_name in PATH_SETTING_FIELDS,
        ),
    }


def _display_setting_value(name: str, value: Any, *, is_path: bool = False) -> str:
    if is_path and str(value):
        value = Path(str(value)).name
    redacted = redact(f"{name}={value}")
    return redacted.split("=", maxsplit=1)[1] if "=" in redacted else redacted


def _load_user_detail(settings: Settings, user_id: int) -> dict[str, Any]:
    with _open_repository(settings) as (repo, _conn):
        user = _user_presentation(repo.get_user_for_admin(user_id))
        next_device_sequence = repo.next_device_sequence(
            settings.bot_device_name_prefix,
            minimum_sequence=settings.bot_device_name_sequence_seed,
        )
        devices = [
            _row_to_dict(row) for row in repo.list_user_devices_for_admin(user_id)
        ]
        orders = [_row_to_dict(row) for row in repo.list_user_orders_for_admin(user_id)]
        admin_actions = [
            _row_to_dict(row) for row in repo.list_admin_actions_for_target_user(user_id)
        ]
    return {
        "user": user,
        "devices": devices,
        "vpn_actions": _build_user_vpn_actions(devices),
        "orders": orders,
        "admin_actions": admin_actions,
        "operator_device_form": _operator_device_form_context(
            settings,
            user=user,
            default_device_name=(
                f"{settings.bot_device_name_prefix}-{next_device_sequence}"
            ),
        ),
    }


def _operator_device_form_context(
    settings: Settings,
    *,
    user: dict[str, Any],
    default_device_name: str,
) -> dict[str, Any]:
    servers: list[str] = []
    config_error = ""
    try:
        config = load_server_config(Path(settings.server_config_path))
        servers = [server.name for server in config.servers]
    except (ConfigError, OSError, ValueError):
        config_error = "Server configuration is unavailable"

    admin_actor_available = _web_admin_actor_id(settings) > 0
    owner_active = str(user["status"]) == "active"
    available = bool(servers) and admin_actor_available and owner_active
    default_server = settings.server_name if settings.server_name in servers else ""
    if not default_server and servers:
        default_server = servers[0]
    return {
        "available": available,
        "apply_enabled": (
            available
            and settings.vps_apply_enabled
            and settings.operator_device_create_enabled
        ),
        "admin_actor_available": admin_actor_available,
        "owner_active": owner_active,
        "servers": servers,
        "config_versions": SUPPORTED_CLIENT_CONFIG_VERSIONS,
        "assignment_modes": CONFIG_ASSIGNMENT_MODES,
        "default_server": default_server,
        "default_device_name": default_device_name,
        "default_duration_days": settings.default_plan_days,
        "config_error": config_error,
    }


def _operator_device_artifact_path(settings: Settings, user_id: int) -> Path:
    return (
        Path(settings.database_path).parent
        / "private-artifacts"
        / "operator-device"
        / str(user_id)
        / f"{uuid4().hex}.conf"
    )


def _build_user_vpn_actions(devices: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    disable_count = sum(
        1 for device in devices if device["status"] in {"active", "pending"}
    )
    enable_count = sum(1 for device in devices if device["status"] == "disabled")
    return {
        "disable": {
            "available": disable_count > 0,
            "hint": (
                f"{disable_count} active/pending "
                f"{_plural(disable_count, 'device', 'devices')} can be disabled"
                if disable_count
                else "No active or pending devices to disable"
            ),
        },
        "enable": {
            "available": enable_count > 0,
            "hint": (
                f"{enable_count} disabled "
                f"{_plural(enable_count, 'device', 'devices')} can be enabled"
                if enable_count
                else "No disabled devices to enable"
            ),
        },
    }


def _plural(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def _user_presentation(row: Any) -> dict[str, Any]:
    user = _row_to_dict(row)
    user["display_label"] = user_display_label(user)
    user["has_telegram_identity"] = user["telegram_id"] is not None
    return user


def _safe_user_audit_identity(user: dict[str, Any]) -> dict[str, object]:
    return {
        "user_id": int(user["id"]),
        "user_label": user_display_label(user),
        "telegram_id": user["telegram_id"],
    }


def _load_server_detail(settings: Settings, server_id: int) -> dict[str, Any]:
    with _open_repository(settings) as (repo, _conn):
        server = _row_to_dict(repo.get_server_for_admin(server_id))
        latest_health = repo.get_latest_server_health(server_id)
        server_actions = [
            _row_to_dict(row)
            for row in repo.list_admin_actions_for_server(server_id, limit=20)
        ]
        server_managed_configs = [
            _managed_config_view(row)
            for row in repo.list_active_devices_for_server(server_id)
        ]
    return {
        "server": server,
        "latest_health": (
            _row_to_dict(latest_health) if latest_health is not None else None
        ),
        "read_only_server_summary": _read_only_server_summary(
            server,
            _row_to_dict(latest_health) if latest_health is not None else None,
        ),
        "server_actions": server_actions,
        "server_managed_configs": server_managed_configs,
    }


def _load_vps_readiness(
    settings: Settings,
    *,
    server: dict[str, Any],
    latest_health: dict[str, Any] | None,
    peer_sync: dict[str, Any] | None,
) -> dict[str, Any]:
    config_path = Path(settings.server_config_path)
    checks = [
        {
            "label": "VPS_APPLY_ENABLED",
            "status": "enabled" if settings.vps_apply_enabled else "disabled",
            "status_class": "active" if settings.vps_apply_enabled else "disabled",
            "detail": (
                "live peer writes are enabled"
                if settings.vps_apply_enabled
                else "live peer writes are blocked"
            ),
        },
        {
            "label": "SERVER_CONFIG_PATH",
            "status": "configured",
            "status_class": "active",
            "detail": _display_setting_value(
                "SERVER_CONFIG_PATH",
                settings.server_config_path,
                is_path=True,
            ),
        },
    ]

    configured_server = None
    try:
        configured_server = select_server(
            load_server_config(config_path),
            str(server["name"]),
        )
    except ConfigError as exc:
        checks.append(
            {
                "label": "Configured server",
                "status": "error",
                "status_class": "failed",
                "detail": redact(str(exc)),
            }
        )
        checks.append(
            {
                "label": "Runtime",
                "status": "unavailable",
                "status_class": "disabled",
                "detail": "server config did not load",
            }
        )
    else:
        checks.append(
            {
                "label": "Configured server",
                "status": "found",
                "status_class": "active",
                "detail": (
                    f"{configured_server.name}; enabled={configured_server.enabled}; "
                    f"interface={configured_server.vpn.interface}; "
                    f"network={configured_server.vpn.network_cidr}"
                ),
            }
        )
        checks.append(
            {
                "label": "Runtime",
                "status": configured_server.runtime.type,
                "status_class": "active",
                "detail": _runtime_readiness_detail(configured_server),
            }
        )

    checks.append(_health_readiness(latest_health))
    checks.append(_peer_sync_readiness(peer_sync))
    return {"checks": checks}


def _read_only_server_summary(
    server: dict[str, Any],
    latest_health: dict[str, Any] | None,
) -> dict[str, Any]:
    if latest_health is None:
        latest_health_status = "not_checked"
        latest_latency_ms = None
        last_checked_at = "-"
        freshness = "not_checked"
    else:
        latest_health_status = str(latest_health["status"])
        latest_latency_ms = latest_health.get("latency_ms")
        last_checked_at = latest_health.get("checked_at") or "-"
        freshness = "fresh"
    return {
        "server_label": server["name"],
        "runtime_kind": server.get("runtime") or "unknown",
        "service_mode": "loopback-only",
        "latest_health_status": latest_health_status,
        "latest_latency_ms": latest_latency_ms,
        "last_checked_at": last_checked_at,
        "data_source": "cached_db",
        "freshness": freshness,
        "action_hint": (
            "read-only status; does not change VPS or peers; "
            "live check requires named gate"
        ),
    }


def _vps_retest_commands(settings: Settings, server: dict[str, Any]) -> list[str]:
    server_name = str(server["name"])
    return [
        "cd /home/amn2",
        "git pull origin codex-vps-test-prep",
        "source venv/bin/activate",
        "python -m pip install -e .",
        (
            "python -m app.cli server retest-plan "
            f"--config {settings.server_config_path} "
            f"--server {server_name} "
            f"--db {settings.database_path}"
        ),
        (
            "python -m app.cli server preflight "
            f"--config {settings.server_config_path} "
            f"--server {server_name} "
            f"--db {settings.database_path}"
        ),
        (
            "python -m app.cli server check "
            f"--config {settings.server_config_path} "
            f"--server {server_name}"
        ),
        (
            "python -m app.cli server sync-peers "
            f"--config {settings.server_config_path} "
            f"--server {server_name} "
            f"--db {settings.database_path}"
        ),
    ]


def _runtime_readiness_detail(server) -> str:
    parts = []
    if server.runtime.container_name:
        parts.append(f"container={server.runtime.container_name}")
    if server.runtime.service_name:
        parts.append(f"service={server.runtime.service_name}")
    if server.runtime.config_path:
        parts.append(f"config_path={server.runtime.config_path}")
    return "; ".join(parts) or "no runtime target configured"


def _health_readiness(latest_health: dict[str, Any] | None) -> dict[str, str]:
    if latest_health is None:
        return {
            "label": "Latest health",
            "status": "not run",
            "status_class": "disabled",
            "detail": "no stored health check",
        }
    latency = (
        f"{latest_health['latency_ms']} ms"
        if latest_health.get("latency_ms") is not None
        else "no latency"
    )
    error = str(latest_health.get("error") or "").strip()
    detail = f"{latency}; checked_at={latest_health.get('checked_at') or '-'}"
    if error:
        detail = f"{detail}; error={error}"
    return {
        "label": "Latest health",
        "status": str(latest_health["status"]),
        "status_class": str(latest_health["status"]),
        "detail": detail,
    }


def _peer_sync_readiness(peer_sync: dict[str, Any] | None) -> dict[str, str]:
    if peer_sync is None:
        return {
            "label": "Peer sync",
            "status": "not run",
            "status_class": "disabled",
            "detail": "not run in this browser session",
        }
    if peer_sync.get("error"):
        return {
            "label": "Peer sync",
            "status": "error",
            "status_class": "failed",
            "detail": redact(peer_sync["error"]),
        }
    unknown_count = int(peer_sync.get("unknown_count") or 0)
    missing_count = int(peer_sync.get("missing_count") or 0)
    needs_attention = unknown_count > 0 or missing_count > 0
    return {
        "label": "Peer sync",
        "status": "attention" if needs_attention else "ready",
        "status_class": "degraded" if needs_attention else "active",
        "detail": (
            f"known={peer_sync.get('known_count', 0)}; "
            f"unknown={unknown_count}; "
            f"missing={missing_count}; "
            f"amnezia_created={peer_sync.get('ignored_count', 0)}"
        ),
    }


def _collect_server_peer_sync(settings: Settings, server_id: int) -> dict[str, Any]:
    with _open_repository(settings) as (repo, _conn):
        server = _load_configured_server(settings, repo, server_id)
        report = PeerInventoryService(repo).compare(
            server_id,
            AwgDumpPeerInventoryCollector(
                interface=server.vpn.interface,
                container_name=server.runtime.container_name
                if server.runtime.type == "docker"
                else None,
                ssh_client=SystemSshClient(
                    server,
                    password=settings.vps_ssh_password or None,
                ),
            ),
        )
        ignored_keys = repo.list_ignored_remote_peer_keys(server_id)
        ignored_peers = [_row_to_dict(row) for row in repo.list_ignored_remote_peers(server_id)]
        observed_at = datetime.now(timezone.utc)
        snapshots = DriftDiagnosticsService(repo).diagnose_inventory(
            server_id,
            (*report.known_remote_peers, *report.unknown_remote_peers),
            observed_at=observed_at,
            now=observed_at,
        )
        reconciliation_snapshots = []
        for snapshot in snapshots:
            metadata = snapshot.safe_metadata()
            metadata["passport_device_id"] = None
            if snapshot.subject_id.startswith("device:"):
                local_device_id = int(snapshot.subject_id.split(":", 1)[1])
                passport = repo.get_device_passport_by_local_device_id(
                    local_device_id
                )
                if passport is not None:
                    metadata["passport_device_id"] = str(passport["device_id"])
            reconciliation_snapshots.append(metadata)
        known_peers = []
        for peer in report.known_remote_peers:
            device = repo.get_device_by_server_peer_public_key(
                server_id,
                peer.peer_public_key,
            )
            if device is None:
                continue
            user = repo.get_user(int(device["user_id"]))
            known_peers.append(
                {
                    "device_id": int(device["id"]),
                    "device_name": str(device["name"]),
                    "device_status": str(device["status"]),
                    "config_version": str(device["config_version"]),
                    "user_id": int(user["id"]),
                    "user_display": _format_sync_user_display(user),
                    "user_telegram_id": (
                        int(user["telegram_id"])
                        if user["telegram_id"] is not None
                        else None
                    ),
                    "peer_public_key": peer.peer_public_key,
                    "vpn_ip": str(device["vpn_ip"]),
                    "allowed_ips": peer.allowed_ips,
                }
            )
    unknown_peers = [
        peer
        for peer in report.unknown_remote_peers
        if peer.peer_public_key not in ignored_keys
    ]
    return {
        "known_count": len(report.known_remote_peers),
        "unknown_count": len(unknown_peers),
        "missing_count": len(report.missing_local_peers),
        "ignored_count": len(ignored_peers),
        "known_peers": known_peers,
        "unknown_peers": [
            {
                "peer_public_key": peer.peer_public_key,
                "allowed_ips": peer.allowed_ips,
            }
            for peer in unknown_peers
        ],
        "missing_peers": [
            {
                "device_id": peer.device_id,
                "device_name": peer.device_name,
                "peer_public_key": peer.peer_public_key,
                "vpn_ip": peer.vpn_ip,
            }
            for peer in report.missing_local_peers
        ],
        "ignored_peers": ignored_peers,
        "reconciliation_snapshots": reconciliation_snapshots,
        "error": "",
    }


def _empty_peer_sync_report(*, error: str) -> dict[str, Any]:
    return {
        "known_count": 0,
        "unknown_count": 0,
        "missing_count": 0,
        "ignored_count": 0,
        "known_peers": [],
        "unknown_peers": [],
        "missing_peers": [],
        "ignored_peers": [],
        "reconciliation_snapshots": [],
        "error": error,
    }


def _format_sync_user_display(user: Any) -> str:
    return user_display_label(user)


def _managed_config_view(row: Any) -> dict[str, Any]:
    return {
        "device_id": int(row["id"]),
        "device_name": str(row["name"]),
        "device_status": str(row["status"]),
        "config_version": str(row["config_version"]),
        "user_id": int(row["user_id"]),
        "user_display": _format_sync_user_display(row),
        "user_telegram_id": (
            int(row["telegram_id"])
            if row["telegram_id"] is not None
            else None
        ),
        "peer_public_key": str(row["peer_public_key"]),
        "vpn_ip": str(row["vpn_ip"]),
        "live_allowed_ips": "",
        "live_status": "not synced",
        "live_status_class": "pending",
    }


def _with_live_peer_sync_status(
    managed_configs: list[dict[str, Any]],
    peer_sync: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if peer_sync is None:
        return [dict(config) for config in managed_configs]
    if peer_sync.get("error"):
        return [
            {
                **config,
                "live_status": "sync error",
                "live_status_class": "disabled",
            }
            for config in managed_configs
        ]
    known_by_key = {
        str(peer["peer_public_key"]): peer
        for peer in peer_sync.get("known_peers", [])
    }
    missing_keys = {
        str(peer["peer_public_key"])
        for peer in peer_sync.get("missing_peers", [])
    }
    merged = []
    for config in managed_configs:
        peer_public_key = str(config["peer_public_key"])
        if peer_public_key in known_by_key:
            merged.append(
                {
                    **config,
                    "live_allowed_ips": str(known_by_key[peer_public_key]["allowed_ips"]),
                    "live_status": "confirmed live",
                    "live_status_class": "active",
                }
            )
        elif peer_public_key in missing_keys:
            merged.append(
                {
                    **config,
                    "live_status": "missing on server",
                    "live_status_class": "disabled",
                }
            )
        else:
            merged.append(
                {
                    **config,
                    "live_status": "not in last sync",
                    "live_status_class": "pending",
                }
            )
    return merged


def _remove_unknown_remote_peer(
    settings: Settings,
    server_id: int,
    peer_public_key: str,
) -> None:
    if not settings.vps_apply_enabled:
        raise ValueError("VPS_APPLY_ENABLED must be true before removing peers from VPN")
    with _open_repository(settings) as (repo, _conn):
        server = _load_configured_server(settings, repo, server_id)
    applier = ServerConfigPeerApplier(
        server,
        password=settings.vps_ssh_password or None,
    )
    applier.remove_peer(server=server, peer_public_key=peer_public_key)


def _add_missing_local_device_to_amnezia(
    settings: Settings,
    request: Request,
    *,
    server_id: int,
    device_id: int,
) -> None:
    with _open_repository(settings) as (repo, _conn):
        repo.get_server(server_id)
        device = _row_to_dict(repo.get_device(device_id))
    if int(device["server_id"]) != server_id:
        raise LookupError("Device not found")
    if str(device["status"]) not in {"pending", "active"}:
        raise ValueError("Only pending or active local devices can be added to Amnezia")

    with _open_repository(settings) as (repo, _conn):
        server_row = _row_to_dict(repo.get_server(server_id))
    device["server_name"] = server_row["name"]
    _apply_devices_to_vpn(settings, [device])

    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            repo.get_device(device_id)
            _record_web_server_action(
                repo,
                settings,
                request,
                action="web_server_missing_device_add",
                server_id=server_id,
                metadata={
                    "device_id": device_id,
                    "peer_public_key": device["peer_public_key"],
                    "vpn_ip": device["vpn_ip"],
                },
            )


def _refresh_peer_sync_after_missing_device_add(
    settings: Settings,
    *,
    server_id: int,
    device_id: int,
) -> dict[str, Any]:
    try:
        report = _collect_server_peer_sync(settings, server_id)
    except Exception as exc:
        report = _empty_peer_sync_report(error=redact(str(exc)))
    report["last_operation"] = {
        "title": "Added to Amnezia",
        "detail": f"Device #{device_id} was added to the VPS config.",
    }
    return report


def _load_configured_server(settings: Settings, repo: Repository, server_id: int):
    server_row = _row_to_dict(repo.get_server(server_id))
    config = load_server_config(Path(settings.server_config_path))
    return select_server(config, str(server_row["name"]))


def _load_peer_sync_from_session(request: Request, server_id: int) -> dict[str, Any] | None:
    raw = request.session.get(_peer_sync_session_key(server_id))
    if not isinstance(raw, str):
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _peer_sync_session_key(server_id: int) -> str:
    return f"server_peer_sync:{server_id}"


def _blank_user_form() -> dict[str, Any]:
    return {
        "telegram_id": "",
        "username": "",
        "first_name": "",
        "last_name": "",
        "email": "",
        "status": "active",
        "is_admin": 0,
    }


def _blank_server_form() -> dict[str, Any]:
    return {
        "name": "",
        "host": "",
        "ssh_port": 22,
        "endpoint_host": "",
        "vpn_port": 30001,
        "vpn_network_cidr": "10.8.0.0/24",
        "server_address": "10.8.0.1/24",
        "server_public_key": "",
        "runtime": "host_systemd",
        "firewall": "ufw",
        "status": "active",
        "max_devices": 254,
    }


def _user_payload(
    *,
    telegram_id: int,
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    status: str,
    is_admin: str | None,
) -> dict[str, Any]:
    if status not in USER_STATUSES:
        raise ValueError(f"unsupported user status: {status}")
    return {
        "telegram_id": telegram_id,
        "username": _optional_text(username),
        "first_name": _optional_text(first_name),
        "last_name": _optional_text(last_name),
        "email": _optional_text(email),
        "status": status,
        "is_admin": _is_checked(is_admin),
    }


def _server_payload(
    *,
    name: str,
    host: str,
    ssh_port: int,
    endpoint_host: str,
    vpn_port: int,
    vpn_network_cidr: str,
    server_address: str,
    server_public_key: str,
    runtime: str,
    firewall: str,
    status: str,
    max_devices: int,
) -> dict[str, Any]:
    _validate_port("ssh_port", ssh_port)
    _validate_port("vpn_port", vpn_port)
    if max_devices < 0:
        raise ValueError("max_devices must be non-negative")
    if status not in SERVER_STATUSES:
        raise ValueError(f"unsupported server status: {status}")
    return {
        "name": _required_text(name, "name"),
        "host": _required_text(host, "host"),
        "ssh_port": ssh_port,
        "endpoint_host": _required_text(endpoint_host, "endpoint_host"),
        "vpn_port": vpn_port,
        "vpn_network_cidr": _required_text(
            vpn_network_cidr,
            "vpn_network_cidr",
        ),
        "server_address": _required_text(server_address, "server_address"),
        "server_public_key": _optional_text(server_public_key) or "",
        "runtime": _required_text(runtime, "runtime"),
        "firewall": _required_text(firewall, "firewall"),
        "status": status,
        "max_devices": max_devices,
    }


def _required_text(value: str, field_name: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field_name} is required")
    return stripped


def _validate_port(field_name: str, value: int) -> None:
    if not 1 <= value <= 65535:
        raise ValueError(f"{field_name} must be in 1..65535")


def _optional_text(value: str) -> str | None:
    stripped = value.strip()
    return stripped or None


def _optional_positive_int(value: str, field_name: str) -> int | None:
    stripped = value.strip()
    if not stripped:
        return None
    try:
        parsed = int(stripped)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a positive integer or empty") from exc
    if parsed <= 0:
        raise ValueError(f"{field_name} must be a positive integer or empty")
    return parsed


def _is_checked(value: str | None) -> bool:
    return value is not None and value.lower() in {"1", "true", "yes", "on"}


def _set_user_status_with_action(
    settings: Settings,
    request: Request,
    *,
    user_id: int,
    status: str,
    action: str,
) -> None:
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            repo.get_user(user_id)
            repo.set_user_status_for_admin(user_id, status)
            _record_web_user_action(
                repo,
                settings,
                request,
                action=action,
                target_user_id=user_id,
                metadata={"status": status},
            )


def _disable_user_vpn(settings: Settings, request: Request, user_id: int) -> int:
    with _open_repository(settings) as (repo, _conn):
        user = _row_to_dict(repo.get_user(user_id))
        barrier = ProtocolIssuanceBarrierService(repo)
        block_plan = barrier.begin_block(user_id)
        devices = [_row_to_dict(row) for row in block_plan.devices]
        protocol_targets = ProtocolConfigLifecycleService(repo).disable_user(
            user_id=user_id,
            actor_id=_web_admin_actor_id(settings),
            reason="web_disable_vpn",
        )

    vps_apply = _revoke_devices_from_vpn(settings, devices)
    disabled_at = utc_now_iso()
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            disabled_count = repo.disable_user_devices(
                user_id,
                reason="web_disable_vpn",
                disabled_at=disabled_at,
            )
            barrier_complete = ProtocolIssuanceBarrierService(repo).complete_block(
                user_id,
                removed_local_device_ids=(
                    {int(device["id"]) for device in devices}
                    if vps_apply == "applied"
                    else set()
                ),
            )
            _record_web_user_action(
                repo,
                settings,
                request,
                action="web_user_disable_vpn",
                target_user_id=user_id,
                metadata={
                    **_safe_user_audit_identity(user),
                    "status": "blocked",
                    "device_ids": [int(device["id"]) for device in devices],
                    "device_names": [str(device["name"]) for device in devices],
                    "disabled_device_count": disabled_count,
                    "vps_apply": vps_apply,
                    "issuance_barrier": (
                        "blocked" if barrier_complete else "blocking"
                    ),
                    "protocol_targets": [
                        target.safe_metadata() for target in protocol_targets
                    ],
                },
            )
    return disabled_count


def _enable_user_vpn(settings: Settings, request: Request, user_id: int) -> int:
    with _open_repository(settings) as (repo, _conn):
        user = _row_to_dict(repo.get_user(user_id))
        ProtocolIssuanceBarrierService(repo).begin_enable(user_id)
        devices = [_row_to_dict(row) for row in repo.list_user_devices_for_vpn_enable(user_id)]

    _apply_devices_to_vpn(settings, devices)
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            enabled_count = ProtocolIssuanceBarrierService(repo).complete_enable(user_id)
            _record_web_user_action(
                repo,
                settings,
                request,
                action="web_user_enable_vpn",
                target_user_id=user_id,
                metadata={
                    **_safe_user_audit_identity(user),
                    "status": "active",
                    "device_ids": [int(device["id"]) for device in devices],
                    "device_names": [str(device["name"]) for device in devices],
                    "enabled_device_count": enabled_count,
                },
            )
    return enabled_count


def _delete_user_device(
    settings: Settings,
    request: Request,
    *,
    user_id: int,
    device_id: int,
) -> None:
    with _open_repository(settings) as (repo, _conn):
        user = _row_to_dict(repo.get_user(user_id))
        device_row = repo.get_user_device_for_admin(user_id=user_id, device_id=device_id)
        if device_row is None:
            raise LookupError("Device not found")
        device = _row_to_dict(device_row)

    with _open_repository(settings) as (repo, _conn):
        remote_required = str(device["status"]) in {"pending", "active"}
        peer_remover = (
            _SingleDeviceWebPeerRemover(settings, device)
            if remote_required and settings.vps_apply_enabled
            else None
        )

        def record_audit(metadata: dict[str, object]) -> None:
            _record_web_user_action(
                repo,
                settings,
                request,
                action="web_device_revoke_cascade",
                target_user_id=user_id,
                metadata={
                    **_safe_user_audit_identity(user),
                    "device_id": device_id,
                    "device_name": str(device["name"]),
                    **metadata,
                },
            )

        profile = repo.get_device_protocol_profile_by_local_device_id(device_id)
        if profile is None:
            cascade_revoke_physical_device(
                repo,
                local_device_id=device_id,
                reason="web_admin_physical_device_revoke",
                revoked_at=datetime.now(timezone.utc),
                peer_remover=peer_remover,
                apply_remote=remote_required and settings.vps_apply_enabled,
                audit_recorder=record_audit,
            )
        else:
            ProtocolConfigLifecycleService(repo).revoke_config(
                local_device_id=device_id,
                actor_id=_web_admin_actor_id(settings),
                reason="web_admin_protocol_config_revoke",
            )
            cascade_revoke_protocol_config(
                repo,
                local_device_id=device_id,
                reason="web_admin_protocol_config_revoke",
                revoked_at=datetime.now(timezone.utc),
                peer_remover=peer_remover,
                apply_remote=remote_required and settings.vps_apply_enabled,
                actor_kind="admin",
                actor_id=_web_admin_actor_id(settings),
                audit_recorder=record_audit,
            )


class _SingleDeviceWebPeerRemover:
    def __init__(self, settings: Settings, device: dict[str, Any]) -> None:
        self._settings = settings
        self._device = device

    def remove_peer(self, *, server, peer_public_key: str) -> None:
        _revoke_devices_from_vpn(self._settings, [self._device])


def _destroy_user(settings: Settings, request: Request, user_id: int) -> None:
    with _open_repository(settings) as (repo, _conn):
        user = _row_to_dict(repo.get_user(user_id))
        devices = [_row_to_dict(row) for row in repo.list_user_devices_for_vpn_removal(user_id)]

    vps_apply = _revoke_devices_from_vpn(settings, devices)
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            repo.hard_delete_user_for_admin(user_id)
            repo.record_admin_action(
                admin_telegram_id=_web_admin_actor_id(settings),
                action="web_user_destroy",
                metadata={
                    "source": "web_admin",
                    "web_admin_username": str(
                        request.session.get("web_admin_username", "")
                    ),
                    "deleted_user_id": user_id,
                    "telegram_id": user["telegram_id"],
                    "revoked_device_count": len(devices),
                    "vps_apply": vps_apply,
                },
            )


def _revoke_devices_from_vpn(settings: Settings, devices: list[dict[str, Any]]) -> str:
    if not devices:
        return "not_needed"
    if not settings.vps_apply_enabled:
        return "skipped"

    config = load_server_config(Path(settings.server_config_path))
    servers_by_name = {server.name: server for server in config.servers}
    appliers: dict[str, ServerConfigPeerApplier] = {}
    for device in devices:
        server_name = str(device["server_name"])
        server = servers_by_name.get(server_name)
        if server is None:
            available = ", ".join(sorted(servers_by_name)) or "<none>"
            raise ConfigError(
                f"Server '{server_name}' not found in {settings.server_config_path}. "
                f"Available: {available}"
            )
        applier = appliers.get(server_name)
        if applier is None:
            applier = ServerConfigPeerApplier(
                server,
                password=settings.vps_ssh_password or None,
            )
            appliers[server_name] = applier
        applier.remove_peer(
            server=server,
            peer_public_key=str(device["peer_public_key"]),
        )
    return "applied"


def _apply_devices_to_vpn(
    settings: Settings,
    devices: list[dict[str, Any]],
) -> None:
    if not devices:
        return
    if not settings.vps_apply_enabled:
        raise ValueError("VPS_APPLY_ENABLED must be true before adding peers to VPN")

    config = load_server_config(Path(settings.server_config_path))
    servers_by_name = {server.name: server for server in config.servers}
    appliers: dict[str, ServerConfigPeerApplier] = {}
    secret_box = SecretBox.from_app_secret(settings.app_secret_key)
    for device in devices:
        server_name = str(device["server_name"])
        server = servers_by_name.get(server_name)
        if server is None:
            available = ", ".join(sorted(servers_by_name)) or "<none>"
            raise ConfigError(
                f"Server '{server_name}' not found in {settings.server_config_path}. "
                f"Available: {available}"
            )
        applier = appliers.get(server_name)
        if applier is None:
            applier = ServerConfigPeerApplier(
                server,
                password=settings.vps_ssh_password or None,
            )
            appliers[server_name] = applier
        applier.apply_peer(
            server=server,
            peer_public_key=str(device["peer_public_key"]),
            preshared_key=secret_box.decrypt_text(str(device["preshared_key_encrypted"])),
            vpn_ip=str(device["vpn_ip"]),
        )


def _reveal_device_secrets(
    settings: Settings,
    request: Request,
    *,
    user_id: int,
    device_id: int,
) -> dict[str, str]:
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            device = repo.get_user_device(user_id=user_id, device_id=device_id)
            if device is None:
                raise LookupError("Device not found")
            if _device_config_material_status(device) != "available":
                raise ConfigMaterialUnavailable(
                    f"Config material is unavailable for device #{device_id}"
                )
            secret_box = SecretBox.from_app_secret(settings.app_secret_key)
            secrets = {
                "private_key": secret_box.decrypt_text(
                    str(device["peer_private_key_encrypted"])
                ),
                "preshared_key": secret_box.decrypt_text(
                    str(device["preshared_key_encrypted"])
                ),
            }
            _record_web_user_action(
                repo,
                settings,
                request,
                action="web_device_secret_reveal",
                target_user_id=user_id,
                target_device_id=device_id,
                metadata={"device_id": device_id},
            )
            return secrets


def _build_and_audit_passport_secret(
    settings: Settings,
    request: Request,
    *,
    passport_device_id: str,
    protocol_version: str | None,
):
    selected_protocol = "awg2" if protocol_version is None else protocol_version
    if selected_protocol not in {"awg2", "awg3"}:
        raise ConfigMaterialUnavailable("Unsupported device protocol profile")
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            passport = repo.get_device_passport(passport_device_id)
            if passport is None:
                raise LookupError("Device passport not found")
            profile = repo.get_device_protocol_profile(
                passport_device_id=passport_device_id,
                protocol_version=selected_protocol,
            )
            if profile is None or str(profile["lifecycle_state"]) != "active":
                raise ConfigMaterialUnavailable("Device protocol profile is unavailable")
            local_device_id = int(profile["local_device_id"])
            device = repo.get_device(local_device_id)
            if (
                device is None
                or int(device["user_id"]) != int(passport["owner_user_id"])
                or str(device["protocol_version"]) != selected_protocol
            ):
                raise ConfigMaterialUnavailable("Device protocol profile is unavailable")
            result = build_device_config_delivery(
                repo=repo,
                secret_box=SecretBox.from_app_secret(settings.app_secret_key),
                device=device,
                client_config_template_dir=settings.client_config_template_dir,
                client_config_defaults=settings.client_config_defaults,
            )
            repo.append_protocol_config_event(
                event_type="config_secret_viewed",
                actor_kind="admin",
                actor_id=_web_admin_actor_id(settings),
                reason="authenticated admin secret view",
                passport_device_id=passport_device_id,
                protocol_version=selected_protocol,
                local_device_id=local_device_id,
                metadata={
                    "passport_device_id": passport_device_id,
                    "local_device_id": local_device_id,
                },
            )
            return result.delivery


def _device_config_material_status(device: Any) -> str:
    try:
        return str(device["config_material_status"])
    except (KeyError, IndexError):
        return "available"


def _email_service(request: Request) -> EmailDeliveryService:
    settings = request.app.state.settings
    return EmailDeliveryService(
        sender=request.app.state.email_sender,
        from_address=settings.smtp_from,
        base_url=str(request.base_url),
        attach_config=settings.email_config_attachments_enabled,
    )


def _required_user_email(user: dict[str, Any]) -> str:
    email = str(user.get("email") or "").strip()
    if not email:
        raise ValueError("User email is required")
    return email


def _record_web_user_action(
    repo: Repository,
    settings: Settings,
    request: Request,
    *,
    action: str,
    target_user_id: int,
    target_device_id: int | None = None,
    metadata: dict[str, Any],
) -> None:
    full_metadata = {
        "source": "web_admin",
        "web_admin_username": str(request.session.get("web_admin_username", "")),
    }
    full_metadata.update(metadata)
    repo.record_admin_action(
        admin_telegram_id=_web_admin_actor_id(settings),
        action=action,
        target_user_id=target_user_id,
        target_device_id=target_device_id,
        metadata=full_metadata,
    )


def _record_web_server_action(
    repo: Repository,
    settings: Settings,
    request: Request,
    *,
    action: str,
    server_id: int,
    metadata: dict[str, Any],
) -> None:
    full_metadata = {
        "source": "web_admin",
        "web_admin_username": str(request.session.get("web_admin_username", "")),
        "server_id": server_id,
    }
    full_metadata.update(metadata)
    repo.record_admin_action(
        admin_telegram_id=_web_admin_actor_id(settings),
        action=action,
        metadata=full_metadata,
    )


def _record_web_plan_action(
    repo: Repository,
    settings: Settings,
    request: Request,
    *,
    action: str,
    plan_id: str,
    metadata: dict[str, Any],
) -> None:
    full_metadata = {
        "source": "web_admin",
        "web_admin_username": str(request.session.get("web_admin_username", "")),
        "plan_id": plan_id,
    }
    full_metadata.update(metadata)
    repo.record_admin_action(
        admin_telegram_id=_web_admin_actor_id(settings),
        action=action,
        metadata=full_metadata,
    )


def _record_web_api_token_action(
    repo: Repository,
    settings: Settings,
    request: Request,
    *,
    action: str,
    metadata: dict[str, Any],
) -> None:
    full_metadata = {
        "source": "web_admin",
        "web_admin_username": str(request.session.get("web_admin_username", "")),
    }
    full_metadata.update(metadata)
    repo.record_admin_action(
        admin_telegram_id=_web_admin_actor_id(settings),
        action=action,
        metadata=full_metadata,
    )


def _record_web_user_vps_failure(
    settings: Settings,
    request: Request,
    *,
    action: str,
    target_user_id: int,
    operation: str,
    exc: Exception,
    metadata: dict[str, Any],
    target_device_id: int | None = None,
) -> None:
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            _record_web_user_action(
                repo,
                settings,
                request,
                action=action,
                target_user_id=target_user_id,
                target_device_id=target_device_id,
                metadata=_failed_vps_metadata(
                    settings,
                    operation=operation,
                    exc=exc,
                    metadata=metadata,
                ),
            )


def _record_web_server_vps_failure(
    settings: Settings,
    request: Request,
    *,
    action: str,
    server_id: int,
    operation: str,
    exc: Exception,
    metadata: dict[str, Any],
) -> None:
    with _open_repository(settings) as (repo, _conn):
        with repo.transaction():
            repo.get_server(server_id)
            _record_web_server_action(
                repo,
                settings,
                request,
                action=action,
                server_id=server_id,
                metadata=_failed_vps_metadata(
                    settings,
                    operation=operation,
                    exc=exc,
                    metadata=metadata,
                ),
            )


def _failed_vps_metadata(
    settings: Settings,
    *,
    operation: str,
    exc: Exception,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    full_metadata = {
        "operation": operation,
        "error_type": type(exc).__name__,
        "redacted_error": redact(str(exc)),
        "vps_apply_enabled": settings.vps_apply_enabled,
    }
    full_metadata.update(metadata)
    return full_metadata


def _record_health_summary(
    repo: Repository,
    server_id: int,
    summary: HealthSummary,
) -> int:
    return repo.record_server_health(
        server_id=server_id,
        status=summary.status,
        latency_ms=summary.latency_ms,
        ssh_ok=summary.ssh_ok,
        awg_ok=summary.awg_ok,
        udp_port_ok=summary.udp_port_ok,
        error=summary.error,
    )


def _web_admin_actor_id(settings: Settings) -> int:
    return settings.admin_ids[0] if settings.admin_ids else 0


def _count_rows(conn: Any, query: str) -> int:
    row = conn.execute(query).fetchone()
    return int(row["count"])


def _row_to_dict(row: Any) -> dict[str, Any]:
    return dict(row)


def _plural_ru(count: int, one: str, few: str, many: str) -> str:
    noun = _plural_ru_word(count, one, few, many)
    return f"{count} {noun}"


def _plural_ru_word(count: int, one: str, few: str, many: str) -> str:
    if count % 10 == 1 and count % 100 != 11:
        return one
    elif 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many
