from __future__ import annotations

from dataclasses import dataclass

from app.security.surface_policy import SurfaceName


@dataclass(frozen=True)
class SurfaceBinding:
    surface: SurfaceName
    method: str
    path: str
    source: str
    policy_id: str | None = None
    exemption_reason: str = ""


READ_ONLY_WEB_VIEW = (
    "Read-only web view covered by existing session-auth web tests; "
    "state changes remain policy-backed POST routes."
)
PUBLIC_TOKEN_FORM_VIEW = (
    "Public token form render only; token-consuming submit route remains policy-backed."
)


def _binding(
    surface: SurfaceName,
    method: str,
    path: str,
    *,
    source: str,
    policy_id: str | None = None,
    exemption_reason: str = "",
) -> SurfaceBinding:
    return SurfaceBinding(
        surface=surface,
        method=method,
        path=path,
        source=source,
        policy_id=policy_id,
        exemption_reason=exemption_reason,
    )


WEB_RUNTIME_ROUTE_BINDINGS: tuple[SurfaceBinding, ...] = (
    _binding(
        "web",
        "GET",
        "/login",
        source="app.web.app:create_web_app",
        exemption_reason="Login form render only; POST /login owns auth-entry policy.",
    ),
    _binding(
        "web",
        "POST",
        "/login",
        source="app.web.app:create_web_app",
        policy_id="web.auth.login_submit",
    ),
    _binding(
        "web",
        "GET",
        "/",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/about",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/orders",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/plans",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "POST",
        "/plans/{plan_id}/device-quota",
        source="app.web.app:create_web_app",
        policy_id="web.plans.device_quota_update",
    ),
    _binding(
        "web",
        "GET",
        "/logs",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/settings",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/config-templates",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/api-readiness",
        source="app.web.app:create_web_app",
        policy_id="web.api_readiness.index",
    ),
    _binding(
        "web",
        "GET",
        "/integration-status",
        source="app.web.app:create_web_app",
        policy_id="web.integration_status.index",
    ),
    _binding(
        "web",
        "GET",
        "/api-tokens",
        source="app.web.app:create_web_app",
        policy_id="web.api_tokens.index",
    ),
    _binding(
        "web",
        "POST",
        "/api-tokens/issue",
        source="app.web.app:create_web_app",
        policy_id="web.api_tokens.issue",
    ),
    _binding(
        "web",
        "POST",
        "/api-tokens/{token_id}/rotate",
        source="app.web.app:create_web_app",
        policy_id="web.api_tokens.rotate",
    ),
    _binding(
        "web",
        "POST",
        "/api-tokens/{token_id}/revoke",
        source="app.web.app:create_web_app",
        policy_id="web.api_tokens.revoke",
    ),
    _binding(
        "web",
        "POST",
        "/config-templates/{config_version}/save",
        source="app.web.app:create_web_app",
        policy_id="web.config_templates.save",
    ),
    _binding(
        "web",
        "POST",
        "/config-templates/{config_version}/reset",
        source="app.web.app:create_web_app",
        policy_id="web.config_templates.reset",
    ),
    _binding(
        "web",
        "GET",
        "/device-passports",
        source="app.web.app:create_web_app",
        policy_id="web.device_passports.index",
    ),
    _binding(
        "web",
        "GET",
        "/device-passports/{device_id}",
        source="app.web.app:create_web_app",
        policy_id="web.device_passports.detail",
    ),
    _binding(
        "web",
        "GET",
        "/device-passports/{device_id}/config",
        source="app.web.app:create_web_app",
        policy_id="web.device_passports.config_secret",
    ),
    _binding(
        "web",
        "GET",
        "/device-passports/{device_id}/qr",
        source="app.web.app:create_web_app",
        policy_id="web.device_passports.qr_secret",
    ),
    _binding(
        "web",
        "GET",
        "/users",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/devices/disabled",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/users/new",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "POST",
        "/users/new",
        source="app.web.app:create_web_app",
        policy_id="web.users.create",
    ),
    _binding(
        "web",
        "GET",
        "/users/{user_id}",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/email/verify/start",
        source="app.web.app:create_web_app",
        policy_id="web.email.verify_start",
    ),
    _binding(
        "public-token",
        "GET",
        "/email/verify",
        source="app.web.app:create_web_app",
        exemption_reason=PUBLIC_TOKEN_FORM_VIEW,
    ),
    _binding(
        "public-token",
        "POST",
        "/email/verify",
        source="app.web.app:create_web_app",
        policy_id="public_token.email_verify_submit",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/devices/{device_id}/email-config",
        source="app.web.app:create_web_app",
        policy_id="web.email.config_send",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/devices/{device_id}/email-recovery/start",
        source="app.web.app:create_web_app",
        policy_id="web.email.recovery_start",
    ),
    _binding(
        "public-token",
        "GET",
        "/email/recover",
        source="app.web.app:create_web_app",
        exemption_reason=PUBLIC_TOKEN_FORM_VIEW,
    ),
    _binding(
        "public-token",
        "POST",
        "/email/recover",
        source="app.web.app:create_web_app",
        policy_id="public_token.email_recover_submit",
    ),
    _binding(
        "web",
        "GET",
        "/users/{user_id}/edit",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/edit",
        source="app.web.app:create_web_app",
        policy_id="web.users.update",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/block",
        source="app.web.app:create_web_app",
        policy_id="web.users.block",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/delete",
        source="app.web.app:create_web_app",
        policy_id="web.users.delete",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/disable-vpn",
        source="app.web.app:create_web_app",
        policy_id="web.users.disable_vpn",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/enable-vpn",
        source="app.web.app:create_web_app",
        policy_id="web.users.enable_vpn",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/devices/create-operator",
        source="app.web.app:create_web_app",
        policy_id="web.devices.create_operator",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/devices/{device_id}/secrets",
        source="app.web.app:create_web_app",
        policy_id="web.devices.secrets",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/devices/{device_id}/delete",
        source="app.web.app:create_web_app",
        policy_id="web.devices.delete",
    ),
    _binding(
        "web",
        "POST",
        "/users/{user_id}/destroy",
        source="app.web.app:create_web_app",
        policy_id="web.users.destroy",
    ),
    _binding(
        "web",
        "GET",
        "/servers",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "GET",
        "/servers/new",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "POST",
        "/servers/new",
        source="app.web.app:create_web_app",
        policy_id="web.servers.create",
    ),
    _binding(
        "web",
        "GET",
        "/servers/{server_id}",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/sync/run",
        source="app.web.app:create_web_app",
        policy_id="web.servers.sync_run",
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/unknown-peers/ignore",
        source="app.web.app:create_web_app",
        policy_id="web.servers.unknown_peers.ignore",
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/amnezia-peers/unmark",
        source="app.web.app:create_web_app",
        policy_id="web.servers.amnezia_peers.unmark",
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/unknown-peers/remove",
        source="app.web.app:create_web_app",
        policy_id="web.servers.unknown_peers.remove",
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/missing-devices/{device_id}/add",
        source="app.web.app:create_web_app",
        policy_id="web.servers.missing_devices.add",
    ),
    _binding(
        "web",
        "GET",
        "/servers/{server_id}/edit",
        source="app.web.app:create_web_app",
        exemption_reason=READ_ONLY_WEB_VIEW,
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/edit",
        source="app.web.app:create_web_app",
        policy_id="web.servers.update",
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/disable",
        source="app.web.app:create_web_app",
        policy_id="web.servers.disable",
    ),
    _binding(
        "web",
        "GET",
        "/servers/{server_id}/health",
        source="app.web.app:create_web_app",
        exemption_reason="Latest persisted health view; POST /health/run owns remote-read policy.",
    ),
    _binding(
        "web",
        "POST",
        "/servers/{server_id}/health/run",
        source="app.web.app:create_web_app",
        policy_id="web.servers.health_run",
    ),
    _binding(
        "web",
        "POST",
        "/logout",
        source="app.web.app:create_web_app",
        policy_id="web.auth.logout",
    ),
)

LOCAL_AGENT_RUNTIME_ROUTE_BINDINGS: tuple[SurfaceBinding, ...] = (
    _binding(
        "local-agent",
        "GET",
        "/agent/health",
        source="app.agent.api:create_agent_app",
        policy_id="local_agent.health",
    ),
    _binding(
        "local-agent",
        "GET",
        "/agent/version",
        source="app.agent.api:create_agent_app",
        policy_id="local_agent.version",
    ),
    _binding(
        "local-agent",
        "GET",
        "/agent/runtime",
        source="app.agent.api:create_agent_app",
        policy_id="local_agent.runtime",
    ),
    _binding(
        "local-agent",
        "GET",
        "/agent/protocols",
        source="app.agent.api:create_agent_app",
        policy_id="local_agent.protocols",
    ),
)

BOT_ACTION_BINDINGS: tuple[SurfaceBinding, ...] = (
    _binding(
        "bot",
        "ACTION",
        "ADMIN_INTEGRATIONS_CALLBACK",
        source="app.bot.main",
        policy_id="bot.admin.integrations",
    ),
    _binding(
        "bot",
        "ACTION",
        "ADMIN_STATUS_CALLBACK",
        source="app.bot.main",
        policy_id="bot.admin.status",
    ),
    _binding(
        "bot",
        "ACTION",
        "ADMIN_SERVERS_CALLBACK",
        source="app.bot.main",
        policy_id="bot.admin.servers",
    ),
    _binding(
        "bot",
        "ACTION",
        "ADMIN_TRAFFIC_CALLBACK",
        source="app.bot.main",
        policy_id="bot.admin.traffic",
    ),
    _binding(
        "bot",
        "ACTION",
        "ADMIN_APPROVE_PREFIX callback",
        source="app.bot.main",
        policy_id="bot.admin.approve_order",
    ),
    _binding(
        "bot",
        "ACTION",
        "ADMIN_RESEND_PREFIX callback",
        source="app.bot.main",
        policy_id="bot.admin.config_resend",
    ),
    _binding(
        "bot",
        "ACTION",
        "USER_RESEND_PREFIX callback",
        source="app.bot.main",
        policy_id="bot.user.config_resend",
    ),
    _binding(
        "bot",
        "ACTION",
        "USER_REVOKE_CONFIRM_PREFIX callback",
        source="app.bot.main",
        policy_id="bot.user.device_revoke",
    ),
    _binding(
        "bot",
        "ACTION",
        "USER_RESET_DEVICES_CONFIRM_CALLBACK",
        source="app.bot.main",
        policy_id="bot.user.devices_reset",
    ),
)

OPERATION_BINDINGS: tuple[SurfaceBinding, ...] = (
    _binding(
        "remote-operation",
        "OPERATION",
        "server.health.check",
        source="app.server.checks",
        policy_id="remote.server.health_check",
    ),
    _binding(
        "cli",
        "COMMAND",
        "server apply-peer --apply",
        source="app.cli",
        policy_id="cli.server.apply_peer_live",
    ),
    _binding(
        "cli",
        "COMMAND",
        "server revoke-peer --apply",
        source="app.cli",
        policy_id="cli.server.revoke_peer_live",
    ),
)

SURFACE_BINDINGS: tuple[SurfaceBinding, ...] = (
    *WEB_RUNTIME_ROUTE_BINDINGS,
    *LOCAL_AGENT_RUNTIME_ROUTE_BINDINGS,
    *BOT_ACTION_BINDINGS,
    *OPERATION_BINDINGS,
)


def policy_backed_bindings() -> tuple[SurfaceBinding, ...]:
    return tuple(binding for binding in SURFACE_BINDINGS if binding.policy_id is not None)


def bindings_by_surface(surface: SurfaceName) -> tuple[SurfaceBinding, ...]:
    return tuple(binding for binding in SURFACE_BINDINGS if binding.surface == surface)
