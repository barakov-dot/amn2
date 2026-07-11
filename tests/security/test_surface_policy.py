import pytest

from app.agent.policy import AGENT_ROUTE_POLICIES, first_slice_policies
from app.security.surface_policy import (
    SURFACE_POLICIES,
    get_surface_policy,
    policies_by_surface,
)


REQUIRED_POLICY_IDS = {
    "local_agent.health",
    "local_agent.version",
    "local_agent.runtime",
    "local_agent.protocols",
    "local_agent.configs.read.blocked",
    "web.auth.login_submit",
    "web.auth.logout",
    "web.config_templates.save",
    "web.config_templates.reset",
    "web.integration_status.index",
    "web.api_tokens.index",
    "web.api_tokens.issue",
    "web.api_tokens.rotate",
    "web.api_tokens.revoke",
    "web.users.create",
    "web.plans.device_quota_update",
    "web.users.update",
    "web.users.block",
    "web.users.delete",
    "web.users.disable_vpn",
    "web.users.enable_vpn",
    "web.devices.create_operator",
    "web.devices.secrets",
    "web.devices.delete",
    "web.users.destroy",
    "public_token.email_verify_submit",
    "web.email.config_send",
    "web.email.recovery_start",
    "public_token.email_recover_submit",
    "web.servers.create",
    "web.servers.update",
    "web.servers.disable",
    "web.servers.sync_run",
    "web.servers.unknown_peers.ignore",
    "web.servers.unknown_peers.remove",
    "web.servers.missing_devices.add",
    "web.servers.health_run",
    "bot.admin.approve_order",
    "bot.admin.integrations",
    "bot.admin.status",
    "bot.admin.servers",
    "bot.admin.traffic",
    "bot.admin.config_resend",
    "bot.user.config_resend",
    "bot.user.device_revoke",
    "bot.user.devices_reset",
    "remote.server.health_check",
    "cli.server.apply_peer_live",
    "cli.server.revoke_peer_live",
    "api.servers.list",
    "api.servers.summary",
    "api.integration.status",
    "api.local_agent.runtime_summary",
    "api.metrics.summary",
    "api.users.summary",
    "self_service.dashboard.blocked",
    "self_service.config_delivery.blocked",
    "self_service.device_revoke.blocked",
    "api.payments.webhook.blocked",
    "api.entitlements.activate.blocked",
    "api.entitlements.manual_review.blocked",
    "api.config_links.issue.blocked",
    "public_token.config_link.redeem.blocked",
    "bot.support.runtime.blocked",
    "bot.news.runtime.blocked",
    "bot.access.profile_icon.apply.blocked",
    "bot.support.profile_icon.apply.blocked",
    "bot.news.profile_icon.apply.blocked",
    "api.health.polling.run.blocked",
    "api.analytics.users.detail.blocked",
    "api.analytics.peers.detail.blocked",
}
API_ROUTE_SHELL_POLICY_IDS = {
    "api.servers.list",
    "api.servers.summary",
    "api.integration.status",
    "api.local_agent.runtime_summary",
    "api.metrics.summary",
    "api.users.summary",
}
P7_WRITE_CONTOUR_POLICY_IDS = {
    "api.install.mutation_requests",
}
PHASE10_PLAN_QUOTA_WRITE_CONTOUR_POLICY_IDS = {
    "web.plans.device_quota_update",
}

SECRET_RISKS = {"secret-read", "public-token-secret-read"}
PUBLIC_TOKEN_RISKS = {
    "public-token-entry",
    "public-token-state-write",
    "public-token-secret-read",
}
REMOTE_RISKS = {"remote-read", "remote-exec"}
VPS_WRITE_POLICY_IDS = {
    "web.users.disable_vpn",
    "web.users.enable_vpn",
    "web.devices.create_operator",
    "web.devices.delete",
    "web.users.destroy",
    "web.servers.sync_run",
    "web.servers.unknown_peers.remove",
    "web.servers.missing_devices.add",
    "bot.admin.approve_order",
    "bot.user.device_revoke",
    "bot.user.devices_reset",
    "cli.server.apply_peer_live",
    "cli.server.revoke_peer_live",
}


def _gate_text(policy):
    return " ".join(policy.gates).lower()


def test_required_policy_ids_exist():
    actual = {policy.policy_id for policy in SURFACE_POLICIES}

    assert REQUIRED_POLICY_IDS <= actual


def test_policy_ids_are_unique():
    policy_ids = [policy.policy_id for policy in SURFACE_POLICIES]

    assert len(policy_ids) == len(set(policy_ids))


@pytest.mark.parametrize(
    "surface",
    (
        "web",
        "public-token",
        "self-service",
        "bot",
        "local-agent",
        "cli",
        "remote-operation",
        "api",
    ),
)
def test_each_surface_has_policy_entries(surface):
    assert policies_by_surface(surface)


def test_enabled_behavior_is_limited_to_approved_product_contours():
    enabled = {
        policy.policy_id
        for policy in SURFACE_POLICIES
        if policy.enables_new_behavior is True
    }

    assert enabled == (
        API_ROUTE_SHELL_POLICY_IDS
        | P7_WRITE_CONTOUR_POLICY_IDS
        | PHASE10_PLAN_QUOTA_WRITE_CONTOUR_POLICY_IDS
    )


def test_local_agent_first_slice_matches_existing_agent_policy():
    expected = {
        (policy.method, policy.path, policy.scope)
        for policy in first_slice_policies()
    }
    actual = {
        (policy.method, policy.path, policy.auth_method.split()[-1])
        for policy in policies_by_surface("local-agent")
        if policy.implementation_mode == "inventory-only"
    }

    assert actual == expected


def test_future_local_agent_routes_are_recorded_as_blocked_future():
    future_agent_routes = {
        (policy.method, policy.path)
        for policy in AGENT_ROUTE_POLICIES
        if not policy.first_slice
    }
    blocked_surface_routes = {
        (policy.method, policy.path)
        for policy in policies_by_surface("local-agent")
        if policy.implementation_mode == "blocked-future"
    }

    assert future_agent_routes <= blocked_surface_routes


def test_secret_and_public_token_policies_have_required_gates():
    for policy in SURFACE_POLICIES:
        gates = _gate_text(policy)
        if policy.risk_class in SECRET_RISKS:
            assert policy.audit_required is True, policy.policy_id
            assert "redaction" in gates or "no raw secret" in gates, policy.policy_id
        if policy.risk_class in PUBLIC_TOKEN_RISKS:
            assert "no raw token" in gates, policy.policy_id
        if policy.risk_class == "public-token-secret-read":
            assert "purpose" in gates, policy.policy_id
            assert "ttl" in gates, policy.policy_id
            assert "one-time" in gates, policy.policy_id
            assert policy.audit_required is True, policy.policy_id


def test_web_admin_post_policies_require_csrf():
    for policy in policies_by_surface("web"):
        if policy.method == "POST":
            assert "csrf" in _gate_text(policy), policy.policy_id


def test_remote_operation_policies_are_bound_to_operation_contracts():
    for policy in SURFACE_POLICIES:
        if policy.risk_class in REMOTE_RISKS:
            assert policy.operation_contract, policy.policy_id
        if policy.risk_class == "remote-read":
            assert "read-only command policy" in _gate_text(policy), policy.policy_id
        if policy.risk_class == "remote-exec":
            assert policy.live_retest_required is True, policy.policy_id


def test_live_retest_is_marked_for_vps_write_surfaces():
    for policy_id in VPS_WRITE_POLICY_IDS:
        policy = get_surface_policy(policy_id)

        assert policy.live_retest_required is True


def test_api_route_shell_policies_are_read_only_scoped_and_no_live_retest():
    expected_scopes = {
        "api.servers.list": "server:read",
        "api.servers.summary": "server:read",
        "api.integration.status": "server:read",
        "api.local_agent.runtime_summary": "server:read",
        "api.metrics.summary": "metrics:read",
        "api.users.summary": "metrics:read",
    }

    for policy_id, scope in expected_scopes.items():
        policy = get_surface_policy(policy_id)

        assert policy.surface == "api"
        assert policy.risk_class == "read-only"
        assert policy.secret_class == "none"
        assert scope in policy.auth_method
        assert policy.side_effects == ()
        assert policy.audit_required is True
        assert policy.live_retest_required is False
        assert policy.implementation_mode == "implemented"
        assert "aggregate-only" in _gate_text(policy)
        assert "no raw secret" in _gate_text(policy)


def test_p7_install_write_route_is_scoped_audited_and_not_remote_exec():
    policy = get_surface_policy("api.install.mutation_requests")

    assert policy.surface == "api"
    assert policy.risk_class == "state-write"
    assert policy.secret_class == "none"
    assert "install:write" in policy.auth_method
    assert policy.audit_required is True
    assert policy.live_retest_required is True
    assert policy.implementation_mode == "implemented"
    assert "p7-c005" in _gate_text(policy)
    assert "no remote exec" in _gate_text(policy)
    assert "no config delivery" in _gate_text(policy)
    assert "no raw secret" in _gate_text(policy)


def test_productization_future_surfaces_remain_blocked_until_named_gates():
    payment = get_surface_policy("api.payments.webhook.blocked")
    entitlement = get_surface_policy("api.entitlements.activate.blocked")
    manual_review = get_surface_policy("api.entitlements.manual_review.blocked")
    support_bot = get_surface_policy("bot.support.runtime.blocked")
    news_bot = get_surface_policy("bot.news.runtime.blocked")

    assert payment.implementation_mode == "blocked-future"
    assert payment.enables_new_behavior is False
    assert "payment processor gate" in _gate_text(payment)
    assert entitlement.implementation_mode == "blocked-future"
    assert entitlement.live_retest_required is True
    assert "config delivery stays blocked" in _gate_text(entitlement)
    assert manual_review.implementation_mode == "blocked-future"
    assert manual_review.live_retest_required is True
    assert "p6-i006" in _gate_text(manual_review)
    assert "manual review" in _gate_text(manual_review)
    assert "no automatic activation" in _gate_text(manual_review)
    assert support_bot.implementation_mode == "blocked-future"
    assert "separate telegram token" in _gate_text(support_bot)
    assert "no config output" in _gate_text(support_bot)
    assert news_bot.implementation_mode == "blocked-future"
    assert "broadcast gate" in _gate_text(news_bot)
    assert "no user/device state" in _gate_text(news_bot)


def test_config_link_surfaces_are_tokenized_and_blocked_until_p6_c002():
    issue = get_surface_policy("api.config_links.issue.blocked")
    redeem = get_surface_policy("public_token.config_link.redeem.blocked")

    assert issue.surface == "api"
    assert issue.method == "POST"
    assert issue.implementation_mode == "blocked-future"
    assert issue.enables_new_behavior is False
    assert issue.secret_class == "token-raw-issue"
    assert "p6-c002" in _gate_text(issue)
    assert "hash-at-rest" in _gate_text(issue)
    assert "no raw token" in _gate_text(issue)

    assert redeem.surface == "public-token"
    assert redeem.method == "GET"
    assert redeem.risk_class == "public-token-secret-read"
    assert redeem.secret_class == "client-config-secret"
    assert redeem.implementation_mode == "blocked-future"
    assert redeem.enables_new_behavior is False
    assert redeem.audit_required is True
    assert redeem.live_retest_required is True
    assert "p6-c002" in _gate_text(redeem)
    assert "purpose" in _gate_text(redeem)
    assert "ttl" in _gate_text(redeem)
    assert "one-time" in _gate_text(redeem)
    assert "redaction" in _gate_text(redeem)
    assert "no raw token" in _gate_text(redeem)


def test_telegram_profile_icon_apply_surfaces_are_identity_mutation_gated():
    for policy_id in (
        "bot.access.profile_icon.apply.blocked",
        "bot.support.profile_icon.apply.blocked",
        "bot.news.profile_icon.apply.blocked",
    ):
        policy = get_surface_policy(policy_id)
        gates = _gate_text(policy)

        assert policy.surface == "bot"
        assert policy.risk_class == "state-write"
        assert policy.secret_class == "token-raw-issue"
        assert policy.implementation_mode == "blocked-future"
        assert policy.enables_new_behavior is False
        assert policy.live_retest_required is True
        assert "p6-i005" in gates
        assert "telegram identity mutation gate" in gates
        assert "operator approval" in gates
        assert "no live bot send" in gates


def test_privacy_status_future_surfaces_remain_aggregate_only_gated():
    polling = get_surface_policy("api.health.polling.run.blocked")
    user_detail = get_surface_policy("api.analytics.users.detail.blocked")
    peer_detail = get_surface_policy("api.analytics.peers.detail.blocked")

    assert polling.implementation_mode == "blocked-future"
    assert polling.risk_class == "remote-read"
    assert polling.live_retest_required is True
    assert "p6-m002" in _gate_text(polling)
    assert "live probe gate" in _gate_text(polling)
    assert "no raw command output" in _gate_text(polling)
    for policy in (user_detail, peer_detail):
        gates = _gate_text(policy)
        assert policy.implementation_mode == "blocked-future"
        assert policy.risk_class == "secret-adjacent-read"
        assert policy.enables_new_behavior is False
        assert "p6-n002" in gates
        assert "aggregate-only" in gates
        assert "no per-user" in gates or "no per-peer" in gates


def test_self_service_surface_is_separate_from_admin_and_blocked_future():
    policies = policies_by_surface("self-service")

    assert {policy.policy_id for policy in policies} == {
        "self_service.dashboard.blocked",
        "self_service.config_delivery.blocked",
        "self_service.device_revoke.blocked",
    }
    for policy in policies:
        gates = _gate_text(policy)

        assert policy.path.startswith("/self-service"), policy.policy_id
        assert policy.actor == "self-service-user", policy.policy_id
        assert "web-admin" not in policy.auth_method, policy.policy_id
        assert "session" not in policy.auth_method, policy.policy_id
        assert "separate self-service auth" in policy.auth_method, policy.policy_id
        assert policy.implementation_mode == "blocked-future", policy.policy_id
        assert policy.enables_new_behavior is False, policy.policy_id
        assert "P6-C001" in policy.gates, policy.policy_id
        assert "admin surface separated" in gates, policy.policy_id
