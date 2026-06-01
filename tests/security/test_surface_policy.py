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
    "web.users.create",
    "web.users.update",
    "web.users.block",
    "web.users.delete",
    "web.users.disable_vpn",
    "web.users.enable_vpn",
    "web.devices.secrets",
    "web.devices.delete",
    "web.users.destroy",
    "public_token.email_verify_submit",
    "web.email.config_send",
    "web.email.recovery_start",
    "public_token.email_recover_submit",
    "self.device.config_download.blocked",
    "public_token.config_share_download.blocked",
    "web.servers.create",
    "web.servers.update",
    "web.servers.disable",
    "web.servers.sync_run",
    "web.servers.unknown_peers.ignore",
    "web.servers.unknown_peers.remove",
    "web.servers.missing_devices.add",
    "web.servers.health_run",
    "bot.admin.approve_order",
    "bot.admin.config_resend",
    "bot.user.config_resend",
    "bot.user.device_revoke",
    "bot.user.devices_reset",
    "remote.server.health_check",
    "cli.server.apply_peer_live",
    "cli.server.revoke_peer_live",
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
    ("web", "public-token", "bot", "local-agent", "cli", "remote-operation"),
)
def test_each_surface_has_policy_entries(surface):
    assert policies_by_surface(surface)


def test_no_policy_enables_new_behavior_in_first_slice():
    assert all(policy.enables_new_behavior is False for policy in SURFACE_POLICIES)


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


def test_future_config_download_policies_remain_blocked_without_routes():
    for policy_id in (
        "self.device.config_download.blocked",
        "public_token.config_share_download.blocked",
        "local_agent.configs.read.blocked",
    ):
        policy = get_surface_policy(policy_id)
        gates = _gate_text(policy)

        assert policy.implementation_mode == "blocked-future"
        assert policy.enables_new_behavior is False
        assert policy.live_retest_required is False
        assert policy.secret_class == "client-config-secret"
        assert policy.audit_required is True
        assert "redaction" in gates
        assert "no raw secret" in gates

    share_policy = get_surface_policy("public_token.config_share_download.blocked")
    share_gates = _gate_text(share_policy)
    assert share_policy.risk_class == "public-token-secret-read"
    assert "hash lookup" in share_gates
    assert "ttl" in share_gates
    assert "one-time" in share_gates
    assert "resource binding" in share_gates
    assert "rate limit" in share_gates


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
