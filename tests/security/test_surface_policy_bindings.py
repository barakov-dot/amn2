from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.routing import APIRoute

from app.agent.api import create_agent_app
from app.agent.auth import AgentToken, hash_agent_token
from app.agent.runtime import (
    FakeLocalRuntimeAdapter,
    ProtocolSnapshot,
    RuntimeSnapshot,
)
from app.config.settings import Settings
from app.security.surface_bindings import (
    WEB_RUNTIME_ROUTE_BINDINGS,
    policy_backed_bindings,
)
from app.security.surface_policy import SURFACE_POLICIES, get_surface_policy
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_policy_backed_bindings_match_surface_policies():
    for binding in policy_backed_bindings():
        policy = get_surface_policy(binding.policy_id)

        assert binding.surface == policy.surface
        assert binding.method == policy.method
        assert binding.path == policy.path


def test_web_runtime_routes_are_bound_or_exempted(tmp_path: Path):
    actual_routes = _route_keys(create_web_app(_settings(tmp_path)))
    bindings = _binding_map(WEB_RUNTIME_ROUTE_BINDINGS)

    assert actual_routes == set(bindings)
    assert [
        binding
        for binding in WEB_RUNTIME_ROUTE_BINDINGS
        if binding.policy_id is None and not binding.exemption_reason
    ] == []


def test_web_post_runtime_routes_have_policy_bindings(tmp_path: Path):
    actual_post_routes = {
        route for route in _route_keys(create_web_app(_settings(tmp_path))) if route[0] == "POST"
    }
    bindings = _binding_map(WEB_RUNTIME_ROUTE_BINDINGS)

    missing_policy = [
        bindings[route]
        for route in sorted(actual_post_routes)
        if bindings[route].policy_id is None
    ]

    assert missing_policy == []


def test_local_agent_runtime_routes_match_inventory_bindings():
    app = _agent_app()
    actual_routes = _route_keys(app)
    inventory_agent_routes = {
        (policy.method, policy.path)
        for policy in SURFACE_POLICIES
        if policy.surface == "local-agent"
        and policy.implementation_mode == "inventory-only"
    }

    assert actual_routes == inventory_agent_routes


def test_blocked_future_local_agent_routes_are_not_mounted():
    actual_routes = _route_keys(_agent_app())
    blocked_routes = {
        (policy.method, policy.path)
        for policy in SURFACE_POLICIES
        if policy.surface == "local-agent"
        and policy.implementation_mode == "blocked-future"
    }

    assert actual_routes.isdisjoint(blocked_routes)


def test_secret_and_destructive_future_routes_remain_blocked():
    blocked_policies = [
        policy
        for policy in SURFACE_POLICIES
        if policy.surface == "local-agent"
        and policy.implementation_mode == "blocked-future"
        and (
            policy.secret_class == "client-config-secret"
            or policy.risk_class in {"secret-read", "destructive"}
        )
    ]
    actual_routes = _route_keys(_agent_app())

    assert blocked_policies
    assert all(policy.implementation_mode == "blocked-future" for policy in blocked_policies)
    assert all(
        (policy.method, policy.path) not in actual_routes
        for policy in blocked_policies
    )


def test_self_service_future_routes_are_policy_only_and_not_mounted(tmp_path: Path):
    blocked_self_service_routes = {
        (policy.method, policy.path)
        for policy in SURFACE_POLICIES
        if policy.surface == "self-service"
        and policy.implementation_mode == "blocked-future"
    }
    actual_routes = _route_keys(create_web_app(_settings(tmp_path)))

    assert blocked_self_service_routes
    assert actual_routes.isdisjoint(blocked_self_service_routes)
    assert all(
        not path.startswith("/self-service")
        for _method, path in actual_routes
    )


def test_surface_policy_test_references_exist():
    missing_refs = [
        (policy.policy_id, test_ref)
        for policy in SURFACE_POLICIES
        for test_ref in policy.test_refs
        if not Path(test_ref).exists()
    ]

    assert missing_refs == []


def _route_keys(app: FastAPI) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods or ():
            if method in {"HEAD", "OPTIONS"}:
                continue
            routes.add((method, route.path))
    return routes


def _binding_map(bindings):
    return {(binding.method, binding.path): binding for binding in bindings}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret-for-route-bindings-123456",
        database_path=str(tmp_path / "amneziya.sqlite3"),
        admin_telegram_ids="",
        server_config_path=str(tmp_path / "servers.yml"),
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
    )


def _agent_app() -> FastAPI:
    return create_agent_app(
        adapter=FakeLocalRuntimeAdapter(
            RuntimeSnapshot(
                server_name="demo-vps",
                runtime_type="docker",
                status="running",
                protocols=(
                    ProtocolSnapshot(
                        name="amneziawg",
                        status="running",
                        runtime_type="docker",
                        capabilities=("detect", "status"),
                        container_name="amnezia-awg",
                        interface="awg0",
                        client_count=2,
                    ),
                ),
            )
        ),
        tokens=(
            AgentToken(
                token_id="agent-token-1",
                token_hash=hash_agent_token("raw-agent-token"),
                scopes=frozenset({"agent:health", "agent:read", "agent:protocols:read"}),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                owner="test-controller",
            ),
        ),
        build_version="test-build",
    )
