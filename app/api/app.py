from __future__ import annotations

import json
from copy import deepcopy
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.agent.api import AGENT_RUNTIME_CONTRACT_VERSION
from app.agent.runtime_summary import build_runtime_summary
from app.config import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.api_tokens import ApiTokenAuthError
from app.services.api_tokens import ApiTokenRecord
from app.services.api_tokens import authenticate_api_token
from app.services.api_tokens import hash_api_token
from app.services.integration_status import build_integration_status


@dataclass(frozen=True)
class ApiAuthContext:
    token: ApiTokenRecord


class InstallMutationRequest(BaseModel):
    requested_action: str = Field(pattern=r"^clean_install_prepare$")
    target: str = Field(default="local", pattern=r"^local$")
    operator_note: str | None = Field(default=None, max_length=500)


def create_api_app(settings: Settings | None = None) -> FastAPI:
    actual_settings = settings or Settings()
    app = FastAPI(title="Amneziya API")
    app.state.settings = actual_settings

    @app.get("/api/servers")
    async def list_servers(
        repo: Repository = Depends(_repo),
        auth: ApiAuthContext = Depends(_require_scope("server:read")),
    ):
        payload = {
            "servers": [
                _server_summary_payload(row)
                for row in repo.list_api_server_summaries()
            ],
        }
        _record_api_read(repo, auth, path="/api/servers", scope="server:read")
        return payload

    @app.get("/api/integration/status")
    async def integration_status(
        repo: Repository = Depends(_repo),
        auth: ApiAuthContext = Depends(_require_scope("server:read")),
    ):
        payload = _api_safe_integration_status(build_integration_status(repo))
        _record_api_read(repo, auth, path="/api/integration/status", scope="server:read")
        return payload

    @app.get("/api/local-agent/runtime/summary")
    async def local_agent_runtime_summary(
        request: Request,
        repo: Repository = Depends(_repo),
        auth: ApiAuthContext = Depends(_require_scope("server:read")),
    ):
        settings: Settings = request.app.state.settings
        payload = {
            "local_agent": {
                "configured": settings.local_agent_enabled,
                "connectivity": "not_checked",
                "read_only": True,
                "source": "controller_settings",
                "write_routes_enabled": False,
                "runtime_summary": asdict(
                    build_runtime_summary(
                        agent_status=(
                            "configured_not_checked"
                            if settings.local_agent_enabled
                            else "disabled"
                        ),
                        agent_version=None,
                        runtime_contract_version=AGENT_RUNTIME_CONTRACT_VERSION,
                        write_enabled=False,
                        runtime=None,
                    )
                ),
            }
        }
        _record_api_read(
            repo,
            auth,
            path="/api/local-agent/runtime/summary",
            scope="server:read",
        )
        return payload

    @app.get("/api/servers/{server_name}/summary")
    async def server_summary(
        server_name: str,
        repo: Repository = Depends(_repo),
        auth: ApiAuthContext = Depends(_require_scope("server:read")),
    ):
        row = repo.get_api_server_summary(server_name)
        if row is None:
            raise HTTPException(status_code=404, detail="server_not_found")
        payload = {"server": _server_summary_payload(row)}
        _record_api_read(
            repo,
            auth,
            path="/api/servers/{server_name}/summary",
            scope="server:read",
        )
        return payload

    @app.get("/api/metrics/summary")
    async def metrics_summary(
        repo: Repository = Depends(_repo),
        auth: ApiAuthContext = Depends(_require_scope("metrics:read")),
    ):
        summary = repo.get_api_metrics_summary()
        payload = {
            "users": {
                "total": summary["users_total"],
                "active": summary["users_active"],
                "blocked": summary["users_blocked"],
                "deleted": summary["users_deleted"],
            },
            "servers": {
                "total": summary["servers_total"],
                "active": summary["servers_active"],
                "degraded": summary["servers_degraded"],
                "disabled": summary["servers_disabled"],
            },
            "devices": {
                "total": summary["devices_total"],
                "active": summary["devices_active"],
                "disabled": summary["devices_disabled"],
                "revoked": summary["devices_revoked"],
            },
            "traffic": {
                "rx_bytes": summary["traffic_rx_bytes"],
                "tx_bytes": summary["traffic_tx_bytes"],
                "source": "latest_device_snapshots",
            },
        }
        _record_api_read(repo, auth, path="/api/metrics/summary", scope="metrics:read")
        return payload

    @app.get("/api/users/summary")
    async def users_summary(
        repo: Repository = Depends(_repo),
        auth: ApiAuthContext = Depends(_require_scope("metrics:read")),
    ):
        summary = repo.get_api_users_summary()
        payload = {
            "users": {
                "total": summary["users_total"],
                "active": summary["users_active"],
                "blocked": summary["users_blocked"],
                "deleted": summary["users_deleted"],
                "admins": summary["users_admins"],
            },
            "devices": {
                "users_with_devices": summary["users_with_devices"],
                "users_without_devices": summary["users_without_devices"],
            },
            "orders": {
                "total": summary["orders_total"],
                "manual_review": summary["orders_manual_review"],
                "approved": summary["orders_approved"],
                "fulfilled": summary["orders_fulfilled"],
                "payment_pending": summary["orders_payment_pending"],
                "rejected": summary["orders_rejected"],
            },
        }
        _record_api_read(repo, auth, path="/api/users/summary", scope="metrics:read")
        return payload

    @app.post("/api/install/mutation-requests", status_code=202)
    async def install_mutation_request(
        payload: InstallMutationRequest,
        request: Request,
        repo: Repository = Depends(_repo),
        auth: ApiAuthContext = Depends(_require_scope("install:write")),
    ):
        settings: Settings = request.app.state.settings
        status = (
            "recorded_ready_for_operator_runner"
            if settings.vps_apply_enabled
            else "recorded_blocked_by_vps_apply_disabled"
        )
        _record_api_write(
            repo,
            auth,
            path="/api/install/mutation-requests",
            scope="install:write",
            status=status,
            requested_action=payload.requested_action,
            target=payload.target,
            vps_apply_enabled=settings.vps_apply_enabled,
        )
        return {
            "install_mutation_request": {
                "status": status,
                "request_recorded": True,
                "requested_action": payload.requested_action,
                "target": payload.target,
                "execution": {
                    "vps_apply_enabled": settings.vps_apply_enabled,
                    "executor_invoked": False,
                    "package_apply_performed": False,
                    "service_restart_performed": False,
                    "public_exposure_performed": False,
                    "config_delivery_performed": False,
                    "telegram_action_performed": False,
                },
                "safe_evidence": True,
            }
        }

    return app


def _api_safe_integration_status(payload: dict) -> dict:
    safe_payload = deepcopy(payload)
    boundary = safe_payload.get("privacy_status_boundary")
    if not isinstance(boundary, dict):
        return safe_payload

    scheduler = boundary.get("health_status_scheduler")
    if isinstance(scheduler, dict):
        blocked = scheduler.pop("blocked_without_gate", ())
        scheduler["blocked_without_gate_count"] = len(blocked)

    analytics = boundary.get("admin_analytics")
    if isinstance(analytics, dict):
        forbidden = analytics.pop("forbidden_fields", ())
        analytics["forbidden_fields_count"] = len(forbidden)

    return safe_payload


async def _repo(request: Request) -> AsyncIterator[Repository]:
    settings: Settings = request.app.state.settings
    conn = connect(settings.database_path)
    initialize_schema(conn)
    try:
        yield Repository(conn)
    finally:
        conn.close()


def _require_scope(required_scope: str):
    async def dependency(
        authorization: str | None = Header(default=None),
        repo: Repository = Depends(_repo),
    ) -> ApiAuthContext:
        raw_token = _extract_bearer_token(authorization)
        now = datetime.now(timezone.utc)
        row = repo.get_valid_api_token(
            token_hash=hash_api_token(raw_token),
            now=now.isoformat(),
        )
        if row is None:
            raise HTTPException(status_code=401, detail="invalid_token")

        record = _api_token_record_from_row(row)
        try:
            token = authenticate_api_token(
                raw_token,
                tokens=(record,),
                required_scope=required_scope,
                now=now,
            )
        except ApiTokenAuthError as exc:
            if exc.reason in {"missing_scope", "inactive_owner"}:
                raise HTTPException(status_code=403, detail=exc.reason) from exc
            raise HTTPException(status_code=401, detail=exc.reason) from exc

        repo.mark_api_token_used(token.token_id, now.isoformat())
        return ApiAuthContext(token=token)

    return dependency


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing_bearer_token")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="invalid_authorization_header")
    return token.strip()


def _api_token_record_from_row(row) -> ApiTokenRecord:
    return ApiTokenRecord(
        token_id=row["id"],
        token_hash=row["token_hash"],
        name=row["name"],
        owner_label=row["owner_label"],
        integration_kind=row["integration_kind"],
        purpose=row["purpose"],
        owner_user_id=row["owner_user_id"],
        owner_status=row["owner_status"],
        scopes=frozenset(json.loads(row["scopes_json"])),
        expires_at=_parse_datetime(row["expires_at"]),
        revoked_at=_parse_datetime(row["revoked_at"]),
    )


def _record_api_read(
    repo: Repository,
    auth: ApiAuthContext,
    *,
    path: str,
    scope: str,
) -> None:
    repo.record_admin_action(
        admin_telegram_id=0,
        action="api_read",
        metadata={
            "aggregate_only": True,
            "method": "GET",
            "owner_label": auth.token.owner_label,
            "path": path,
            "scope": scope,
            "status": "allowed",
            "token_id": auth.token.token_id,
            "token_name": auth.token.name,
        },
    )


def _record_api_write(
    repo: Repository,
    auth: ApiAuthContext,
    *,
    path: str,
    scope: str,
    status: str,
    requested_action: str,
    target: str,
    vps_apply_enabled: bool,
) -> None:
    repo.record_admin_action(
        admin_telegram_id=0,
        action="api_write",
        metadata={
            "aggregate_only": False,
            "method": "POST",
            "owner_label": auth.token.owner_label,
            "path": path,
            "requested_action": requested_action,
            "scope": scope,
            "status": status,
            "target": target,
            "token_id": auth.token.token_id,
            "token_name": auth.token.name,
            "vps_apply_enabled": vps_apply_enabled,
        },
    )


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _server_summary_payload(row) -> dict[str, object]:
    return {
        "name": row["name"],
        "status": row["status"],
        "enabled": row["status"] != "disabled",
        "configured": True,
        "runtime": row["runtime"],
        "device_counts": {
            "active": int(row["active_device_count"]),
            "total": int(row["total_device_count"]),
        },
        "health": {
            "status": row["health_status"] or "unknown",
            "latency_ms": row["health_latency_ms"],
            "checked_at": row["health_checked_at"],
            "readiness": {
                "ssh": bool(row["health_ssh_ok"]),
                "awg": bool(row["health_awg_ok"]),
                "udp_port": bool(row["health_udp_port_ok"]),
            },
        },
    }
