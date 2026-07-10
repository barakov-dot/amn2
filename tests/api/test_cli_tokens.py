import json
from pathlib import Path

from app.cli import build_parser
from app.cli import run_api_smoke_cycle
from app.cli import run_api_smoke_check
from app.cli import run_api_token_issue
from app.cli import run_api_token_revoke
from app.db.connection import connect
from app.db.schema import initialize_schema
from app.services.api_tokens import hash_api_token


def test_cli_accepts_api_token_issue_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "api",
            "token",
            "issue",
            "--db",
            "data/amneziya.sqlite3",
            "--name",
            "VPS smoke",
            "--owner-label",
            "ops",
            "--scope",
            "server:read",
            "--scope",
            "metrics:read",
            "--expires-at",
            "2026-06-08T10:00:00+00:00",
        ]
    )

    assert args.command == "api"
    assert args.api_command == "token"
    assert args.api_token_command == "issue"
    assert args.db == "data/amneziya.sqlite3"
    assert args.name == "VPS smoke"
    assert args.owner_label == "ops"
    assert args.scopes == ["server:read", "metrics:read"]
    assert args.expires_at == "2026-06-08T10:00:00+00:00"


def test_cli_accepts_api_token_revoke_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "api",
            "token",
            "revoke",
            "--db",
            "data/amneziya.sqlite3",
            "--token-id",
            "api_token_1",
            "--reason",
            "smoke-complete",
        ]
    )

    assert args.command == "api"
    assert args.api_command == "token"
    assert args.api_token_command == "revoke"
    assert args.db == "data/amneziya.sqlite3"
    assert args.token_id == "api_token_1"
    assert args.reason == "smoke-complete"


def test_cli_accepts_api_smoke_check_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "api",
            "smoke-check",
            "--base-url",
            "http://127.0.0.1:3040",
            "--token",
            "raw-api-token",
            "--server-name",
            "local",
            "--pretty",
        ]
    )

    assert args.command == "api"
    assert args.api_command == "smoke-check"
    assert args.base_url == "http://127.0.0.1:3040"
    assert args.token == "raw-api-token"
    assert args.server_name == "local"
    assert args.pretty is True


def test_cli_accepts_api_smoke_cycle_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "api",
            "smoke-cycle",
            "--db",
            "data/amneziya.sqlite3",
            "--base-url",
            "http://127.0.0.1:3040",
            "--server-name",
            "local",
            "--name",
            "VPS smoke",
            "--owner-label",
            "ops",
            "--expires-at",
            "2026-06-08T10:00:00+00:00",
            "--pretty",
        ]
    )

    assert args.command == "api"
    assert args.api_command == "smoke-cycle"
    assert args.db == "data/amneziya.sqlite3"
    assert args.base_url == "http://127.0.0.1:3040"
    assert args.server_name == "local"
    assert args.name == "VPS smoke"
    assert args.owner_label == "ops"
    assert args.expires_at == "2026-06-08T10:00:00+00:00"
    assert args.pretty is True


def test_run_api_token_issue_stores_hash_and_outputs_raw_token_once(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"

    result = json.loads(
        run_api_token_issue(
            db_path=db_path,
            name="VPS smoke",
            owner_label="ops",
            scopes=["server:read", "metrics:read"],
            expires_at="2026-06-08T10:00:00+00:00",
            raw_token="raw-api-token",
        )
    )

    assert result == {
        "action": "api_token.issued",
        "token_id": result["token_id"],
        "name": "VPS smoke",
        "owner_label": "ops",
        "integration_kind": "operator_automation",
        "purpose": "VPS smoke",
        "scopes": ["metrics:read", "server:read"],
        "expires_at": "2026-06-08T10:00:00+00:00",
        "raw_token_display": "one-time",
        "raw_token": "raw-api-token",
    }
    assert "token_hash" not in result

    conn = connect(db_path)
    try:
        initialize_schema(conn)
        row = conn.execute(
            "SELECT * FROM api_tokens WHERE id = ?",
            (result["token_id"],),
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    assert row["name"] == "VPS smoke"
    assert row["owner_label"] == "ops"
    assert row["scopes_json"] == '["metrics:read", "server:read"]'
    assert row["expires_at"] == "2026-06-08T10:00:00+00:00"
    assert row["token_hash"] == hash_api_token("raw-api-token")
    assert "raw-api-token" not in str(dict(row))


def test_run_api_token_issue_supports_pretty_json(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"

    result = run_api_token_issue(
        db_path=db_path,
        name="VPS smoke",
        owner_label="ops",
        scopes=["server:read"],
        expires_at="2026-06-08T10:00:00+00:00",
        raw_token="raw-api-token",
        pretty=True,
    )

    assert result.startswith("{\n  ")
    assert json.loads(result)["raw_token"] == "raw-api-token"


def test_run_api_token_revoke_marks_token_without_secret_output(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"
    issue = json.loads(
        run_api_token_issue(
            db_path=db_path,
            name="VPS smoke",
            owner_label="ops",
            scopes=["server:read"],
            expires_at="2026-06-08T10:00:00+00:00",
            raw_token="raw-api-token",
        )
    )

    revoked = json.loads(
        run_api_token_revoke(
            db_path=db_path,
            token_id=issue["token_id"],
            reason="smoke-complete",
            revoked_at="2026-06-01T12:00:00+00:00",
        )
    )
    repeated = json.loads(
        run_api_token_revoke(
            db_path=db_path,
            token_id=issue["token_id"],
            reason="smoke-complete",
            revoked_at="2026-06-01T12:05:00+00:00",
        )
    )

    assert revoked == {
        "action": "api_token.revoked",
        "token_id": issue["token_id"],
        "status": "revoked",
        "reason": "smoke-complete",
        "revoked_at": "2026-06-01T12:00:00+00:00",
        "rotated_from_token_id": None,
    }
    assert repeated["status"] == "already-revoked-or-missing"
    assert "raw-api-token" not in json.dumps(revoked)
    assert "token_hash" not in json.dumps(revoked)

    conn = connect(db_path)
    try:
        initialize_schema(conn)
        row = conn.execute(
            "SELECT revoked_at, revoke_reason FROM api_tokens WHERE id = ?",
            (issue["token_id"],),
        ).fetchone()
    finally:
        conn.close()

    assert row["revoked_at"] == "2026-06-01T12:00:00+00:00"
    assert row["revoke_reason"] == "smoke-complete"


def test_run_api_smoke_cycle_hides_raw_token_and_revokes_after_smoke(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"
    calls = []

    def fake_http_get(url: str, headers: dict[str, str], timeout: float):
        calls.append((url, headers, timeout))
        return 200, json.dumps({"body_secret_marker": "must-not-be-output"})

    result = json.loads(
        run_api_smoke_cycle(
            db_path=db_path,
            base_url="http://127.0.0.1:3040",
            server_name="local",
            name="VPS smoke",
            owner_label="ops",
            expires_at="2026-06-08T10:00:00+00:00",
            raw_token="raw-cycle-token",
            http_get=fake_http_get,
        )
    )

    assert result["action"] == "api_smoke_cycle.completed"
    assert result["status"] == "passed"
    assert result["token"] == {
        "token_id": result["token"]["token_id"],
        "name": "VPS smoke",
        "owner_label": "ops",
        "integration_kind": "operator_automation",
        "purpose": "VPS smoke",
        "scopes": ["metrics:read", "server:read"],
        "expires_at": "2026-06-08T10:00:00+00:00",
        "raw_token_display": "hidden",
    }
    assert result["smoke"]["status"] == "passed"
    assert result["smoke"]["checked_routes"] == 6
    assert result["revoke"]["status"] == "revoked"
    assert result["revoke"]["reason"] == "smoke-complete"
    assert {call[1]["Authorization"] for call in calls} == {"Bearer raw-cycle-token"}
    serialized = json.dumps(result)
    assert "raw-cycle-token" not in serialized
    assert "Authorization" not in serialized
    assert "token_hash" not in serialized
    assert "body_secret_marker" not in serialized
    assert "must-not-be-output" not in serialized

    conn = connect(db_path)
    try:
        initialize_schema(conn)
        row = conn.execute(
            "SELECT revoked_at, revoke_reason, token_hash FROM api_tokens WHERE id = ?",
            (result["token"]["token_id"],),
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    assert row["revoked_at"]
    assert row["revoke_reason"] == "smoke-complete"
    assert row["token_hash"] == hash_api_token("raw-cycle-token")


def test_run_api_smoke_check_calls_expected_routes_without_secret_output():
    calls = []

    def fake_http_get(url: str, headers: dict[str, str], timeout: float):
        calls.append((url, headers, timeout))
        if url.endswith("/api/users/summary"):
            return 200, json.dumps({"users": {"total": 1}})
        return 200, json.dumps({"ok": True})

    result = json.loads(
        run_api_smoke_check(
            base_url="http://127.0.0.1:3040/",
            token="raw-api-token",
            server_name="local",
            timeout=3.5,
            http_get=fake_http_get,
        )
    )

    assert [call[0] for call in calls] == [
        "http://127.0.0.1:3040/api/servers",
        "http://127.0.0.1:3040/api/integration/status",
        "http://127.0.0.1:3040/api/local-agent/runtime/summary",
        "http://127.0.0.1:3040/api/servers/local/summary",
        "http://127.0.0.1:3040/api/metrics/summary",
        "http://127.0.0.1:3040/api/users/summary",
    ]
    assert calls[0][1] == {"Authorization": "Bearer raw-api-token"}
    assert calls[0][2] == 3.5
    assert result["status"] == "passed"
    assert result["checked_routes"] == 6
    assert "raw-api-token" not in json.dumps(result)
    assert "Authorization" not in json.dumps(result)
    assert "ok" not in json.dumps(result)


def test_run_api_smoke_check_reports_status_and_forbidden_markers_only():
    def fake_http_get(url: str, headers: dict[str, str], timeout: float):
        if url.endswith("/api/servers"):
            return 200, json.dumps({"ssh_port": 22, "token_hash": "sha256:secret"})
        return 403, json.dumps({"detail": "missing_scope"})

    result = json.loads(
        run_api_smoke_check(
            base_url="http://127.0.0.1:3040",
            token="raw-api-token",
            server_name="local",
            http_get=fake_http_get,
            pretty=True,
        )
    )

    assert result["status"] == "failed"
    assert result["routes"][0] == {
        "name": "servers",
        "status_code": 200,
        "forbidden_markers": ["token_hash", "ssh_port"],
    }
    assert result["routes"][1]["status_code"] == 403
    assert "sha256:secret" not in json.dumps(result)
    assert "raw-api-token" not in json.dumps(result)
