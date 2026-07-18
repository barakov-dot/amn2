# DEVICE-001 Read-only Operator UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить authenticated read-only list/detail UX для Device Passport и lifecycle metadata без DB/VPS/Telegram/config/peer mutation.

**Architecture:** Repository получает bounded global list query, domain service преобразует строки в существующий `DevicePassport`, а отдельный web projector формирует safe template views. Два session-authenticated GET route рендерят Russian-first templates и получают явные SurfacePolicy/runtime bindings; ни один компонент не принимает network collector или write dependency.

**Tech Stack:** CPython 3.12.x, SQLite, FastAPI/Starlette session auth, Jinja2 autoescape, pytest, существующие `DevicePassport`, `DeviceLifecycleEvent`, `SurfacePolicy` и `SurfaceBinding` contracts.

## Global Constraints

- Base branch/head: `codex-vps-test-prep` at design commit `57efe86` descended from production source `0b858c5`.
- Public/self-service/API routes remain closed; only authenticated web-admin GET views are added.
- No raw config, private key, PSK, Enrollment Ticket secret/hash, token-bearing material or raw database row reaches HTML.
- No SSH, VPS, Telegram, peer inventory collector, config/peer generation/delivery or automatic drift remediation.
- No database schema change and no write transaction.
- `docs/CLIENT_RELEASE_MONITOR_BASELINE.ru.md` is outside this AMN2 worktree and must not be touched by later AMN3 status sync.
- The independent `TELEGRAM-GROUP-ICON-001` live gate is not implemented by this plan.
- Every task follows RED → GREEN → REFACTOR and ends with an independently reviewable commit.

---

### Task 1: Bounded global Device Passport read contract

**Files:**
- Modify: `tests/services/test_device_passports.py`
- Modify: `app/db/repositories.py`
- Modify: `app/services/device_passports.py`

**Interfaces:**
- Consumes: existing `Repository.get_device_passport`, `Repository.list_device_passports_for_owner`, `_passport_from_row`.
- Produces: `Repository.list_device_passports(*, limit: int = 100) -> list[sqlite3.Row]` and `list_all_device_passports(repo, *, reconciliations=None, limit=100) -> tuple[DevicePassport, ...]`.

- [ ] **Step 1: Write failing global-list tests**

Add the import and tests below to `tests/services/test_device_passports.py`:

```python
from app.services.device_passports import list_all_device_passports


def test_global_passport_list_is_bounded_and_sorted_by_latest_update():
    conn, repo, first_owner_id, first_local_device_id = _repo()
    second_owner_id = repo.upsert_user(
        telegram_id=8002,
        username="second-passport-user",
        first_name="Second",
        last_name="Owner",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    second_local_device_id = repo.create_device(
        user_id=second_owner_id,
        server_id=server_id,
        name="phone",
        duration_days=30,
        vpn_ip="10.8.0.3",
        peer_public_key="second-passport-public-key",
        peer_private_key_encrypted="encrypted-private-2",
        preshared_key_encrypted="encrypted-psk-2",
        config_version="amneziawg_v2",
    )
    first = create_device_passport(
        repo,
        owner_user_id=first_owner_id,
        local_device_id=first_local_device_id,
        platform="android_tv",
        official_client_type="amnezia_vpn",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text="first-config",
    )
    second = create_device_passport(
        repo,
        owner_user_id=second_owner_id,
        local_device_id=second_local_device_id,
        platform="windows",
        official_client_type="amneziawg",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text="second-config",
    )
    conn.execute(
        "UPDATE device_passports SET updated_at = ? WHERE device_id = ?",
        ("2026-07-18 11:00:00", first.device_id),
    )
    conn.execute(
        "UPDATE device_passports SET updated_at = ? WHERE device_id = ?",
        ("2026-07-18 12:00:00", second.device_id),
    )
    conn.commit()

    items = list_all_device_passports(repo, limit=1)

    assert [item.device_id for item in items] == [second.device_id]


@pytest.mark.parametrize("limit", [0, 101])
def test_global_passport_list_rejects_out_of_range_limit(limit: int):
    _, repo, _, _ = _repo()

    with pytest.raises(ValueError, match="limit must be between 1 and 100"):
        list_all_device_passports(repo, limit=limit)
```

- [ ] **Step 2: Run the RED test**

Run:

```powershell
python -m pytest tests/services/test_device_passports.py -q
```

Expected: collection fails because `list_all_device_passports` does not exist.

- [ ] **Step 3: Add the repository query**

Add next to `list_device_passports_for_owner` in `app/db/repositories.py`:

```python
    def list_device_passports(
        self,
        *,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        if not 1 <= limit <= 100:
            raise ValueError("device passport limit must be between 1 and 100")
        return self._conn.execute(
            """
            SELECT
                device_id,
                local_device_id,
                owner_user_id,
                platform,
                official_client_type,
                client_version,
                import_method,
                config_schema_version,
                config_fingerprint,
                last_seen_at,
                acceptance_evidence_json,
                revoked_at,
                revoke_reason,
                created_at,
                updated_at
            FROM device_passports
            ORDER BY updated_at DESC, device_id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
```

- [ ] **Step 4: Add the domain service**

Add to `app/services/device_passports.py` after `list_device_passports`:

```python
def list_all_device_passports(
    repo: Repository,
    *,
    reconciliations: dict[str, ReconciliationSnapshot] | None = None,
    limit: int = 100,
) -> tuple[DevicePassport, ...]:
    snapshots = reconciliations or {}
    return tuple(
        _passport_from_row(
            repo,
            row,
            reconciliation=snapshots.get(str(row["device_id"])),
        )
        for row in repo.list_device_passports(limit=limit)
    )
```

- [ ] **Step 5: Run focused GREEN tests**

Run:

```powershell
python -m pytest tests/services/test_device_passports.py tests/services/test_device_lifecycle.py -q
```

Expected: all focused tests pass.

- [ ] **Step 6: Review and commit Task 1**

Run:

```powershell
git diff --check
git diff -- tests/services/test_device_passports.py app/db/repositories.py app/services/device_passports.py
git add tests/services/test_device_passports.py app/db/repositories.py app/services/device_passports.py
git commit -m "Add global Device Passport read contract"
```

Expected: one commit containing only the repository/service contract and tests.

---

### Task 2: Safe Device Passport web projector

**Files:**
- Create: `app/web/device_passports.py`
- Create: `tests/web/test_device_passport_views.py`

**Interfaces:**
- Consumes: `list_all_device_passports`, `get_device_passport`, `list_device_lifecycle_events`, `Repository.get_user`.
- Produces: `build_device_passport_list_view(repo, *, limit=100) -> dict[str, object]` and `build_device_passport_detail_view(repo, device_id) -> dict[str, object]`.

- [ ] **Step 1: Write failing projector tests**

Create `tests/web/test_device_passport_views.py` with focused in-memory fixtures and these assertions:

```python
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.device_passports import (
    DeviceAcceptanceEvidence,
    create_device_passport,
    record_device_acceptance,
)
from app.web.device_passports import (
    build_device_passport_detail_view,
    build_device_passport_list_view,
)


def test_list_view_contains_safe_owner_and_status_metadata():
    conn, repo, user_id, local_device_id, passport_id = _seed_passport()

    view = build_device_passport_list_view(repo)

    assert view["limit"] == 100
    assert view["count"] == 1
    item = view["items"][0]
    assert item["device_id"] == passport_id
    assert item["owner"] == {"id": user_id, "display": "passport-owner"}
    assert item["local_device_id"] == local_device_id
    assert item["state"] == "active"
    assert item["acceptance_status"] == "passed"
    assert item["drift_state"] == "unknown"
    assert "never-store-projector-secret" not in json.dumps(view)
    assert "encrypted-private" not in json.dumps(view)
    assert "encrypted-psk" not in json.dumps(view)
    assert conn.in_transaction is False


def test_detail_view_contains_lifecycle_and_capability_boundary():
    _, repo, user_id, _, passport_id = _seed_passport()

    view = build_device_passport_detail_view(repo, passport_id)

    assert view["owner"]["id"] == user_id
    assert view["passport"]["device_id"] == passport_id
    assert view["passport"]["config_fingerprint"].startswith("sha256:")
    assert view["passport"]["capability_boundary"]["hardware_fingerprint"] is False
    assert view["passport"]["recommended_next_action"] == "collect_fresh_observation"
    assert view["lifecycle"] == []


def _seed_passport() -> tuple[sqlite3.Connection, Repository, int, int, str]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=18001,
        username="passport-owner",
        first_name="Passport",
        last_name="Owner",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    local_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="operator-phone",
        duration_days=30,
        vpn_ip="10.8.0.22",
        peer_public_key="projector-public-key",
        peer_private_key_encrypted="encrypted-private",
        preshared_key_encrypted="encrypted-psk",
        config_version="amneziawg_v2",
    )
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=local_device_id,
        platform="android",
        official_client_type="amnezia_vpn",
        client_version="4.8.19.0",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text="never-store-projector-secret",
    )
    now = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
    record_device_acceptance(
        repo,
        device_id=passport.device_id,
        last_seen_at=now,
        evidence=DeviceAcceptanceEvidence(
            status="passed",
            source="manual_client_test",
            observed_at=now,
            reference="device-001-projector-pass",
        ),
    )
    return conn, repo, user_id, local_device_id, passport.device_id
```

- [ ] **Step 2: Run the RED projector tests**

Run:

```powershell
python -m pytest tests/web/test_device_passport_views.py -q
```

Expected: collection fails because `app.web.device_passports` does not exist.

- [ ] **Step 3: Implement the projector**

Create `app/web/device_passports.py`:

```python
from __future__ import annotations

from typing import Any

from app.db.repositories import Repository
from app.services.device_lifecycle import list_device_lifecycle_events
from app.services.device_passports import (
    DevicePassport,
    get_device_passport,
    list_all_device_passports,
)


def build_device_passport_list_view(
    repo: Repository,
    *,
    limit: int = 100,
) -> dict[str, object]:
    items = [_list_item(repo, passport) for passport in list_all_device_passports(repo, limit=limit)]
    return {"items": items, "count": len(items), "limit": limit}


def build_device_passport_detail_view(
    repo: Repository,
    device_id: str,
) -> dict[str, object]:
    passport = get_device_passport(repo, device_id)
    owner = _owner_view(repo, passport.owner_user_id)
    lifecycle = [
        event.safe_metadata()
        for event in list_device_lifecycle_events(
            repo,
            passport_device_id=passport.device_id,
        )
    ]
    return {
        "owner": owner,
        "passport": passport.safe_metadata(),
        "state": "revoked" if passport.revoked_at is not None else "active",
        "acceptance_status": (
            passport.acceptance_evidence.status
            if passport.acceptance_evidence is not None
            else "pending"
        ),
        "lifecycle": lifecycle,
    }


def _list_item(repo: Repository, passport: DevicePassport) -> dict[str, Any]:
    lifecycle = list_device_lifecycle_events(
        repo,
        passport_device_id=passport.device_id,
    )
    metadata = passport.safe_metadata()
    return {
        "device_id": passport.device_id,
        "owner": _owner_view(repo, passport.owner_user_id),
        "local_device_id": passport.local_device_id,
        "platform": passport.platform,
        "official_client_type": passport.official_client_type,
        "client_version": passport.client_version,
        "state": "revoked" if passport.revoked_at is not None else "active",
        "acceptance_status": (
            passport.acceptance_evidence.status
            if passport.acceptance_evidence is not None
            else "pending"
        ),
        "drift_state": passport.reconciliation.drift_state,
        "last_seen_at": metadata["last_seen_at"],
        "last_observed_at": metadata["last_observed_at"],
        "updated_at": metadata["updated_at"],
        "lifecycle_completed": [
            event.stage
            for event in lifecycle
            if event.status == "completed"
        ],
    }


def _owner_view(repo: Repository, owner_user_id: int) -> dict[str, object]:
    row = repo.get_user(owner_user_id)
    if row is None:
        raise LookupError("device passport owner not found")
    display = str(row["username"] or "").strip()
    if not display:
        display = " ".join(
            part
            for part in (
                str(row["first_name"] or "").strip(),
                str(row["last_name"] or "").strip(),
            )
            if part
        )
    if not display:
        display = str(row["telegram_id"])
    return {"id": owner_user_id, "display": display}
```

- [ ] **Step 4: Run GREEN projector tests**

Run:

```powershell
python -m pytest tests/web/test_device_passport_views.py tests/services/test_device_passports.py tests/services/test_device_lifecycle.py -q
```

Expected: all tests pass.

- [ ] **Step 5: Verify the narrow projector boundary**

Confirm `_list_item` calls `passport.safe_metadata()` exactly once, and that
the projector adds no caching, pagination, filters, serializer dependency,
database writes or remote observation.

- [ ] **Step 6: Review and commit Task 2**

```powershell
git diff --check
git diff -- app/web/device_passports.py tests/web/test_device_passport_views.py
git add app/web/device_passports.py tests/web/test_device_passport_views.py
git commit -m "Add safe Device Passport web views"
```

---

### Task 3: Authenticated list/detail routes and Russian-first templates

**Files:**
- Modify: `app/web/app.py`
- Modify: `app/web/templates/base.html`
- Create: `app/web/templates/device_passports.html`
- Create: `app/web/templates/device_passport_detail.html`
- Create: `tests/web/test_device_passports.py`

**Interfaces:**
- Consumes: the Task 2 projector and existing `_is_authenticated`, `_open_repository`, `_template_context`.
- Produces: authenticated `GET /device-passports` and `GET /device-passports/{device_id}`.

- [ ] **Step 1: Write RED route/security tests**

Create the complete `tests/web/test_device_passports.py` module:

```python
from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.device_passports import create_device_passport
from app.web.app import create_web_app
from app.web.auth import create_password_hash

TEST_APP_SECRET = "test-secret-for-device-passports-1234567890"


def test_device_passport_routes_redirect_when_unauthenticated(tmp_path: Path):
    client = _client(tmp_path)

    for path in ("/device-passports", "/device-passports/dev_missing"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_device_passport_list_and_detail_render_safe_read_only_metadata(tmp_path: Path):
    settings, passport_id = _seed_database(tmp_path)
    client = _authenticated_client(settings)
    before = _database_dump(Path(settings.database_path))

    listing = client.get("/device-passports")
    detail = client.get(f"/device-passports/{passport_id}")
    after = _database_dump(Path(settings.database_path))

    assert listing.status_code == 200
    assert "Паспорта устройств" in listing.text
    assert passport_id in listing.text
    assert "passport-web-owner" in listing.text
    assert "Последние 100 записей" in listing.text
    assert detail.status_code == 200
    assert "Жизненный цикл" in detail.text
    assert "Возможности и ограничения" in detail.text
    assert "collect_fresh_observation" in detail.text
    assert "hardware_fingerprint" in detail.text
    assert "false" in detail.text.lower()
    for forbidden in (
        "never-render-this-private-config",
        "encrypted-web-private-key",
        "encrypted-web-psk",
        "amn2_enroll_",
    ):
        assert forbidden not in listing.text
        assert forbidden not in detail.text
    assert after == before


def test_device_passport_detail_returns_fixed_not_found(tmp_path: Path):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)

    response = client.get("/device-passports/dev_reflect_me")

    assert response.status_code == 404
    assert response.text == "Device passport not found"
    assert "dev_reflect_me" not in response.text


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key=TEST_APP_SECRET,
        database_path=str(tmp_path / "amneziya.sqlite3"),
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
        vps_apply_enabled=False,
        server_config_path=str(tmp_path / "servers.yml"),
    )


def _client(
    tmp_path: Path | None = None,
    *,
    settings: Settings | None = None,
) -> TestClient:
    actual_settings = settings or _settings(tmp_path or Path("."))
    return TestClient(create_web_app(actual_settings), base_url="https://testserver")


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


def _seed_database(tmp_path: Path) -> tuple[Settings, str]:
    settings = _settings(tmp_path)
    conn = connect(Path(settings.database_path))
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        user_id = repo.upsert_user(
            telegram_id=18002,
            username="passport-web-owner",
            first_name="Passport",
            last_name="Web",
        )
        server_id = repo.ensure_default_server(
            name="local",
            network_cidr="10.8.0.0/24",
        )
        local_device_id = repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="web-phone",
            duration_days=30,
            vpn_ip="10.8.0.24",
            peer_public_key="web-passport-public-key",
            peer_private_key_encrypted="encrypted-web-private-key",
            preshared_key_encrypted="encrypted-web-psk",
            config_version="amneziawg_v2",
        )
        passport = create_device_passport(
            repo,
            owner_user_id=user_id,
            local_device_id=local_device_id,
            platform="android",
            official_client_type="amnezia_vpn",
            import_method="standard_conf",
            config_schema_version="amneziawg_v2",
            config_text="never-render-this-private-config",
        )
        return settings, passport.device_id
    finally:
        conn.close()


def _database_dump(database_path: Path) -> str:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        return "\n".join(conn.iterdump())
    finally:
        conn.close()
```

- [ ] **Step 2: Run RED route tests**

```powershell
python -m pytest tests/web/test_device_passports.py -q
```

Expected: authenticated requests return `404` because routes are absent.

- [ ] **Step 3: Mount list/detail routes**

Import the projector in `app/web/app.py`:

```python
from app.web.device_passports import (
    build_device_passport_detail_view,
    build_device_passport_list_view,
)
```

Add before `/users/{user_id}` routes:

```python
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
```

- [ ] **Step 4: Add Russian-first templates**

Create the complete `app/web/templates/device_passports.html`:

```jinja2
{% extends "base.html" %}

{% block content %}
  <section class="section-heading page-heading">
    <div>
      <p class="eyebrow">DEVICE-001 · операторский обзор</p>
      <h1>Паспорта устройств</h1>
    </div>
  </section>

  <section class="panel">
    <div class="panel-header">
      <h2>Безопасные метаданные</h2>
    </div>
    <p class="muted-text">Последние {{ limit }} записей · только чтение · без live-проверки VPS</p>
    {% if items %}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID паспорта</th>
              <th>Владелец</th>
              <th>Локальное устройство</th>
              <th>Платформа / клиент</th>
              <th>Приёмка</th>
              <th>Статус</th>
              <th>Drift</th>
              <th>Последние данные</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {% for item in items %}
              <tr>
                <td><a href="/device-passports/{{ item.device_id }}">{{ item.device_id }}</a></td>
                <td><a href="/users/{{ item.owner.id }}">{{ item.owner.display }}</a></td>
                <td>{{ item.local_device_id or "не привязан" }}</td>
                <td>
                  <span class="primary-text">{{ item.platform }}</span>
                  <span class="muted-text">{{ item.official_client_type }} {{ item.client_version or "" }}</span>
                </td>
                <td>{{ item.acceptance_status }}</td>
                <td><span class="status status-{{ item.state }}">{{ item.state }}</span></td>
                <td>{{ item.drift_state }}</td>
                <td>
                  <span class="primary-text">seen: {{ item.last_seen_at or "-" }}</span>
                  <span class="muted-text">observed: {{ item.last_observed_at or "-" }}</span>
                  <span class="muted-text">updated: {{ item.updated_at }}</span>
                </td>
                <td><a href="/device-passports/{{ item.device_id }}">Открыть паспорт</a></td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    {% else %}
      <p class="empty-state">Паспорта устройств не найдены.</p>
    {% endif %}
  </section>
{% endblock %}
```

Create the complete `app/web/templates/device_passport_detail.html`:

```jinja2
{% extends "base.html" %}

{% block content %}
  <section class="section-heading page-heading">
    <div>
      <p class="eyebrow">DEVICE-001 · только чтение</p>
      <h1>{{ passport.device_id }}</h1>
    </div>
    <a href="/device-passports">Назад к паспортам</a>
  </section>

  <section class="detail-grid">
    <article class="panel">
      <div class="panel-header"><h2>Паспорт</h2></div>
      <dl class="details">
        <div><dt>Владелец</dt><dd><a href="/users/{{ owner.id }}">{{ owner.display }}</a></dd></div>
        <div><dt>Локальное устройство</dt><dd>{{ passport.local_device_id or "не привязан" }}</dd></div>
        <div><dt>Платформа</dt><dd>{{ passport.platform }}</dd></div>
        <div><dt>Официальный клиент</dt><dd>{{ passport.official_client_type }} {{ passport.client_version or "" }}</dd></div>
        <div><dt>Метод импорта</dt><dd>{{ passport.import_method }}</dd></div>
        <div><dt>Схема конфига</dt><dd>{{ passport.config_schema_version }}</dd></div>
        <div><dt>Отпечаток конфига</dt><dd class="wrap-text">{{ passport.config_fingerprint }}</dd></div>
        <div><dt>Состояние</dt><dd><span class="status status-{{ state }}">{{ state }}</span></dd></div>
        <div><dt>Последняя активность</dt><dd>{{ passport.last_seen_at or "-" }}</dd></div>
        <div><dt>Обновлён</dt><dd>{{ passport.updated_at }}</dd></div>
      </dl>
    </article>

    <article class="panel">
      <div class="panel-header"><h2>Сверка состояния</h2></div>
      <dl class="details">
        <div><dt>Drift</dt><dd>{{ passport.drift_state }}</dd></div>
        <div><dt>Причина drift</dt><dd>{{ passport.drift_reason or "-" }}</dd></div>
        <div><dt>Последнее наблюдение</dt><dd>{{ passport.last_observed_at or "-" }}</dd></div>
        <div><dt>Рекомендация только для чтения</dt><dd>{{ passport.recommended_next_action }}</dd></div>
      </dl>
    </article>
  </section>

  <section class="detail-grid">
    <article class="panel">
      <div class="panel-header"><h2>Ожидаемое состояние</h2></div>
      <dl class="details">
        {% for key, value in passport.desired_state.items() %}
          <div><dt>{{ key }}</dt><dd class="wrap-text">{{ value if value is not none else "-" }}</dd></div>
        {% endfor %}
      </dl>
    </article>
    <article class="panel">
      <div class="panel-header"><h2>Наблюдаемое состояние</h2></div>
      <dl class="details">
        {% for key, value in passport.observed_state.items() %}
          <div><dt>{{ key }}</dt><dd class="wrap-text">{{ value if value is not none else "-" }}</dd></div>
        {% endfor %}
      </dl>
    </article>
  </section>

  <section class="detail-grid">
    <article class="panel">
      <div class="panel-header"><h2>Приёмка устройства</h2></div>
      <p><span class="status status-{{ acceptance_status }}">{{ acceptance_status }}</span></p>
      {% if passport.acceptance_evidence %}
        <dl class="details">
          {% for key, value in passport.acceptance_evidence.items() %}
            <div><dt>{{ key }}</dt><dd class="wrap-text">{{ value }}</dd></div>
          {% endfor %}
        </dl>
      {% else %}
        <p class="empty-state">Подтверждение приёмки ещё не записано.</p>
      {% endif %}
    </article>
    <article class="panel">
      <div class="panel-header"><h2>Возможности и ограничения</h2></div>
      <dl class="details">
        {% for key, value in passport.capability_boundary.items() %}
          <div><dt>{{ key }}</dt><dd>{{ "true" if value else "false" }}</dd></div>
        {% endfor %}
      </dl>
    </article>
  </section>

  <section class="panel">
    <div class="panel-header"><h2>Жизненный цикл</h2></div>
    {% if lifecycle %}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Этап</th><th>Статус</th><th>Время</th><th>Длительность, мс</th><th>Источник</th></tr>
          </thead>
          <tbody>
            {% for event in lifecycle %}
              <tr>
                <td>{{ event.stage }}</td>
                <td>{{ event.status }}</td>
                <td>{{ event.occurred_at }}</td>
                <td>{{ event.duration_ms }}</td>
                <td>{{ event.evidence.source }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    {% else %}
      <p class="empty-state">События жизненного цикла ещё не записаны.</p>
    {% endif %}
  </section>
{% endblock %}
```

Both new templates must contain no form and no `button` element. The detail
page labels `recommended_next_action` as `Рекомендация только для чтения`.

Add to authenticated nav in `app/web/templates/base.html`:

```jinja2
<a class="nav-link" href="/device-passports">Паспорта устройств</a>
```

- [ ] **Step 5: Run GREEN route tests**

```powershell
python -m pytest tests/web/test_device_passports.py tests/web/test_device_passport_views.py tests/web/test_users.py -q
```

Expected: all focused web tests pass.

- [ ] **Step 6: Verify templates contain no mutation controls**

```powershell
rg -n "<form|method=|csrf_token|POST|Удалить|Применить|Создать" app/web/templates/device_passports.html app/web/templates/device_passport_detail.html
```

Expected: no matches.

- [ ] **Step 7: Review and commit Task 3**

```powershell
git diff --check
git add app/web/app.py app/web/templates/base.html app/web/templates/device_passports.html app/web/templates/device_passport_detail.html tests/web/test_device_passports.py
git commit -m "Add Device Passport operator pages"
```

---

### Task 4: SurfacePolicy and runtime binding closure

**Files:**
- Modify: `app/security/surface_policy.py`
- Modify: `app/security/surface_bindings.py`
- Modify: `tests/security/test_surface_policy.py`
- Modify: `tests/security/test_surface_policy_bindings.py`

**Interfaces:**
- Consumes: mounted Task 3 routes.
- Produces: `web.device_passports.index` and `web.device_passports.detail` policy IDs plus exact GET runtime bindings.

- [ ] **Step 1: Write RED policy tests**

Add both IDs to `EXPECTED_POLICY_IDS` in `tests/security/test_surface_policy.py`
and add:

```python
def test_device_passport_web_surfaces_are_read_only_and_secret_safe():
    expected = {
        "web.device_passports.index": "/device-passports",
        "web.device_passports.detail": "/device-passports/{device_id}",
    }
    for policy_id, path in expected.items():
        policy = get_surface_policy(policy_id)
        assert policy.surface == "web"
        assert policy.method == "GET"
        assert policy.path == path
        assert policy.actor == "web-admin"
        assert policy.auth_method == "session"
        assert policy.risk_class == "secret-adjacent-read"
        assert policy.secret_class == "secret-adjacent"
        assert policy.side_effects == ()
        assert policy.audit_required is False
        assert policy.live_retest_required is False
        assert policy.implementation_mode == "implemented"
        assert policy.enables_new_behavior is True
        gates = " ".join(policy.gates).lower()
        assert "no db mutation" in gates
        assert "no remote observation" in gates
        assert "no raw config" in gates
```

Add to `tests/security/test_surface_policy_bindings.py`:

```python
def test_device_passport_get_routes_use_explicit_policy_bindings():
    bindings = _binding_map(WEB_RUNTIME_ROUTE_BINDINGS)
    assert bindings[("GET", "/device-passports")].policy_id == (
        "web.device_passports.index"
    )
    assert bindings[("GET", "/device-passports/{device_id}")].policy_id == (
        "web.device_passports.detail"
    )
```

- [ ] **Step 2: Run RED policy tests**

```powershell
python -m pytest tests/security/test_surface_policy.py tests/security/test_surface_policy_bindings.py -q
```

Expected: missing policy IDs and runtime bindings fail.

- [ ] **Step 3: Add SurfacePolicy entries**

Add to `SURFACE_POLICIES` near other authenticated read-only web surfaces:

```python
    _p(
        "web.device_passports.index",
        "web",
        "GET",
        "/device-passports",
        "web-admin",
        "session",
        "secret-adjacent-read",
        "secret-adjacent",
        (),
        (
            "session required",
            "safe metadata only",
            "no raw config/private key/PSK/ticket secret/token hash",
            "no remote observation",
            "no DB mutation",
        ),
        False,
        "",
        False,
        "implemented",
        ("tests/web/test_device_passports.py",),
        "Authenticated bounded Device Passport inventory view.",
        enables_new_behavior=True,
    ),
    _p(
        "web.device_passports.detail",
        "web",
        "GET",
        "/device-passports/{device_id}",
        "web-admin",
        "session",
        "secret-adjacent-read",
        "secret-adjacent",
        (),
        (
            "session required",
            "safe metadata only",
            "no raw config/private key/PSK/ticket secret/token hash",
            "no remote observation",
            "no DB mutation",
            "fixed 404",
        ),
        False,
        "",
        False,
        "implemented",
        ("tests/web/test_device_passports.py",),
        "Authenticated Device Passport lifecycle and drift detail view.",
        enables_new_behavior=True,
    ),
```

- [ ] **Step 4: Add exact runtime bindings**

Add to `WEB_RUNTIME_ROUTE_BINDINGS` next to `/users`:

```python
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
```

- [ ] **Step 5: Run GREEN policy and web tests**

```powershell
python -m pytest tests/security/test_surface_policy.py tests/security/test_surface_policy_bindings.py tests/web/test_device_passports.py -q
```

Expected: all tests pass and both mounted routes have exact policy bindings.

- [ ] **Step 6: Review and commit Task 4**

```powershell
git diff --check
git add app/security/surface_policy.py app/security/surface_bindings.py tests/security/test_surface_policy.py tests/security/test_surface_policy_bindings.py
git commit -m "Bind Device Passport read-only surfaces"
```

---

### Task 5: Final verification, evidence and source commit closure

**Files:**
- No new AMN2 source file changes after Tasks 1–4 unless review remediation is required.
- Parent AMN3 workflow writes: `C:\Users\SooL\Documents\VPS-OPS-LAB\research\amn2\phase-12-device-001-read-only-operator-ux-2026-07-18.md`.

**Interfaces:**
- Consumes: Tasks 1–4 complete implementation.
- Produces: exact receipt fields for AMN3 evidence and a clean AMN2 source branch ready for push/status sync.

- [ ] **Step 1: Run focused regression**

```powershell
python -m pytest tests/services/test_device_passports.py tests/services/test_device_lifecycle.py tests/web/test_device_passport_views.py tests/web/test_device_passports.py tests/web/test_users.py tests/security/test_surface_policy.py tests/security/test_surface_policy_bindings.py -q
```

Expected: zero failures.

- [ ] **Step 2: Run the full AMN2 suite**

```powershell
python -m pytest tests -q
```

Expected: zero failures; the existing documented platform skip/warning may remain unchanged.

- [ ] **Step 3: Run static and secret-negative checks**

```powershell
python -m compileall -q app
git diff --check
rg -n "setChatPhoto|setMyProfilePhoto|send(Message|Photo|Document)|deleteWebhook|drop_pending_updates|docker (stop|restart)|\bawg\b|\bwg set\b" app/web/device_passports.py app/web/app.py app/web/templates/device_passports.html app/web/templates/device_passport_detail.html
rg -n --pcre2 "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{20,}" app tests
```

Expected: compile and diff checks pass; forbidden-operation and high-confidence-secret scans return no matches.

- [ ] **Step 4: Return exact evidence fields to the parent AMN3 workflow**

Return `base=57efe86`,
`scope=device_passport_authenticated_read_only_list_detail`, both GET route
names, `db_mutation=false`, `remote_observation=false`, `telegram=false`,
`vps=false`, `config_peer_delivery=false` and `awg=untouched`. Record the
verbatim final pytest summaries under `focused_tests` and `full_tests`, the
diff-check result, the final Codex Security diff-scan result, exact changed
paths, policy IDs, secret-negative result and any unchanged warning/skip. The
parent workflow persists these fields in AMN3; do not claim deployment or
production activation.

- [ ] **Step 5: Run complete Git diff and Codex Security diff review**

Review every changed source/test/template/doc file. Require complete coverage,
deferred `0` and reportable findings `0`; remediate and rerun if any finding
survives. Verify no user/unrelated path is staged.

- [ ] **Step 6: Commit review remediation only if the review changed AMN2**

If review remediation changed an AMN2 source, test or template file, stage only
those approved paths, run `git diff --cached --check`, rerun the affected and
full tests, and commit with `git commit -m "Harden Device Passport operator UX"`.
If no remediation was needed, create no empty evidence commit in AMN2.

- [ ] **Step 7: Verify source branch before handoff**

```powershell
git status --short --branch
git log -6 --oneline --decorate
```

Expected: clean AMN2 worktree, `codex-vps-test-prep` ahead of origin only by
the approved design/plan/implementation/evidence commits. Push and AMN3 status
sync are the next parent workflow steps; no VPS package/live action follows
implicitly.
