import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

import app.web.app as web_app
from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.server.peer_apply import PeerApplyError
from app.services.peer_inventory import PeerInventoryReport, RemotePeer
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_servers_redirects_when_unauthenticated(tmp_path: Path):
    client = _client(settings=_settings(tmp_path))

    response = client.get("/servers", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_servers_lists_latest_health_latency_errors_and_device_counts(tmp_path: Path):
    settings = _settings(tmp_path)
    with _repo(Path(settings.database_path)) as repo:
        user_id = _seed_user(repo)
        server_id = _seed_server(repo, name="debian-vps-1")
        _seed_device(repo, user_id=user_id, server_id=server_id, status="active")
        _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="revoked",
            vpn_ip="10.44.0.3",
            peer_public_key="revoked-public",
        )
        repo.record_server_health(
            server_id=server_id,
            status="degraded",
            latency_ms=118,
            ssh_ok=True,
            awg_ok=False,
            udp_port_ok=True,
            error="awg service down",
        )
    client = _authenticated_client(settings)

    response = client.get("/servers")

    assert response.status_code == 200
    assert "debian-vps-1" in response.text
    assert "degraded" in response.text
    assert "118 ms" in response.text
    assert "awg service down" in response.text
    assert "1 / 2" in response.text


def test_create_server_from_web_stores_fields_redirects_and_records_action(
    tmp_path: Path,
):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    client = _authenticated_client(settings)
    form = client.get("/servers/new")
    assert form.status_code == 200

    response = client.post(
        "/servers/new",
        data=_server_form(
            _csrf_token(form.text),
            name="edge-1",
            host="203.0.113.20",
            ssh_port="2222",
            endpoint_host="vpn.example.com",
            vpn_port="31000",
            vpn_network_cidr="10.44.0.0/24",
            server_address="10.44.0.1/24",
            server_public_key="server-public-key",
            runtime="host_systemd",
            firewall="ufw",
            status="active",
            max_devices="128",
        ),
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert re.fullmatch(r"/servers/\d+", response.headers["location"])
    server_id = int(response.headers["location"].rsplit("/", 1)[1])
    with _repo(Path(settings.database_path)) as repo:
        server = repo.get_server(server_id)
        assert server["name"] == "edge-1"
        assert server["host"] == "203.0.113.20"
        assert server["ssh_port"] == 2222
        assert server["endpoint_host"] == "vpn.example.com"
        assert server["vpn_port"] == 31000
        assert server["vpn_network_cidr"] == "10.44.0.0/24"
        assert server["server_address"] == "10.44.0.1"
        assert server["server_public_key"] == "server-public-key"
        assert server["runtime"] == "host_systemd"
        assert server["firewall"] == "ufw"
        assert server["status"] == "active"
        assert server["max_devices"] == 128
        action = _latest_admin_action(repo)
        assert action["admin_telegram_id"] == 9001
        assert action["action"] == "web_server_create"
        assert json.loads(action["metadata_json"])["server_id"] == server_id


def test_create_server_rejects_invalid_port_status_without_mutating(tmp_path: Path):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)
    form = client.get("/servers/new")

    response = client.post(
        "/servers/new",
        data=_server_form(
            _csrf_token(form.text),
            name="invalid-server",
            ssh_port="70000",
            status="retired",
        ),
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "ssh_port must be in 1..65535" in response.text
    with _repo(Path(settings.database_path)) as repo:
        assert _server_by_name(repo, "invalid-server") is None
        assert _latest_admin_action(repo) is None


def test_server_detail_shows_config_health_and_actions(tmp_path: Path):
    settings = _settings(tmp_path)
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="detail-vps")
        repo.record_server_health(
            server_id=server_id,
            status="online",
            latency_ms=45,
            ssh_ok=True,
            awg_ok=True,
            udp_port_ok=True,
            error=None,
        )
    client = _authenticated_client(settings)

    response = client.get(f"/servers/{server_id}")

    assert response.status_code == 200
    assert "detail-vps" in response.text
    assert "203.0.113.10" in response.text
    assert "10.44.0.1" in response.text
    assert "server-public-key" in response.text
    assert "online" in response.text
    assert "45 ms" in response.text
    assert f"/servers/{server_id}/health/run" in response.text
    assert f"/servers/{server_id}/sync/run" in response.text
    assert "Read-only local record: stores health status only; no VPS changes." in response.text
    assert (
        "Read-only compare: inventories AmneziaWG peers without adding or removing them."
        in response.text
    )
    assert (
        "Disable this server in the admin database only? No VPS peers will be changed."
        in response.text
    )


def test_server_detail_shows_vps_readiness_block(tmp_path: Path):
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        server_config_path=server_config_path,
        vps_apply_enabled=True,
    )
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="local")
        repo.record_server_health(
            server_id=server_id,
            status="online",
            latency_ms=64,
            ssh_ok=True,
            awg_ok=True,
            udp_port_ok=True,
            error=None,
        )
    client = _authenticated_client(settings)

    response = client.get(f"/servers/{server_id}")

    assert response.status_code == 200
    assert "VPS readiness" in response.text
    assert "VPS_APPLY_ENABLED" in response.text
    assert "enabled" in response.text
    assert "SERVER_CONFIG_PATH" in response.text
    assert "servers.yml" in response.text
    assert "Configured server" in response.text
    assert "local" in response.text
    assert "Runtime" in response.text
    assert "docker" in response.text
    assert "amnezia-awg2" in response.text
    assert "/opt/amnezia/awg/awg0.conf" in response.text
    assert "Latest health" in response.text
    assert "online" in response.text
    assert "64 ms" in response.text
    assert "Peer sync" in response.text
    assert "not run in this browser session" in response.text


def test_server_detail_shows_vps_retest_bundle_commands(tmp_path: Path):
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(tmp_path, server_config_path=server_config_path)
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="local")
    client = _authenticated_client(settings)

    response = client.get(f"/servers/{server_id}")

    assert response.status_code == 200
    assert "VPS retest bundle" in response.text
    assert "git pull origin codex-vps-test-prep" in response.text
    assert "python -m app.cli server retest-plan" in response.text
    assert f"--config {server_config_path}" in response.text
    assert "--server local" in response.text
    assert f"--db {settings.database_path}" in response.text
    assert "python -m app.cli server preflight" in response.text
    assert "python -m app.cli server sync-peers" in response.text


def test_server_sync_run_displays_peer_inventory_report(tmp_path: Path, monkeypatch):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    with _repo(Path(settings.database_path)) as repo:
        user_id = _seed_user(repo)
        server_id = _seed_server(repo, name="local")
        _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="active",
            vpn_ip="10.44.0.2",
            peer_public_key="known-peer",
        )
        _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="active",
            vpn_ip="10.44.0.4",
            peer_public_key="missing-peer",
        )
    monkeypatch.setattr(
        web_app,
        "_collect_server_peer_sync",
        lambda settings, server_id: {
            "known_count": 1,
            "unknown_count": 1,
            "missing_count": 1,
            "ignored_count": 1,
            "known_peers": [
                {
                    "device_id": 7,
                    "device_name": "active-device",
                    "device_status": "active",
                    "config_version": "amneziawg_v2",
                    "user_id": 3,
                    "user_display": "@alice",
                    "user_telegram_id": 1001,
                    "peer_public_key": "known-peer",
                    "vpn_ip": "10.44.0.2",
                    "allowed_ips": "10.44.0.2/32",
                }
            ],
            "unknown_peers": [
                {
                    "peer_public_key": "unknown-peer",
                    "allowed_ips": "10.44.0.3/32",
                }
            ],
            "missing_peers": [
                {
                    "device_id": 1,
                    "device_name": "missing-device",
                    "peer_public_key": "missing-peer",
                    "vpn_ip": "10.44.0.2",
                }
            ],
            "ignored_peers": [
                {
                    "peer_public_key": "amnezia-created-peer",
                    "allowed_ips": "10.44.0.10/32",
                }
            ],
            "error": "",
        },
    )
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")

    response = client.post(
        f"/servers/{server_id}/sync/run",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )
    page = client.get(f"/servers/{server_id}")

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}"
    assert "Синхронизация peer" in page.text
    assert "Известные peer панели" in page.text
    assert "1 / 1 / 1" in page.text
    assert "Working configs on server" in page.text
    assert "@alice" in page.text
    assert "1001" in page.text
    assert "active-device" in page.text
    assert "active" in page.text
    assert "amneziawg_v2" in page.text
    assert "confirmed live" in page.text
    assert "known-peer" in page.text
    assert "10.44.0.2/32" in page.text
    assert "unknown-peer" in page.text
    assert "10.44.0.3/32" in page.text
    assert "Созданы в Amnezia" in page.text
    assert "amnezia-created-peer" in page.text
    assert "Снять пометку" in page.text
    assert "missing-peer" in page.text
    assert (
        "VPS write gate: adding a missing local device writes one peer to AmneziaWG."
        in page.text
    )
    assert (
        "Add this local device peer to AmneziaWG on the VPS? "
        "This is a live write and should follow the VPS gate."
    ) in page.text
    assert "Recent server actions" in page.text
    assert "web_server_peer_sync_run" in page.text
    with _repo(Path(settings.database_path)) as repo:
        action = _latest_admin_action(repo)
        assert action["action"] == "web_server_peer_sync_run"


def test_server_detail_shows_managed_configs_before_peer_sync(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    with _repo(Path(settings.database_path)) as repo:
        user_id = _seed_user(repo)
        server_id = _seed_server(repo, name="local")
        _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="active",
            vpn_ip="10.44.0.8",
            peer_public_key="approved-peer",
        )
    client = _authenticated_client(settings)

    response = client.get(f"/servers/{server_id}")

    assert response.status_code == 200
    assert "Working configs on server" in response.text
    assert "@alice" in response.text
    assert "approved-peer" in response.text
    assert "10.44.0.8/32" in response.text
    assert "not synced" in response.text


def test_collect_server_peer_sync_enriches_known_peers_with_user_and_device(
    tmp_path: Path,
    monkeypatch,
):
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(tmp_path, server_config_path=server_config_path)
    with _repo(Path(settings.database_path)) as repo:
        user_id = _seed_user(repo)
        server_id = _seed_server(repo, name="local")
        device_id = _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="active",
            vpn_ip="10.44.0.2",
            peer_public_key="known-peer",
        )

    class FakePeerInventoryService:
        def __init__(self, repo):
            self._repo = repo

        def compare(self, server_id, collector):
            return PeerInventoryReport(
                known_remote_peers=(
                    RemotePeer(
                        peer_public_key="known-peer",
                        allowed_ips="10.44.0.2/32",
                        latest_handshake=0,
                        rx_bytes=0,
                        tx_bytes=0,
                    ),
                ),
                unknown_remote_peers=(),
                missing_local_peers=(),
            )

    monkeypatch.setattr(web_app, "PeerInventoryService", FakePeerInventoryService)

    report = web_app._collect_server_peer_sync(settings, server_id)

    assert report["known_peers"] == [
        {
            "device_id": device_id,
            "device_name": "active-device",
            "device_status": "active",
            "config_version": "amneziawg_v2",
            "user_id": user_id,
            "user_display": "@alice",
            "user_telegram_id": 1001,
            "peer_public_key": "known-peer",
            "vpn_ip": "10.44.0.2",
            "allowed_ips": "10.44.0.2/32",
        }
    ]


def test_ignore_unknown_remote_peer_records_it_for_server(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="local")
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")

    response = client.post(
        f"/servers/{server_id}/unknown-peers/ignore",
        data={
            "peer_public_key": "unknown-peer",
            "allowed_ips": "10.44.0.3/32",
            "csrf_token": _csrf_token(detail.text),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}"
    with _repo(Path(settings.database_path)) as repo:
        assert repo.list_ignored_remote_peer_keys(server_id) == {"unknown-peer"}
        action = _latest_admin_action(repo)
        assert action["action"] == "web_server_peer_ignore"


def test_unignore_amnezia_created_peer_removes_marker_for_server(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="local")
        repo.ignore_remote_peer(
            server_id=server_id,
            peer_public_key="amnezia-created-peer",
            allowed_ips="10.44.0.10/32",
        )
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")

    response = client.post(
        f"/servers/{server_id}/amnezia-peers/unmark",
        data={
            "peer_public_key": "amnezia-created-peer",
            "csrf_token": _csrf_token(detail.text),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}"
    with _repo(Path(settings.database_path)) as repo:
        assert repo.list_ignored_remote_peers(server_id) == []
        action = _latest_admin_action(repo)
        assert action["action"] == "web_server_peer_unmark_amnezia"


def test_add_missing_local_device_to_amnezia_applies_stored_peer(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str, str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier_with_apply(calls),
    )
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=server_config_path,
        vps_apply_enabled=True,
    )
    with _repo(Path(settings.database_path)) as repo:
        user_id = _seed_user(repo)
        server_id = _seed_server(repo, name="local")
        device_id = _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="active",
            vpn_ip="10.44.0.22",
            peer_public_key="missing-peer",
            preshared_key="stored-psk",
            encrypted=True,
        )
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")

    response = client.post(
        f"/servers/{server_id}/missing-devices/{device_id}/add",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}"
    assert calls == [("local", "missing-peer", "stored-psk", "10.44.0.22")]
    with _repo(Path(settings.database_path)) as repo:
        action = _latest_admin_action(repo)
        assert action["action"] == "web_server_missing_device_add"
        assert '"device_id": ' + str(device_id) in action["metadata_json"]


def test_add_missing_local_device_refreshes_sync_report_with_added_peer(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str, str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier_with_apply(calls),
    )
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=server_config_path,
        vps_apply_enabled=True,
    )
    with _repo(Path(settings.database_path)) as repo:
        user_id = _seed_user(repo)
        server_id = _seed_server(repo, name="local")
        device_id = _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="active",
            vpn_ip="10.44.0.22",
            peer_public_key="missing-peer",
            preshared_key="stored-psk",
            encrypted=True,
        )
    refreshed_report = {
        "known_count": 1,
        "unknown_count": 0,
        "missing_count": 0,
        "ignored_count": 0,
        "known_peers": [
                {
                    "device_id": device_id,
                    "device_name": "active-device",
                "device_status": "active",
                "config_version": "amneziawg_v2",
                "user_id": user_id,
                "user_display": "@alice",
                "user_telegram_id": 1001,
                "peer_public_key": "missing-peer",
                "vpn_ip": "10.44.0.22",
                "allowed_ips": "10.44.0.22/32",
            }
        ],
        "unknown_peers": [],
        "missing_peers": [],
        "ignored_peers": [],
        "error": "",
    }
    monkeypatch.setattr(
        web_app,
        "_collect_server_peer_sync",
        lambda settings, server_id: dict(refreshed_report),
    )
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")

    response = client.post(
        f"/servers/{server_id}/missing-devices/{device_id}/add",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )
    page = client.get(f"/servers/{server_id}")

    assert response.status_code == 303
    assert calls == [("local", "missing-peer", "stored-psk", "10.44.0.22")]
    assert "Added to Amnezia" in page.text
    assert "active-device" in page.text
    assert "missing-peer" in page.text
    assert "10.44.0.22/32" in page.text


def test_add_missing_local_device_returns_redacted_peer_apply_error(
    tmp_path: Path,
    monkeypatch,
):
    class FailingPeerApplier:
        def __init__(self, server, *, password=None):
            self._server = server

        def apply_peer(
            self,
            *,
            server,
            peer_public_key: str,
            preshared_key: str,
            vpn_ip: str,
        ) -> None:
            raise PeerApplyError(
                "Docker apply failed: PresharedKey = secret-psk"
            )

    monkeypatch.setattr(web_app, "ServerConfigPeerApplier", FailingPeerApplier)
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        server_config_path=server_config_path,
        vps_apply_enabled=True,
    )
    with _repo(Path(settings.database_path)) as repo:
        user_id = _seed_user(repo)
        server_id = _seed_server(repo, name="local")
        device_id = _seed_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            status="active",
            vpn_ip="10.44.0.22",
            peer_public_key="missing-peer",
            preshared_key="stored-psk",
            encrypted=True,
        )
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")

    response = client.post(
        f"/servers/{server_id}/missing-devices/{device_id}/add",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "PeerApplyError: Docker apply failed" in response.text
    assert "secret-psk" not in response.text
    with _repo(Path(settings.database_path)) as repo:
        action = _latest_admin_action(repo)
        metadata = json.loads(action["metadata_json"])
        assert action["action"] == "web_server_missing_device_add_failed"
        assert metadata["operation"] == "add_missing_local_device_to_amnezia"
        assert metadata["server_id"] == server_id
        assert metadata["device_id"] == device_id
        assert metadata["error_type"] == "PeerApplyError"
        assert "Docker apply failed" in metadata["redacted_error"]
        assert "secret-psk" not in metadata["redacted_error"]


def test_remove_unknown_remote_peer_revokes_it_from_amnezia(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier(calls),
    )
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=server_config_path,
        vps_apply_enabled=True,
    )
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="local")
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")

    response = client.post(
        f"/servers/{server_id}/unknown-peers/remove",
        data={
            "peer_public_key": "unknown-peer",
            "csrf_token": _csrf_token(detail.text),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}"
    assert calls == [("local", "unknown-peer")]
    with _repo(Path(settings.database_path)) as repo:
        action = _latest_admin_action(repo)
        assert action["action"] == "web_server_peer_remove"


def test_edit_server_updates_fields_and_records_action(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="edit-vps")
    client = _authenticated_client(settings)
    form = client.get(f"/servers/{server_id}/edit")
    assert form.status_code == 200

    response = client.post(
        f"/servers/{server_id}/edit",
        data=_server_form(
            _csrf_token(form.text),
            name="edit-vps-renamed",
            host="203.0.113.99",
            ssh_port="2200",
            endpoint_host="vpn-renamed.example.com",
            vpn_port="32000",
            vpn_network_cidr="10.55.0.0/24",
            server_address="10.55.0.1/24",
            server_public_key="server-public-updated",
            runtime="docker",
            firewall="nftables",
            status="degraded",
            max_devices="64",
        ),
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}"
    with _repo(Path(settings.database_path)) as repo:
        server = repo.get_server(server_id)
        assert server["name"] == "edit-vps-renamed"
        assert server["host"] == "203.0.113.99"
        assert server["ssh_port"] == 2200
        assert server["endpoint_host"] == "vpn-renamed.example.com"
        assert server["vpn_port"] == 32000
        assert server["vpn_network_cidr"] == "10.55.0.0/24"
        assert server["server_address"] == "10.55.0.1"
        assert server["server_public_key"] == "server-public-updated"
        assert server["runtime"] == "docker"
        assert server["firewall"] == "nftables"
        assert server["status"] == "degraded"
        assert server["max_devices"] == 64
        assert _latest_admin_action(repo)["action"] == "web_server_update"


def test_disable_server_marks_status_disabled_without_deleting_row(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="disable-vps")
    client = _authenticated_client(settings)
    detail = client.get(f"/servers/{server_id}")
    assert detail.status_code == 200

    response = client.post(
        f"/servers/{server_id}/disable",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}"
    with _repo(Path(settings.database_path)) as repo:
        server = repo.get_server(server_id)
        assert server["name"] == "disable-vps"
        assert server["status"] == "disabled"
        assert _latest_admin_action(repo)["action"] == "web_server_disable"


def test_server_health_page_shows_latest_health(tmp_path: Path):
    settings = _settings(tmp_path)
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="health-vps")
        repo.record_server_health(
            server_id=server_id,
            status="offline",
            latency_ms=250,
            ssh_ok=False,
            awg_ok=False,
            udp_port_ok=False,
            error="SSH connection timed out",
        )
    client = _authenticated_client(settings)

    response = client.get(f"/servers/{server_id}/health")

    assert response.status_code == 200
    assert "health-vps" in response.text
    assert "offline" in response.text
    assert "250 ms" in response.text
    assert "SSH connection timed out" in response.text
    assert "ssh: failed" in response.text
    assert "awg: failed" in response.text
    assert "udp port: failed" in response.text


def test_health_run_stores_unknown_when_server_config_is_unavailable(tmp_path: Path):
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=tmp_path / "missing-servers.yml",
    )
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="not-in-config")
    client = _authenticated_client(settings)
    page = client.get(f"/servers/{server_id}/health")
    assert page.status_code == 200

    response = client.post(
        f"/servers/{server_id}/health/run",
        data={"csrf_token": _csrf_token(page.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/servers/{server_id}/health"
    with _repo(Path(settings.database_path)) as repo:
        latest = repo.get_latest_server_health(server_id)
        assert latest is not None
        assert latest["status"] == "unknown"
        assert latest["latency_ms"] is None
        assert latest["ssh_ok"] == 0
        assert latest["awg_ok"] == 0
        assert latest["udp_port_ok"] == 0
        assert "Add server 'not-in-config' to" in latest["error"]
        action = _latest_admin_action(repo)
        assert action["action"] == "web_server_health_run"
        metadata = json.loads(action["metadata_json"])
        assert metadata["operation_id"] == "server.health.check"
        assert metadata["risk_class"] == "read-only-remote"
        assert metadata["consistency_status"] == "read-only"
        assert metadata["status"] == "unknown"


def test_invalid_csrf_does_not_create_edit_disable_or_run_health(tmp_path: Path):
    settings = _settings(tmp_path)
    with _repo(Path(settings.database_path)) as repo:
        server_id = _seed_server(repo, name="csrf-vps")
    client = _authenticated_client(settings)

    create_response = client.post(
        "/servers/new",
        data=_server_form("missing"),
        follow_redirects=False,
    )
    edit_response = client.post(
        f"/servers/{server_id}/edit",
        data=_server_form(
            "bad-token",
            name="mutated",
            host="203.0.113.200",
            status="disabled",
        ),
        follow_redirects=False,
    )
    disable_response = client.post(
        f"/servers/{server_id}/disable",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )
    run_response = client.post(
        f"/servers/{server_id}/health/run",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )
    sync_response = client.post(
        f"/servers/{server_id}/sync/run",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )

    assert create_response.status_code == 403
    assert edit_response.status_code == 403
    assert disable_response.status_code == 403
    assert run_response.status_code == 403
    assert sync_response.status_code == 403
    with _repo(Path(settings.database_path)) as repo:
        assert _server_by_name(repo, "default-vps") is None
        server = repo.get_server(server_id)
        assert server["name"] == "csrf-vps"
        assert server["host"] == "203.0.113.10"
        assert server["status"] == "active"
        assert repo.get_latest_server_health(server_id) is None
        assert _latest_admin_action(repo) is None


def _settings(
    tmp_path: Path,
    *,
    admin_telegram_ids: str = "",
    server_config_path: Path | None = None,
    vps_apply_enabled: bool = False,
) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret-for-web-servers-1234567890",
        database_path=str(tmp_path / "amneziya.sqlite3"),
        admin_telegram_ids=admin_telegram_ids,
        server_config_path=str(server_config_path or (tmp_path / "servers.yml")),
        vps_apply_enabled=vps_apply_enabled,
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
    )


def _client(*, settings: Settings) -> TestClient:
    return TestClient(create_web_app(settings), base_url="https://testserver")


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


class _repo:
    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._conn = None

    def __enter__(self) -> Repository:
        self._conn = connect(self._database_path)
        initialize_schema(self._conn)
        return Repository(self._conn)

    def __exit__(self, *args) -> None:
        assert self._conn is not None
        self._conn.close()


def _seed_user(repo: Repository) -> int:
    return repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )


def _seed_server(repo: Repository, *, name: str) -> int:
    return repo.upsert_server_config(
        name=name,
        host="203.0.113.10",
        ssh_port=22,
        endpoint_host="vpn.example.test",
        vpn_port=30001,
        vpn_network_cidr="10.44.0.0/24",
        server_address="10.44.0.1/24",
        server_public_key="server-public-key",
        runtime="host_systemd",
        firewall="ufw",
        max_devices=254,
    )


def _seed_device(
    repo: Repository,
    *,
    user_id: int,
    server_id: int,
    status: str,
    vpn_ip: str = "10.44.0.2",
    peer_public_key: str = "active-public",
    preshared_key: str | None = None,
    encrypted: bool = False,
) -> int:
    private_key = f"{status}-private"
    stored_preshared_key = preshared_key or f"{status}-psk"
    if encrypted:
        secret_box = SecretBox.from_app_secret("test-secret-for-web-servers-1234567890")
        private_key = secret_box.encrypt_text(private_key)
        stored_preshared_key = secret_box.encrypt_text(stored_preshared_key)
    else:
        private_key = f"v1:{private_key}"
        stored_preshared_key = f"v1:{stored_preshared_key}"
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name=f"{status}-device",
        duration_days=7,
        vpn_ip=vpn_ip,
        peer_public_key=peer_public_key,
        peer_private_key_encrypted=private_key,
        preshared_key_encrypted=stored_preshared_key,
        config_version="amneziawg_v2",
    )
    if status == "revoked":
        repo.revoke_device(
            device_id,
            reason="test",
            revoked_at="2026-05-29T10:00:00Z",
        )
    return device_id


def _server_form(csrf_token: str, **overrides: str) -> dict[str, str]:
    payload = {
        "name": "default-vps",
        "host": "203.0.113.20",
        "ssh_port": "22",
        "endpoint_host": "vpn.example.com",
        "vpn_port": "30001",
        "vpn_network_cidr": "10.44.0.0/24",
        "server_address": "10.44.0.1/24",
        "server_public_key": "server-public-key",
        "runtime": "host_systemd",
        "firewall": "ufw",
        "status": "active",
        "max_devices": "254",
        "csrf_token": csrf_token,
    }
    payload.update(overrides)
    return payload


def _server_by_name(repo: Repository, name: str):
    return repo._conn.execute("SELECT * FROM servers WHERE name = ?", (name,)).fetchone()


def _latest_admin_action(repo: Repository):
    return repo._conn.execute(
        "SELECT * FROM admin_actions ORDER BY id DESC LIMIT 1"
    ).fetchone()


def _write_server_config(tmp_path: Path, *, server_name: str) -> Path:
    path = tmp_path / "servers.yml"
    path.write_text(
        f"""
servers:
  - name: {server_name}
    enabled: true
    location: test
    ssh:
      host: 127.0.0.1
      port: 22
      user: root
      auth:
        type: password
    vpn:
      endpoint_host: vpn.example.test
      port: 37661
      interface: awg0
      network_cidr: 10.44.0.0/24
      server_address: 10.44.0.1/24
      dns: 1.1.1.1
      allowed_ips: 0.0.0.0/0
      max_devices: 254
      server_public_key: server-public-key
    firewall:
      provider: ufw
      open_vpn_port: true
    runtime:
      type: docker
      container_name: amnezia-awg2
      config_path: /opt/amnezia/awg/awg0.conf
""".lstrip(),
        encoding="utf-8",
    )
    return path


def _fake_peer_applier(calls: list[tuple[str, str]]):
    class FakePeerApplier:
        def __init__(self, server, *, password=None):
            self._server = server

        def remove_peer(self, *, server, peer_public_key: str) -> None:
            calls.append((server.name, peer_public_key))

    return FakePeerApplier


def _fake_peer_applier_with_apply(calls: list[tuple[str, str, str, str]]):
    class FakePeerApplier:
        def __init__(self, server, *, password=None):
            self._server = server

        def apply_peer(
            self,
            *,
            server,
            peer_public_key: str,
            preshared_key: str,
            vpn_ip: str,
        ) -> None:
            calls.append((server.name, peer_public_key, preshared_key, vpn_ip))

    return FakePeerApplier
