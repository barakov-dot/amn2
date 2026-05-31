import base64
import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.access import (
    AccessService,
    IpAllocationConflict,
    MaxDevicesReached,
    OrderAlreadyFulfilled,
    OrderNotApprovable,
    RemoteOperationPartialFailure,
)
from app.server.peer_apply import PeerApplyError
import app.vpn.amneziawg_v2.config as awg_config


def test_approve_order_creates_active_device_with_encrypted_secrets(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    secret_box = SecretBox.from_app_secret("test-secret-for-access-service-1234567890")
    service = AccessService(repo=repo, secret_box=secret_box)
    result = service.approve_order(order_id=order_id, server_id=server_id, device_name="iPhone", admin_telegram_id=999)

    device = repo.get_device(result.device_id)
    assert device["status"] == "active"
    assert device["vpn_ip"] == "10.8.0.2"
    assert device["peer_private_key_encrypted"].startswith("v1:")
    assert "PrivateKey =" in result.config_text
    private_key = secret_box.decrypt_text(device["peer_private_key_encrypted"])
    derived_public_key = base64.b64encode(
        x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    assert device["peer_public_key"] == derived_public_key


def test_approve_order_uses_client_config_defaults(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"),
        client_config_defaults=awg_config.ClientConfigDefaults(
            dns="9.9.9.9",
            allowed_ips="10.0.0.0/8",
            persistent_keepalive=15,
            jc=8,
            jmin=12,
            jmax=42,
            s1=11,
            s2=22,
            h1=101,
            h2=202,
            h3=303,
            h4=404,
        ),
    )

    result = service.approve_order(
        order_id=order_id,
        server_id=server_id,
        device_name="iPhone",
        admin_telegram_id=999,
    )

    assert "DNS = 9.9.9.9" in result.config_text
    assert "AllowedIPs = 10.0.0.0/8" in result.config_text
    assert "PersistentKeepalive = 15" in result.config_text
    assert "Jc = 8" in result.config_text
    assert "Jmin = 12" in result.config_text
    assert "Jmax = 42" in result.config_text
    assert "S1 = 11" in result.config_text
    assert "S2 = 22" in result.config_text
    assert "H1 = 101" in result.config_text
    assert "H2 = 202" in result.config_text
    assert "H3 = 303" in result.config_text
    assert "H4 = 404" in result.config_text


def test_approve_order_uses_plan_duration_when_order_has_plan(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    repo.seed_default_plans()
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(
        user_id=user_id,
        plan_id="days_30",
        payment_mode="free_test",
    )

    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"),
        duration_days=7,
    )
    result = service.approve_order(
        order_id=order_id,
        server_id=server_id,
        device_name="iPhone",
        admin_telegram_id=999,
    )

    device = repo.get_device(result.device_id)
    assert device["duration_days"] == 30


def test_approve_order_enforces_max_devices(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")

    service = AccessService(repo=repo, secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"), max_devices_per_user=1)
    first_order = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    second_order = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    service.approve_order(first_order, server_id, "iPhone", admin_telegram_id=999)

    with pytest.raises(MaxDevicesReached):
        service.approve_order(second_order, server_id, "Laptop", admin_telegram_id=999)


def test_approve_order_rejects_already_fulfilled_order_without_creating_device(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    service = AccessService(repo=repo, secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"))
    first_result = service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    with pytest.raises(OrderAlreadyFulfilled):
        service.approve_order(order_id, server_id, "Laptop", admin_telegram_id=999)

    order = repo.get_order(order_id)
    assert repo.count_active_devices(user_id) == 1
    assert order["device_id"] == first_result.device_id


@pytest.mark.parametrize("status", ["payment_pending", "rejected"])
def test_approve_order_rejects_non_approvable_order_without_creating_device(tmp_path, status):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    conn.commit()
    original_order = dict(repo.get_order(order_id))

    service = AccessService(repo=repo, secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"))

    with pytest.raises(OrderNotApprovable, match=status):
        service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    assert repo.count_active_devices(user_id) == 0
    assert dict(repo.get_order(order_id)) == original_order


def test_approve_order_rolls_back_device_and_order_when_admin_audit_fails(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = FailingAdminActionRepository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    service = AccessService(repo=repo, secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"))

    with pytest.raises(RuntimeError, match="audit failed"):
        service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    order = repo.get_order(order_id)
    assert repo.count_active_devices(user_id) == 0
    assert order["status"] == "manual_review"
    assert order["device_id"] is None


def test_approve_order_reports_partial_failure_when_remote_apply_succeeds_but_admin_audit_fails(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = FailingAdminActionRepository(conn)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    peer_applier = RecordingPeerApplier()

    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"),
        peer_applier=peer_applier,
    )
    with pytest.raises(RemoteOperationPartialFailure) as exc_info:
        service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    failure = exc_info.value.result
    order = repo.get_order(order_id)
    assert failure.operation_id == "access.approve_order"
    assert failure.consistency_status == "partial-failure"
    assert failure.remote_applied is True
    assert failure.local_applied is False
    assert "manual review" in failure.recovery_note.lower()
    assert peer_applier.calls
    assert repo.count_active_devices(user_id) == 0
    assert order["status"] == "manual_review"
    assert order["device_id"] is None


def test_approve_order_applies_peer_before_fulfilling_order(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    peer_applier = RecordingPeerApplier()

    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"),
        peer_applier=peer_applier,
    )
    result = service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    device = repo.get_device(result.device_id)
    assert peer_applier.calls == [
        {
            "server_id": server_id,
            "peer_public_key": device["peer_public_key"],
            "preshared_key": SecretBox.from_app_secret(
                "test-secret-for-access-service-1234567890"
            ).decrypt_text(device["preshared_key_encrypted"]),
            "vpn_ip": "10.8.0.2",
        }
    ]
    assert repo.get_order(order_id)["status"] == "fulfilled"


def test_approve_order_allocates_after_live_remote_ips_from_peer_applier(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.1.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    peer_applier = RecordingPeerApplier(remote_allocated_ips=["10.8.1.1/32", "10.8.1.2/32"])

    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"),
        peer_applier=peer_applier,
    )
    result = service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    device = repo.get_device(result.device_id)
    assert device["vpn_ip"] == "10.8.1.3"
    assert peer_applier.calls[0]["vpn_ip"] == "10.8.1.3"


def test_approve_order_rolls_back_device_and_order_when_peer_apply_fails(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"),
        peer_applier=RecordingPeerApplier(error=PeerApplyError("apply failed")),
    )

    with pytest.raises(PeerApplyError):
        service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    order = repo.get_order(order_id)
    assert repo.count_active_devices(user_id) == 0
    assert order["status"] == "manual_review"
    assert order["device_id"] is None


def test_approve_order_retries_ip_allocation_after_duplicate_ip_race(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = DuplicateIpRaceRepository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    service = AccessService(repo=repo, secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"))
    result = service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    assert repo.get_device(result.device_id)["vpn_ip"] == "10.8.0.3"


def test_approve_order_raises_clear_error_after_duplicate_ip_retries_are_exhausted(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = AlwaysDuplicateIpRepository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    service = AccessService(repo=repo, secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"))

    with pytest.raises(IpAllocationConflict):
        service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    order = repo.get_order(order_id)
    assert repo.count_active_devices(user_id) == 0
    assert order["status"] == "manual_review"
    assert order["device_id"] is None


def test_approve_order_raises_clear_error_when_retry_refresh_exhausts_ips(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = LastFreeIpConsumedRepository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/30")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")

    service = AccessService(repo=repo, secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"))

    with pytest.raises(IpAllocationConflict):
        service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    order = repo.get_order(order_id)
    assert repo.count_active_devices(user_id) == 0
    assert order["status"] == "manual_review"
    assert order["device_id"] is None


class FailingAdminActionRepository(Repository):
    def record_admin_action(self, **kwargs):
        raise RuntimeError("audit failed")


class RecordingPeerApplier:
    def __init__(self, *, error=None, remote_allocated_ips=None):
        self.calls = []
        self._error = error
        self._remote_allocated_ips = list(remote_allocated_ips or [])

    def apply_peer(self, *, server, peer_public_key, preshared_key, vpn_ip):
        self.calls.append(
            {
                "server_id": int(server["id"]),
                "peer_public_key": peer_public_key,
                "preshared_key": preshared_key,
                "vpn_ip": vpn_ip,
            }
        )
        if self._error is not None:
            raise self._error

    def list_allocated_ips(self, *, server):
        return list(self._remote_allocated_ips)


class DuplicateIpRaceRepository(Repository):
    def __init__(self, conn):
        super().__init__(conn)
        self._duplicate_seen = False

    def list_allocated_ips(self, server_id: int) -> list[str]:
        allocated_ips = super().list_allocated_ips(server_id)
        if self._duplicate_seen and "10.8.0.2" not in allocated_ips:
            allocated_ips.append("10.8.0.2")
        return allocated_ips

    def create_device(self, **kwargs):
        if kwargs["vpn_ip"] == "10.8.0.2" and not self._duplicate_seen:
            self._duplicate_seen = True
            raise sqlite3.IntegrityError("UNIQUE constraint failed: devices.server_id, devices.vpn_ip")
        return super().create_device(**kwargs)


class AlwaysDuplicateIpRepository(Repository):
    def create_device(self, **kwargs):
        raise sqlite3.IntegrityError("UNIQUE constraint failed: devices.server_id, devices.vpn_ip")


class LastFreeIpConsumedRepository(Repository):
    def __init__(self, conn):
        super().__init__(conn)
        self._duplicate_seen = False

    def list_allocated_ips(self, server_id: int) -> list[str]:
        allocated_ips = super().list_allocated_ips(server_id)
        if self._duplicate_seen and "10.8.0.2" not in allocated_ips:
            allocated_ips.append("10.8.0.2")
        return allocated_ips

    def create_device(self, **kwargs):
        self._duplicate_seen = True
        raise sqlite3.IntegrityError("UNIQUE constraint failed: devices.server_id, devices.vpn_ip")
