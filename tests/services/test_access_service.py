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
    OperatorOwnerNotActive,
    OperatorOwnerNotFound,
    OperatorOwnerSharedRequiresAdmin,
    OperatorPeerApplierRequired,
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


def test_approve_order_enforces_configured_plan_device_quota(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    repo.upsert_plan(
        plan_id="single_device",
        name="Single device",
        duration_days=30,
        max_devices=1,
    )
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    first_order = repo.create_order(
        user_id=user_id,
        plan_id="single_device",
        payment_mode="free_test",
    )
    second_order = repo.create_order(
        user_id=user_id,
        plan_id="single_device",
        payment_mode="free_test",
    )
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        max_devices_per_user=10,
    )

    first = service.approve_order(
        first_order,
        server_id,
        "iPhone",
        admin_telegram_id=999,
    )

    assert first.assignment_mode == "dedicated_device"
    assert repo.get_device(first.device_id)["assignment_mode"] == "dedicated_device"
    with pytest.raises(MaxDevicesReached):
        service.approve_order(
            second_order,
            server_id,
            "Laptop",
            admin_telegram_id=999,
        )


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
    assert failure.consistency_status == "remote-changed-local-failed"
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


def test_create_operator_device_uses_explicit_owner_and_records_audit(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    other_user_id = repo.upsert_user(
        telegram_id=1002,
        username="bob",
        first_name="Bob",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    written_configs = []
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )

    result = service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="Neobyatnaya-AMNZ-N-android-tv-02",
        duration_days=365,
        admin_telegram_id=999,
        config_version="amneziawg_v2",
        config_artifact_writer=lambda text: written_configs.append(text)
        or "private/device.conf",
    )

    device = repo.get_device(result.device_id)
    assert int(device["user_id"]) == owner_user_id
    assert int(device["user_id"]) != other_user_id
    assert int(device["duration_days"]) == 365
    assert device["config_version"] == "amneziawg_v2"
    assert device["assignment_mode"] == "dedicated_device"
    assert result.assignment_mode == "dedicated_device"
    assert result.config_artifact_path == "private/device.conf"
    assert written_configs == [result.config_text]
    audit = conn.execute(
        "SELECT action, target_user_id, target_device_id, metadata_json "
        "FROM admin_actions WHERE target_device_id = ?",
        (result.device_id,),
    ).fetchone()
    assert audit["action"] == "access.create_operator_device"
    assert int(audit["target_user_id"]) == owner_user_id
    assert int(audit["target_device_id"]) == result.device_id
    assert "server_id" in audit["metadata_json"]
    assert peer_applier.calls
    assert conn.execute(
        "SELECT COUNT(*) FROM orders WHERE device_id = ?", (result.device_id,)
    ).fetchone()[0] == 0


def test_create_operator_owner_shared_profile_bypasses_client_device_limit(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_user_for_admin(
        telegram_id=1001,
        username="owner",
        first_name="Owner",
        last_name=None,
        email=None,
        status="active",
        is_admin=True,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        max_devices_per_user=1,
        peer_applier=peer_applier,
    )
    service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="Owner phone",
        duration_days=365,
        admin_telegram_id=999,
    )

    shared = service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="Neobyatnaya.NET shared",
        duration_days=365,
        admin_telegram_id=999,
        assignment_mode="owner_shared",
    )

    assert shared.assignment_mode == "owner_shared"
    assert repo.get_device(shared.device_id)["assignment_mode"] == "owner_shared"
    assert repo.count_active_devices(owner_user_id) == 2
    audit = conn.execute(
        "SELECT metadata_json FROM admin_actions WHERE target_device_id = ?",
        (shared.device_id,),
    ).fetchone()[0]
    assert '"assignment_mode": "owner_shared"' in audit
    assert '"physical_device_count_enforceable": false' in audit


def test_create_operator_owner_shared_rejects_client_owner_without_remote_apply(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    client_user_id = repo.upsert_user(
        telegram_id=1001,
        username="client",
        first_name="Client",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )

    with pytest.raises(OperatorOwnerSharedRequiresAdmin):
        service.create_operator_device(
            owner_user_id=client_user_id,
            server_id=server_id,
            device_name="Client shared",
            duration_days=30,
            admin_telegram_id=999,
            assignment_mode="owner_shared",
        )

    assert repo.list_user_devices(client_user_id, statuses=("active", "pending")) == []
    assert peer_applier.calls == []


def test_create_operator_device_rejects_non_active_owner_without_remote_apply(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    repo.set_user_status_for_admin(owner_user_id, "blocked")
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )

    with pytest.raises(OperatorOwnerNotActive):
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Android TV",
            duration_days=30,
            admin_telegram_id=999,
        )

    assert repo.count_active_devices(owner_user_id) == 0
    assert peer_applier.calls == []


def test_create_operator_device_rejects_missing_owner_without_remote_apply(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )

    with pytest.raises(OperatorOwnerNotFound):
        service.create_operator_device(
            owner_user_id=9999,
            server_id=server_id,
            device_name="Android TV",
            duration_days=30,
            admin_telegram_id=999,
        )

    assert peer_applier.calls == []


def test_create_operator_device_enforces_device_limit(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        max_devices_per_user=1,
        peer_applier=RecordingPeerApplier(),
    )
    service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="First",
        duration_days=30,
        admin_telegram_id=999,
    )

    with pytest.raises(MaxDevicesReached):
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Second",
            duration_days=30,
            admin_telegram_id=999,
        )


def test_create_operator_device_requires_live_peer_applier(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
    )

    with pytest.raises(OperatorPeerApplierRequired):
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Android TV",
            duration_days=30,
            admin_telegram_id=999,
        )

    assert repo.count_active_devices(owner_user_id) == 0


def test_create_operator_device_reports_partial_failure_after_remote_apply(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = FailingAdminActionRepository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )

    with pytest.raises(RemoteOperationPartialFailure) as exc_info:
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Android TV",
            duration_days=30,
            admin_telegram_id=999,
        )

    failure = exc_info.value.result
    assert failure.operation_id == "access.create_operator_device"
    assert failure.consistency_status == "remote-changed-local-failed"
    assert failure.remote_applied is True
    assert failure.local_applied is False
    assert "explicit owner" in failure.recovery_note.lower()
    assert peer_applier.calls
    assert repo.count_active_devices(owner_user_id) == 0


def test_create_operator_device_does_not_apply_peer_when_render_fails(
    tmp_path, monkeypatch
):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )
    monkeypatch.setattr(
        "app.services.access.render_client_config_for_version",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("render failed")),
    )

    with pytest.raises(RuntimeError, match="render failed"):
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Android TV",
            duration_days=30,
            admin_telegram_id=999,
        )

    assert peer_applier.calls == []
    assert repo.count_active_devices(owner_user_id) == 0


def test_create_operator_device_artifact_failure_is_partial_after_remote_apply(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )

    with pytest.raises(RemoteOperationPartialFailure) as exc_info:
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Android TV",
            duration_days=30,
            admin_telegram_id=999,
            config_artifact_writer=lambda _text: (_ for _ in ()).throw(
                OSError("artifact write failed")
            ),
        )

    assert exc_info.value.result.operation_id == "access.create_operator_device"
    assert peer_applier.calls
    assert repo.count_active_devices(owner_user_id) == 0
    reconciliation = conn.execute(
        "SELECT action, metadata_json FROM admin_actions WHERE target_user_id = ?",
        (owner_user_id,),
    ).fetchone()
    assert reconciliation["action"] == "access.create_operator_device.partial_failure"
    assert "remote-changed-local-failed" in reconciliation["metadata_json"]
