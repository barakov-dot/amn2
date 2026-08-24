import base64
import ipaddress
import sqlite3
from contextlib import contextmanager
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services import access as access_module
from app.services.access import (
    AccessService,
    Awg3IssuerMaterial,
    IpAllocationConflict,
    MaxDevicesReached,
    OperatorOwnerNotActive,
    OperatorOwnerNotFound,
    OperatorOwnerSharedRequiresAdmin,
    OperatorPeerApplierRequired,
    OperatorDeviceContext,
    OrderAlreadyFulfilled,
    OrderNotApprovable,
    RemoteOperationPartialFailure,
)
from app.vpn.amneziawg_v3.config import HeaderProtectionSecretRef
from app.services.config_identity import build_config_identity
from app.services.device_lifecycle import list_device_lifecycle_events
from app.services.device_passports import fingerprint_config, get_device_passport
from app.services.vpn_runtime_instances import RuntimeInstanceSpec
from app.server.peer_apply import PeerApplyError
import app.vpn.amneziawg_v2.config as awg_config
from app.access_expiry import AccessExpiry, INDEFINITE
from app.vpn.protocol_versions import ProtocolVersion


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
    repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="Existing local device",
        duration_days=30,
        vpn_ip="10.8.1.3",
        peer_public_key="existing-local-peer",
        peer_private_key_encrypted="encrypted-private-key",
        preshared_key_encrypted="encrypted-preshared-key",
        config_version="amneziawg_v2",
    )
    peer_applier = RecordingPeerApplier(remote_allocated_ips=["10.8.1.200/32"])

    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-for-access-service-1234567890"),
        peer_applier=peer_applier,
    )
    result = service.approve_order(order_id, server_id, "iPhone", admin_telegram_id=999)

    device = repo.get_device(result.device_id)
    assert device["vpn_ip"] == "10.8.1.201"
    assert peer_applier.calls[0]["vpn_ip"] == "10.8.1.201"


def test_allocator_default_preserves_awg2_remote_high_watermark():
    vpn_ip = access_module._allocate_vpn_ip(
        network_cidr="10.9.0.0/24",
        server_address="10.9.0.1/24",
        allocated_ips=["10.9.0.3", "10.8.0.2"],
        remote_allocated_ips=["10.9.0.200/32", "10.8.0.3/32"],
    )

    assert vpn_ip == "10.9.0.201"


def test_allocator_lowest_free_uses_first_available_awg3_address():
    vpn_ip = access_module._allocate_vpn_ip(
        network_cidr="10.9.0.0/24",
        server_address="10.9.0.1/24",
        allocated_ips=["10.9.0.3", "10.8.0.2"],
        remote_allocated_ips=["10.9.0.200/32", "10.8.0.3/32"],
        strategy="lowest_free",
    )

    assert vpn_ip == "10.9.0.2"


def test_allocator_awg2_high_watermark_does_not_wrap_to_lower_free_addresses():
    with pytest.raises(RuntimeError, match="No available VPN IP addresses"):
        access_module._allocate_vpn_ip(
            network_cidr="10.9.0.0/24",
            server_address="10.9.0.1/24",
            allocated_ips=[f"10.9.0.{suffix}" for suffix in range(201, 255)],
            remote_allocated_ips=["10.9.0.200/32"],
        )


def test_allocator_does_not_materialize_a_huge_host_iterator(monkeypatch):
    real_network = ipaddress.ip_network("0.0.0.0/0")

    class GuardedHosts:
        def __init__(self):
            self._next = 1

        def __iter__(self):
            return self

        def __next__(self):
            address = ipaddress.ip_address(self._next)
            self._next += 1
            return address

        def __length_hint__(self):
            raise AssertionError("allocator materialized the host iterator")

    class HugeNetwork:
        num_addresses = 2**32

        def __contains__(self, address):
            return address in real_network

        def hosts(self):
            return GuardedHosts()

    monkeypatch.setattr(
        access_module.ipaddress,
        "ip_network",
        lambda _cidr, strict=False: HugeNetwork(),
    )

    vpn_ip = access_module._allocate_vpn_ip(
        network_cidr="0.0.0.0/0",
        server_address="0.0.0.1",
        allocated_ips=["0.0.0.2"],
        remote_allocated_ips=["0.0.0.3/32"],
        strategy="lowest_free",
    )

    assert vpn_ip == "0.0.0.4"


def test_allocator_reports_exhaustion_after_all_usable_addresses_are_reserved():
    with pytest.raises(RuntimeError, match="No available VPN IP addresses"):
        access_module._allocate_vpn_ip(
            network_cidr="10.9.0.0/30",
            server_address="10.9.0.1/30",
            allocated_ips=[],
            remote_allocated_ips=["10.9.0.2/32"],
            strategy="lowest_free",
        )


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


class FailingDevicePassportRepository(Repository):
    def create_device_passport(self, **kwargs):
        raise RuntimeError("passport persistence unavailable")


class RecordingPeerApplier:
    def __init__(self, *, error=None, remote_allocated_ips=None):
        self.calls = []
        self.list_calls = []
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
        self.list_calls.append(int(server["id"]))
        return list(self._remote_allocated_ips)


def _access_side_effect_counts(conn):
    return {
        table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in (
            "devices",
            "device_passports",
            "device_lifecycle_events",
            "admin_actions",
        )
    }


def _install_access_boundary_probes(monkeypatch, repo):
    calls = {"transaction": 0, "owner": 0, "keypair": 0, "preshared_key": 0}
    original_transaction = repo.transaction
    original_get_user = repo.get_user
    original_generate_keypair = access_module.generate_keypair
    original_generate_key = access_module.generate_key

    @contextmanager
    def recording_transaction():
        calls["transaction"] += 1
        with original_transaction():
            yield

    def recording_get_user(user_id):
        calls["owner"] += 1
        return original_get_user(user_id)

    def recording_generate_keypair():
        calls["keypair"] += 1
        return original_generate_keypair()

    def recording_generate_key():
        calls["preshared_key"] += 1
        return original_generate_key()

    monkeypatch.setattr(repo, "transaction", recording_transaction)
    monkeypatch.setattr(repo, "get_user", recording_get_user)
    monkeypatch.setattr(access_module, "generate_keypair", recording_generate_keypair)
    monkeypatch.setattr(access_module, "generate_key", recording_generate_key)
    return calls


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


def test_create_operator_device_records_passport_and_config_ready_evidence(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Operator")
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=RecordingPeerApplier(),
    )

    result = service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="Linux laptop",
        duration_days=30,
        admin_telegram_id=999,
        device_context=OperatorDeviceContext(
            platform="linux",
            official_client_type="amnezia_vpn",
            client_version="4.8.19.0",
            import_method="conf_file",
        ),
    )

    passport_row = repo.get_device_passport_by_local_device_id(result.device_id)
    assert passport_row is not None
    passport = get_device_passport(repo, str(passport_row["device_id"]))
    assert passport.local_device_id == result.device_id
    assert passport.owner_user_id == owner_user_id
    assert passport.server_id == server_id
    assert passport.config_schema_version == "amneziawg_v2"
    assert passport.platform == "linux"
    assert passport.official_client_type == "amnezia_vpn"
    assert passport.client_version == "4.8.19.0"
    assert passport.import_method == "conf_file"
    assert passport.config_fingerprint == fingerprint_config(result.config_text)

    lifecycle = list_device_lifecycle_events(
        repo,
        passport_device_id=passport.device_id,
    )
    assert [(event.stage, event.status) for event in lifecycle] == [
        ("config_ready", "completed")
    ]
    assert lifecycle[0].evidence.safe_metadata() == {
        "source": "operator_config_renderer",
        "reference": "schema:amneziawg_v2",
    }
    database_dump = "\n".join(conn.iterdump())
    assert result.config_text not in database_dump
    assert "PrivateKey =" not in lifecycle[0].evidence.reference
    assert all(event.stage != "delivered" for event in lifecycle)


def test_create_operator_device_binds_the_preallocated_passport_identity(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Preallocated")
    server_id = repo.ensure_default_server(
        name="local", network_cidr="10.8.0.0/24"
    )
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=RecordingPeerApplier(),
    )

    result = service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="AWG3 laptop",
        duration_days=30,
        admin_telegram_id=999,
        config_version="amneziawg_v2",
        passport_device_id="dev_0123456789abcdef0123456789abcdef",
        device_context=OperatorDeviceContext(
            platform="windows",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
            protocol_version="awg2",
            runtime_instance_id="runtime-awg3",
            client_identity_evidence_status="verified",
            compatibility_evidence_id="compat-awg3",
        ),
    )

    assert result.passport_device_id == "dev_0123456789abcdef0123456789abcdef"
    passport = repo.get_device_passport("dev_0123456789abcdef0123456789abcdef")
    assert passport is not None
    assert passport["owner_user_id"] == owner_user_id
    assert passport["local_device_id"] == result.device_id


def test_create_operator_unassigned_indefinite_slot_has_no_fake_passport(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Recipient")
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=RecordingPeerApplier(),
        max_devices_per_user=4,
    )

    result = service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="NEOBYATNAYA.NET-Recipient-01",
        duration_days=None,
        expiry=AccessExpiry(INDEFINITE, None, None),
        admin_telegram_id=999,
        assignment_mode="recipient_unassigned",
    )

    device = repo.get_device(result.device_id)
    assert device["assignment_mode"] == "recipient_unassigned"
    assert device["expiry_policy"] == "indefinite"
    assert device["duration_days"] is None
    assert device["expires_at"] is None
    assert device["config_fingerprint"] == fingerprint_config(result.config_text)
    assert result.passport_device_id is None
    assert result.config_fingerprint == device["config_fingerprint"]
    assert repo.get_device_passport_by_local_device_id(result.device_id) is None
    assert conn.execute("SELECT COUNT(*) FROM device_lifecycle_events").fetchone()[0] == 0


def test_create_operator_device_stores_precomputed_canonical_display_name(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Иван")
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=RecordingPeerApplier(),
    )
    result = service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="  Pixel 8  ",
        duration_days=30,
        admin_telegram_id=999,
    )

    identity = build_config_identity(
        user_label="Иван",
        device_label="Pixel 8",
        collision_device_id=result.device_id,
    )
    assert repo.get_device(result.device_id)["name"] == identity.display_name
    assert result.config_filename == identity.filename


def test_create_operator_device_uses_safe_owner_label_fallbacks(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    username_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    full_name_user_id = repo.upsert_user(
        telegram_id=1002,
        username=None,
        first_name="Bob",
        last_name="Smith",
    )
    local_user_id = repo.upsert_user(
        telegram_id=987654321,
        username=None,
        first_name=None,
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=RecordingPeerApplier(),
    )

    username_result = service.create_operator_device(
        owner_user_id=username_user_id,
        server_id=server_id,
        device_name="Tablet",
        duration_days=30,
        admin_telegram_id=999,
    )
    full_name_result = service.create_operator_device(
        owner_user_id=full_name_user_id,
        server_id=server_id,
        device_name="Laptop",
        duration_days=30,
        admin_telegram_id=999,
    )
    local_result = service.create_operator_device(
        owner_user_id=local_user_id,
        server_id=server_id,
        device_name="Router",
        duration_days=30,
        admin_telegram_id=999,
    )

    assert repo.get_device(username_result.device_id)["name"] == (
        "NEOBYATNAYA.NET — alice — Tablet"
    )
    assert repo.get_device(full_name_result.device_id)["name"] == (
        "NEOBYATNAYA.NET — Bob Smith — Laptop"
    )
    fallback_name = str(repo.get_device(local_result.device_id)["name"])
    assert fallback_name == f"NEOBYATNAYA.NET — User-{local_user_id} — Router"
    assert "987654321" not in fallback_name


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


def test_create_operator_device_rejects_invalid_context_before_remote_apply(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Operator")
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )

    with pytest.raises(ValueError, match="unsupported device platform"):
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Laptop",
            duration_days=30,
            admin_telegram_id=999,
            device_context=OperatorDeviceContext(platform="unsupported-os"),
        )

    assert peer_applier.calls == []
    assert repo.count_active_devices(owner_user_id) == 0
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM device_lifecycle_events").fetchone()[0] == 0


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
    assert conn.execute(
        "SELECT COUNT(*) FROM device_lifecycle_events WHERE stage = 'delivered'"
    ).fetchone()[0] == 0


def test_create_operator_device_passport_failure_preserves_partial_failure(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = FailingDevicePassportRepository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Operator")
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
            device_name="Linux laptop",
            duration_days=30,
            admin_telegram_id=999,
            device_context=OperatorDeviceContext(platform="linux"),
        )

    assert exc_info.value.result.operation_id == "access.create_operator_device"
    assert exc_info.value.result.consistency_status == "remote-changed-local-failed"
    assert peer_applier.calls
    assert repo.count_active_devices(owner_user_id) == 0
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM device_lifecycle_events WHERE stage = 'delivered'"
    ).fetchone()[0] == 0


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
    assert conn.execute(
        "SELECT COUNT(*) FROM device_lifecycle_events WHERE stage = 'delivered'"
    ).fetchone()[0] == 0


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
    assert conn.execute(
        "SELECT COUNT(*) FROM device_lifecycle_events WHERE stage = 'delivered'"
    ).fetchone()[0] == 0


def _existing_passport_protocol_fixture(tmp_path):
    conn = connect(tmp_path / "existing-passport.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(
        name="local",
        network_cidr="10.8.0.0/24",
    )
    peer_applier = RecordingPeerApplier()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        max_devices_per_user=1,
        peer_applier=peer_applier,
    )
    original = service.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="Primary laptop",
        duration_days=30,
        admin_telegram_id=999,
        config_version="amneziawg_v2",
        device_context=OperatorDeviceContext(
            platform="windows",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
            protocol_version="awg2",
            runtime_instance_id="runtime-awg2",
            client_identity_evidence_status="verified",
            compatibility_evidence_id="evidence-awg2",
        ),
    )
    peer_applier.calls.clear()
    return (
        conn,
        repo,
        service,
        peer_applier,
        owner_user_id,
        server_id,
        str(original.passport_device_id),
    )


def _awg3_existing_passport_context():
    return OperatorDeviceContext(
        platform="windows",
        official_client_type="amnezia_vpn",
        client_version="5.0.0.5",
        protocol_version="awg3",
        runtime_instance_id="runtime-awg3",
        client_identity_evidence_status="verified",
        compatibility_evidence_id="evidence-awg3",
    )


class _RecordingAwg3SecretResolver:
    def __init__(self, *, secret="test-header-protection-key", error=None):
        self.secret = secret
        self.error = error
        self.calls = []

    def resolve(self, reference):
        self.calls.append(reference)
        if self.error is not None:
            raise self.error
        return self.secret


def _awg3_issuer_material(*, resolver=None, s1=12, s2=13, s3=14, s4=15):
    active_resolver = resolver or _RecordingAwg3SecretResolver()
    fingerprint = "sha256:" + __import__("hashlib").sha256(
        active_resolver.secret.encode("utf-8")
    ).hexdigest()
    return Awg3IssuerMaterial(
        provider_identity="phase15-material-provider-001",
        runtime_instance_id="runtime-awg3",
        endpoint_host="awg3.example.test",
        server_public_key="awg3-server-public",
        s1=s1,
        s2=s2,
        s3=s3,
        s4=s4,
        content_padding_addition="0-64",
        rekey_after_time="120",
        rekey_timeout="5",
        reject_after_time="180",
        keepalive_timeout="30",
        max_handshake_attempts="20",
        header_protection_key=HeaderProtectionSecretRef(
            reference="phase15-hpk-001",
            fingerprint=fingerprint,
        ),
        secret_resolver=active_resolver,
    )


def test_create_protocol_device_for_existing_passport_reuses_lineage_without_recounting_quota(
    tmp_path,
):
    (
        conn,
        repo,
        service,
        peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)

    result = service.create_protocol_device_for_existing_passport(
        owner_user_id=owner_user_id,
        passport_device_id=passport_device_id,
        server_id=server_id,
        device_name="AWG3 laptop",
        config_version="amneziawg_v3",
        client_build="50005",
        device_context=_awg3_existing_passport_context(),
        awg3_material=_awg3_issuer_material(),
        runtime_target=_accepted_awg3_runtime(server_id),
        runtime_peer_applier=peer_applier,
    )

    assert result.passport_device_id == passport_device_id
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 1
    assert repo.count_active_devices(owner_user_id) == 2
    assert repo.get_device_passport(passport_device_id)["local_device_id"] != result.device_id
    device = repo.get_device(result.device_id)
    assert device["protocol_version"] == "awg3"
    assert device["runtime_instance_id"] == "runtime-awg3"
    assert device["compatibility_evidence_id"] == "evidence-awg3"
    assert device["config_version"] == "amneziawg_v3"
    assert len(peer_applier.calls) == 1


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("wrong_owner", "passport owner mismatch"),
        ("missing_passport", "passport was not found"),
        ("missing_lineage", "passport local device lineage"),
        ("invalid_context", "passport client context mismatch"),
    ],
)
def test_create_protocol_device_for_existing_passport_validates_before_secrets_or_peer(
    tmp_path,
    monkeypatch,
    mutation,
    expected_error,
):
    (
        conn,
        repo,
        service,
        peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)
    requested_owner_id = owner_user_id
    requested_passport_id = passport_device_id
    context = _awg3_existing_passport_context()
    if mutation == "wrong_owner":
        requested_owner_id = repo.upsert_user(
            telegram_id=1002,
            username="bob",
            first_name="Bob",
            last_name=None,
        )
    elif mutation == "missing_passport":
        requested_passport_id = "dev_ffffffffffffffffffffffffffffffff"
    elif mutation == "missing_lineage":
        conn.execute(
            "UPDATE device_passports SET local_device_id = NULL WHERE device_id = ?",
            (passport_device_id,),
        )
        conn.commit()
    elif mutation == "invalid_context":
        context = OperatorDeviceContext(
            platform="android",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
            protocol_version="awg3",
            runtime_instance_id="runtime-awg3",
            client_identity_evidence_status="verified",
            compatibility_evidence_id="evidence-awg3",
        )

    secret_calls = []

    def unexpected_secret_generation():
        secret_calls.append("secret")
        raise AssertionError("secret generation must follow validation")

    monkeypatch.setattr("app.services.access.generate_keypair", unexpected_secret_generation)
    monkeypatch.setattr("app.services.access.generate_key", unexpected_secret_generation)

    with pytest.raises(ValueError, match=expected_error):
        service.create_protocol_device_for_existing_passport(
            owner_user_id=requested_owner_id,
            passport_device_id=requested_passport_id,
            server_id=server_id,
            device_name="AWG3 laptop",
            config_version="amneziawg_v3",
            client_build="50005",
            device_context=context,
            awg3_material=_awg3_issuer_material(),
            runtime_target=_accepted_awg3_runtime(server_id),
            runtime_peer_applier=peer_applier,
        )

    assert secret_calls == []
    assert peer_applier.calls == []
    assert repo.count_active_devices(owner_user_id) == 1
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 1


@pytest.mark.parametrize("field", ["s1", "s2", "s3", "s4"])
def test_awg3_issuer_material_rejects_each_nonce_below_12(field):
    values = {"s1": 12, "s2": 12, "s3": 12, "s4": 12}
    values[field] = 11

    with pytest.raises(ValueError, match="S1-S4"):
        _awg3_issuer_material(**values)


@pytest.mark.parametrize(
    "failure_kind",
    ["resolver", "invalid_text", "fingerprint"],
)
def test_hpk_resolution_failures_use_narrow_safe_pre_side_effect_type(
    tmp_path,
    monkeypatch,
    failure_kind,
):
    (
        conn,
        repo,
        service,
        peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)
    resolver = _RecordingAwg3SecretResolver()
    if failure_kind == "resolver":
        resolver.error = RuntimeError("raw provider detail must not escape")
    elif failure_kind == "invalid_text":
        resolver.secret = " invalid-header-protection-key"
    material = _awg3_issuer_material(resolver=resolver)
    if failure_kind == "fingerprint":
        material = replace(
            material,
            header_protection_key=HeaderProtectionSecretRef(
                reference="phase15-hpk-001",
                fingerprint="sha256:" + "f" * 64,
            ),
        )
    key_calls = []

    def unexpected_key_generation():
        key_calls.append("key")
        raise AssertionError("key generation must follow HPK resolution")

    monkeypatch.setattr("app.services.access.generate_keypair", unexpected_key_generation)
    monkeypatch.setattr("app.services.access.generate_key", unexpected_key_generation)

    with pytest.raises(Exception) as raised:
        service.create_protocol_device_for_existing_passport(
            owner_user_id=owner_user_id,
            passport_device_id=passport_device_id,
            server_id=server_id,
            device_name="AWG3 laptop",
            config_version="amneziawg_v3",
            client_build="50005",
            device_context=_awg3_existing_passport_context(),
            awg3_material=material,
            runtime_target=_accepted_awg3_runtime(server_id),
            runtime_peer_applier=peer_applier,
        )

    narrow_type = getattr(
        access_module,
        "Awg3HeaderProtectionKeyUnavailable",
        None,
    )
    assert narrow_type is not None
    assert type(raised.value) is narrow_type
    assert str(raised.value) == "AWG3 header protection key is unavailable"
    assert "raw provider detail" not in str(raised.value)
    assert resolver.calls == ["phase15-hpk-001"]
    assert key_calls == []
    assert peer_applier.calls == []
    assert repo.count_active_devices(owner_user_id) == 1
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 1


def test_failure_after_hpk_resolution_remains_outside_narrow_type(
    tmp_path,
    monkeypatch,
):
    (
        _conn,
        _repo,
        service,
        peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)
    resolver = _RecordingAwg3SecretResolver()

    def fail_after_resolution():
        raise ValueError("post-resolution failure")

    monkeypatch.setattr("app.services.access.generate_keypair", fail_after_resolution)

    with pytest.raises(ValueError, match="post-resolution failure") as raised:
        service.create_protocol_device_for_existing_passport(
            owner_user_id=owner_user_id,
            passport_device_id=passport_device_id,
            server_id=server_id,
            device_name="AWG3 laptop",
            config_version="amneziawg_v3",
            client_build="50005",
            device_context=_awg3_existing_passport_context(),
            awg3_material=_awg3_issuer_material(resolver=resolver),
            runtime_target=_accepted_awg3_runtime(server_id),
            runtime_peer_applier=peer_applier,
        )

    narrow_type = getattr(
        access_module,
        "Awg3HeaderProtectionKeyUnavailable",
        None,
    )
    assert narrow_type is not None
    assert not isinstance(raised.value, narrow_type)
    assert resolver.calls == ["phase15-hpk-001"]
    assert peer_applier.calls == []


def _accepted_awg3_runtime(server_id):
    return RuntimeInstanceSpec(
        runtime_instance_id="runtime-awg3",
        server_id=server_id,
        protocol_version=ProtocolVersion.AWG3,
        runtime_version="awg3-runtime-1",
        interface_name="awg3",
        udp_port=30003,
        vpn_cidr="10.9.0.0/24",
        container_name=None,
        service_name="awg3.service",
        config_path="/etc/amnezia/awg3.conf",
        lifecycle_state="accepted",
        acceptance_receipt="sha256:" + "b" * 64,
    )


def _operator_awg2_context(**changes):
    return replace(
        OperatorDeviceContext(
            platform="windows",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
        ),
        **changes,
    )


@pytest.mark.parametrize(
    ("context", "expected_context"),
    (
        pytest.param(
            _operator_awg2_context(),
            (None, None, None, None),
            id="all-evidence-absent",
        ),
        pytest.param(
            _operator_awg2_context(protocol_version="awg2"),
            ("awg2", None, None, None),
            id="exact-awg2-with-evidence-absent",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime-awg3-looking-id",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="opaque-evidence-awg3-looking-id",
            ),
            (
                "awg2",
                "opaque-runtime-awg3-looking-id",
                "verified",
                "opaque-evidence-awg3-looking-id",
            ),
            id="exact-awg2-full-opaque-tuple",
        ),
    ),
)
def test_operator_awg2_accepts_only_complete_context_shapes_and_keeps_high_watermark(
    tmp_path,
    context,
    expected_context,
):
    conn = connect(tmp_path / "operator-awg2-valid-context.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Operator")
    server_id = repo.ensure_default_server(
        name="local",
        network_cidr="10.8.0.0/24",
    )
    peer_applier = RecordingPeerApplier(
        remote_allocated_ips=["10.8.0.200/32"]
    )
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
        device_name="AWG2 context matrix",
        duration_days=30,
        admin_telegram_id=999,
        config_version="amneziawg_v2",
        device_context=context,
        client_build="50005",
    )

    device = repo.get_device(result.device_id)
    assert device["vpn_ip"] == "10.8.0.201"
    assert (
        device["protocol_version"],
        device["runtime_instance_id"],
        device["client_identity_evidence_status"],
        device["compatibility_evidence_id"],
    ) == expected_context
    assert peer_applier.list_calls == [server_id]
    assert len(peer_applier.calls) == 1
    assert peer_applier.calls[0]["vpn_ip"] == "10.8.0.201"


@pytest.mark.parametrize(
    "context",
    (
        pytest.param(
            _operator_awg2_context(runtime_instance_id="opaque-runtime"),
            id="runtime-without-protocol",
        ),
        pytest.param(
            _operator_awg2_context(client_identity_evidence_status="verified"),
            id="status-without-protocol",
        ),
        pytest.param(
            _operator_awg2_context(compatibility_evidence_id="opaque-evidence"),
            id="evidence-without-protocol",
        ),
        pytest.param(
            _operator_awg2_context(
                runtime_instance_id="opaque-runtime",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="full-tuple-without-protocol",
        ),
        pytest.param(_operator_awg2_context(protocol_version="awg3"), id="awg3"),
        pytest.param(_operator_awg2_context(protocol_version="AWG3"), id="awg3-alias"),
        pytest.param(_operator_awg2_context(protocol_version="AWG2"), id="awg2-alias"),
        pytest.param(_operator_awg2_context(protocol_version=""), id="blank-protocol"),
        pytest.param(_operator_awg2_context(protocol_version=" "), id="space-protocol"),
        pytest.param(
            _operator_awg2_context(protocol_version=" awg2"),
            id="leading-space-protocol",
        ),
        pytest.param(
            _operator_awg2_context(protocol_version="awg2 "),
            id="trailing-space-protocol",
        ),
        pytest.param(
            _operator_awg2_context(protocol_version="unknown"),
            id="unknown-protocol",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime",
            ),
            id="partial-runtime-only",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                client_identity_evidence_status="verified",
            ),
            id="partial-status-only",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="partial-evidence-only",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime",
                client_identity_evidence_status="verified",
            ),
            id="partial-runtime-status",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="partial-runtime-evidence",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="partial-status-evidence",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="blank-runtime-id",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="",
            ),
            id="blank-evidence-id",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id=" opaque-runtime",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="whitespace-runtime-id",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="opaque-evidence ",
            ),
            id="whitespace-evidence-id",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime",
                client_identity_evidence_status="Verified",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="status-alias",
        ),
        pytest.param(
            _operator_awg2_context(
                protocol_version="awg2",
                runtime_instance_id="opaque-runtime",
                client_identity_evidence_status="verified ",
                compatibility_evidence_id="opaque-evidence",
            ),
            id="whitespace-status",
        ),
    ),
)
def test_operator_awg2_rejects_incomplete_or_noncanonical_context_before_side_effects(
    tmp_path,
    monkeypatch,
    context,
):
    conn = connect(tmp_path / "operator-awg2-invalid-context.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Operator")
    server_id = repo.ensure_default_server(
        name="local",
        network_cidr="10.8.0.0/24",
    )
    peer_applier = RecordingPeerApplier(
        remote_allocated_ips=["10.8.0.200/32"]
    )
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=peer_applier,
    )
    artifact_calls = []
    before = _access_side_effect_counts(conn)
    boundary_calls = _install_access_boundary_probes(monkeypatch, repo)

    with pytest.raises(ValueError):
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Invalid AWG2 context",
            duration_days=30,
            admin_telegram_id=999,
            config_version="amneziawg_v2",
            device_context=context,
            client_build="50005",
            config_artifact_writer=lambda text: artifact_calls.append(text),
        )

    assert boundary_calls == {
        "transaction": 0,
        "owner": 0,
        "keypair": 0,
        "preshared_key": 0,
    }
    assert _access_side_effect_counts(conn) == before
    assert peer_applier.calls == []
    assert peer_applier.list_calls == []
    assert artifact_calls == []


@pytest.mark.parametrize(
    "injection",
    (
        "runtime_target",
        "awg3_material",
        "runtime_peer_applier",
        "awg3_context",
        "combined",
    ),
)
def test_operator_awg2_rejects_awg3_only_inputs_before_any_side_effect(
    tmp_path,
    monkeypatch,
    injection,
):
    conn = connect(tmp_path / "operator-awg2-boundary.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.create_operator_recipient(operator_label="Operator")
    server_id = repo.ensure_default_server(
        name="local",
        network_cidr="10.8.0.0/24",
    )
    awg2_peer_applier = RecordingPeerApplier(
        remote_allocated_ips=["10.8.0.200/32"]
    )
    runtime_peer_applier = RecordingPeerApplier(
        remote_allocated_ips=["10.9.0.200/32"]
    )
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        peer_applier=awg2_peer_applier,
    )
    material = _awg3_issuer_material()
    kwargs = {
        "device_context": OperatorDeviceContext(
            platform="windows",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
        ),
        "client_build": "50005",
    }
    if injection in {"runtime_target", "combined"}:
        kwargs["runtime_target"] = _accepted_awg3_runtime(server_id)
    if injection in {"awg3_material", "combined"}:
        kwargs["awg3_material"] = material
    if injection in {"runtime_peer_applier", "combined"}:
        kwargs["runtime_peer_applier"] = runtime_peer_applier
    if injection in {"awg3_context", "combined"}:
        kwargs["device_context"] = _awg3_existing_passport_context()
    before = _access_side_effect_counts(conn)
    boundary_calls = _install_access_boundary_probes(monkeypatch, repo)

    with pytest.raises(
        ValueError,
        match="AWG3-only inputs require amneziawg_v3",
    ):
        service.create_operator_device(
            owner_user_id=owner_user_id,
            server_id=server_id,
            device_name="Injected AWG3 input",
            duration_days=30,
            admin_telegram_id=999,
            config_version="amneziawg_v2",
            **kwargs,
        )

    assert boundary_calls == {
        "transaction": 0,
        "owner": 0,
        "keypair": 0,
        "preshared_key": 0,
    }
    assert _access_side_effect_counts(conn) == before
    assert awg2_peer_applier.calls == []
    assert awg2_peer_applier.list_calls == []
    assert runtime_peer_applier.calls == []
    assert runtime_peer_applier.list_calls == []
    assert material.secret_resolver.calls == []


def test_existing_passport_protocol_rejects_v2_before_any_side_effect(
    tmp_path,
    monkeypatch,
):
    (
        conn,
        repo,
        service,
        awg2_peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)
    awg2_peer_applier.list_calls.clear()
    runtime_peer_applier = RecordingPeerApplier(
        remote_allocated_ips=["10.9.0.200/32"]
    )
    material = _awg3_issuer_material()
    before = _access_side_effect_counts(conn)
    boundary_calls = _install_access_boundary_probes(monkeypatch, repo)

    with pytest.raises(
        ValueError,
        match="protocol device creation requires amneziawg_v3",
    ):
        service.create_protocol_device_for_existing_passport(
            owner_user_id=owner_user_id,
            passport_device_id=passport_device_id,
            server_id=server_id,
            device_name="AWG3 laptop",
            config_version="amneziawg_v2",
            client_build="50005",
            device_context=_awg3_existing_passport_context(),
            awg3_material=material,
            runtime_target=_accepted_awg3_runtime(server_id),
            runtime_peer_applier=runtime_peer_applier,
        )

    assert boundary_calls == {
        "transaction": 0,
        "owner": 0,
        "keypair": 0,
        "preshared_key": 0,
    }
    assert _access_side_effect_counts(conn) == before
    assert awg2_peer_applier.calls == []
    assert awg2_peer_applier.list_calls == []
    assert runtime_peer_applier.calls == []
    assert runtime_peer_applier.list_calls == []
    assert material.secret_resolver.calls == []


def test_existing_passport_awg3_uses_only_exact_runtime_config_ipam_and_peer(
    tmp_path,
):
    (
        _conn,
        repo,
        service,
        awg2_peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)
    repo.create_device(
        user_id=owner_user_id,
        server_id=server_id,
        name="Existing AWG3 device",
        duration_days=30,
        vpn_ip="10.9.0.3",
        peer_public_key="existing-awg3-peer",
        peer_private_key_encrypted="encrypted-private-key",
        preshared_key_encrypted="encrypted-preshared-key",
        config_version="amneziawg_v3",
        protocol_version="awg3",
        runtime_instance_id="runtime-awg3",
        compatibility_evidence_id="evidence-awg3",
        client_identity_evidence_status="verified",
    )
    runtime_peer_applier = RecordingPeerApplier(
        remote_allocated_ips=["10.9.0.200/32"]
    )

    result = service.create_protocol_device_for_existing_passport(
        owner_user_id=owner_user_id,
        passport_device_id=passport_device_id,
        server_id=server_id,
        device_name="AWG3 laptop",
        config_version="amneziawg_v3",
        client_build="50005",
        device_context=_awg3_existing_passport_context(),
        awg3_material=_awg3_issuer_material(),
        runtime_target=_accepted_awg3_runtime(server_id),
        runtime_peer_applier=runtime_peer_applier,
    )

    device = repo.get_device(result.device_id)
    assert device["server_id"] == server_id
    assert device["runtime_instance_id"] == "runtime-awg3"
    assert device["vpn_ip"] == "10.9.0.2"
    assert "Address = 10.9.0.2/32" in result.config_text
    assert "Endpoint = awg3.example.test:30003" in result.config_text
    assert "PublicKey = awg3-server-public" in result.config_text
    assert "10.8.0." not in result.config_text
    assert awg2_peer_applier.calls == []
    assert len(runtime_peer_applier.calls) == 1
    assert runtime_peer_applier.calls[0]["vpn_ip"] == "10.9.0.2"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("content_padding_addition", "65-66"),
        ("content_padding_addition", "64-0"),
        ("content_padding_addition", "0-65"),
        ("content_padding_addition", "not-a-range"),
        ("rekey_after_time", "0"),
        ("rekey_timeout", "not-an-integer"),
        ("reject_after_time", "119"),
        ("keepalive_timeout", "-1"),
        ("max_handshake_attempts", "65536"),
    ],
)
def test_awg3_issuer_material_rejects_invalid_semantic_ranges(field, value):
    material = _awg3_issuer_material()

    with pytest.raises(ValueError, match=field):
        replace(material, **{field: value})


def test_awg3_semantic_validation_precedes_client_key_and_psk_generation(
    tmp_path,
    monkeypatch,
):
    (
        _conn,
        _repo,
        service,
        _awg2_peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)
    material = _awg3_issuer_material()
    object.__setattr__(material, "max_handshake_attempts", "65536")
    key_calls = []

    def unexpected_key_generation():
        key_calls.append("key")
        raise AssertionError("semantic validation must precede key generation")

    monkeypatch.setattr("app.services.access.generate_keypair", unexpected_key_generation)
    monkeypatch.setattr("app.services.access.generate_key", unexpected_key_generation)

    with pytest.raises(ValueError, match="max_handshake_attempts"):
        service.create_protocol_device_for_existing_passport(
            owner_user_id=owner_user_id,
            passport_device_id=passport_device_id,
            server_id=server_id,
            device_name="AWG3 laptop",
            config_version="amneziawg_v3",
            client_build="50005",
            device_context=_awg3_existing_passport_context(),
            awg3_material=material,
            runtime_target=_accepted_awg3_runtime(server_id),
            runtime_peer_applier=_awg2_peer_applier,
        )

    assert key_calls == []


def test_physical_quota_counts_dual_profile_passport_once_for_future_devices(tmp_path):
    (
        _conn,
        repo,
        service,
        peer_applier,
        owner_user_id,
        server_id,
        passport_device_id,
    ) = _existing_passport_protocol_fixture(tmp_path)
    awg3 = service.create_protocol_device_for_existing_passport(
        owner_user_id=owner_user_id,
        passport_device_id=passport_device_id,
        server_id=server_id,
        device_name="AWG3 laptop",
        config_version="amneziawg_v3",
        client_build="50005",
        device_context=_awg3_existing_passport_context(),
        awg3_material=_awg3_issuer_material(),
        runtime_target=_accepted_awg3_runtime(server_id),
        runtime_peer_applier=peer_applier,
    )
    repo.create_device_protocol_profile(
        passport_device_id=passport_device_id,
        protocol_version="awg3",
        local_device_id=awg3.device_id,
        lifecycle_state="active",
    )
    service_with_two_physical_slots = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "test-secret-for-access-service-1234567890"
        ),
        max_devices_per_user=2,
        peer_applier=peer_applier,
    )

    second_physical = service_with_two_physical_slots.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=server_id,
        device_name="Phone",
        duration_days=30,
        admin_telegram_id=999,
        config_version="amneziawg_v2",
        device_context=OperatorDeviceContext(
            platform="android",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
            protocol_version="awg2",
            runtime_instance_id="runtime-awg2",
            client_identity_evidence_status="verified",
            compatibility_evidence_id="evidence-awg2-phone",
        ),
    )

    assert second_physical.device_id != awg3.device_id
    assert repo.count_active_physical_devices(owner_user_id) == 2
