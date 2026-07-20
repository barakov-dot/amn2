import pytest

from app.access_expiry import AccessExpiry, INDEFINITE
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.access import AccessService, OperatorDeviceContext
from app.services.access_slot_assignment import assign_access_slot


class PeerApplier:
    def list_allocated_ips(self, *, server):
        return []

    def apply_peer(self, **kwargs):
        return None


def _slot(tmp_path):
    conn = connect(tmp_path / "assignment.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_id = repo.create_operator_recipient(operator_label="Иван")
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    created = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-assignment-123456789012345"),
        peer_applier=PeerApplier(),
    ).create_operator_device(
        owner_user_id=owner_id,
        server_id=server_id,
        device_name="01",
        duration_days=None,
        expiry=AccessExpiry(INDEFINITE, None, None),
        admin_telegram_id=7001,
        assignment_mode="recipient_unassigned",
    )
    return conn, repo, created


def test_assign_slot_creates_one_passport_without_rotating_access(tmp_path):
    conn, repo, created = _slot(tmp_path)
    before = dict(repo.get_device(created.device_id))
    context = OperatorDeviceContext(platform="android", client_version="4.8.21.0")

    first = assign_access_slot(
        repo,
        request_id="assign-001",
        local_device_id=created.device_id,
        device_label="Pixel 8",
        context=context,
        admin_telegram_id=7001,
    )
    replay = assign_access_slot(
        repo,
        request_id="assign-001",
        local_device_id=created.device_id,
        device_label="Pixel 8",
        context=context,
        admin_telegram_id=7001,
    )

    after = dict(repo.get_device(created.device_id))
    assert replay.device_id == first.device_id
    assert after["assignment_mode"] == "dedicated_device"
    assert after["peer_public_key"] == before["peer_public_key"]
    assert after["vpn_ip"] == before["vpn_ip"]
    assert after["config_fingerprint"] == before["config_fingerprint"]
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 1


def test_assign_slot_conflict_and_second_assignment_fail_without_mutation(tmp_path):
    conn, repo, created = _slot(tmp_path)
    context = OperatorDeviceContext(platform="android")
    assign_access_slot(
        repo,
        request_id="assign-001",
        local_device_id=created.device_id,
        device_label="Pixel 8",
        context=context,
        admin_telegram_id=7001,
    )

    with pytest.raises(ValueError, match="request does not match"):
        assign_access_slot(
            repo,
            request_id="assign-001",
            local_device_id=created.device_id,
            device_label="Other",
            context=context,
            admin_telegram_id=7001,
        )
    with pytest.raises(ValueError, match="already assigned"):
        assign_access_slot(
            repo,
            request_id="assign-002",
            local_device_id=created.device_id,
            device_label="Pixel 8",
            context=context,
            admin_telegram_id=7001,
        )
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 1
