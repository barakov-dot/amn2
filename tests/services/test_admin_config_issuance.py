import json

import pytest

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.access import AccessService
from app.services.admin_config_issuance import (
    AdminConfigIssuanceService,
    validate_admin_config_issuance_manifest,
)


APP_SECRET = "test-secret-for-admin-issuance-1234567890"


class FakePeerApplier:
    def __init__(self):
        self.applied = []

    def list_allocated_ips(self, *, server):
        return []

    def apply_peer(self, *, server, peer_public_key, preshared_key, vpn_ip):
        self.applied.append((int(server["id"]), peer_public_key, vpn_ip))


class FailOnSecondAccessService:
    def __init__(self, delegate):
        self.delegate = delegate
        self.calls = 0

    def create_operator_device(self, **kwargs):
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("raw ssh endpoint 203.0.113.41 failed with secret material")
        return self.delegate.create_operator_device(**kwargs)


def _repo(tmp_path):
    conn = connect(tmp_path / "issuance.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    repo.create_server_for_admin(
        name="Spain-Madrid",
        host="203.0.113.41",
        ssh_port=22,
        endpoint_host="vpn.private.example",
        vpn_port=51820,
        vpn_network_cidr="10.77.0.0/24",
        server_address="10.77.0.1/24",
        server_public_key="server-public-key",
        runtime="docker",
        firewall="iptables",
        status="active",
        max_devices=100,
    )
    return conn, repo


def _access(repo, peer_applier):
    return AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(APP_SECRET),
        peer_applier=peer_applier,
    )


def _manifest(*items):
    return {
        "request_id": "spain-first-real-001",
        "server": "Spain-Madrid",
        "items": list(items),
    }


def _item(recipient, device, platform="android"):
    return {
        "recipient_label": recipient,
        "device_label": device,
        "platform": platform,
    }


def _unassigned_item(recipient, quantity):
    return {
        "mode": "recipient_unassigned",
        "recipient_label": recipient,
        "quantity": quantity,
    }


def test_unassigned_quantity_expands_deterministically_and_defaults_indefinite():
    validated = validate_admin_config_issuance_manifest(
        _manifest(_unassigned_item("Иван", 4))
    )

    assert len(validated.expanded_slots) == 4
    assert [slot.slot_sequence for slot in validated.expanded_slots] == [1, 2, 3, 4]
    assert [slot.device_label for slot in validated.expanded_slots] == ["01", "02", "03", "04"]
    assert all(slot.assignment_mode == "recipient_unassigned" for slot in validated.expanded_slots)
    assert all(slot.expiry.policy == "indefinite" for slot in validated.expanded_slots)


@pytest.mark.parametrize("quantity", [0, 101, True])
def test_unassigned_quantity_rejects_out_of_range_values(quantity):
    with pytest.raises(ValueError, match="quantity"):
        validate_admin_config_issuance_manifest(
            _manifest(_unassigned_item("Иван", quantity))
        )


def test_unassigned_quantity_four_issues_four_safe_idempotent_slots(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    attachments = []
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: attachments.append((filename, content)),
        max_devices_per_recipient=4,
    )
    manifest = _manifest(_unassigned_item("Иван", 4))

    first = service.issue_manifest(manifest)
    replay = service.issue_manifest(manifest)

    assert first == replay
    assert len(first.receipts) == 4
    assert [r.slot_sequence for r in first.receipts] == [1, 2, 3, 4]
    assert [r.config_filename for r in first.receipts] == [
        "NEOBYATNAYA.NET-Ivan-01.conf",
        "NEOBYATNAYA.NET-Ivan-02.conf",
        "NEOBYATNAYA.NET-Ivan-03.conf",
        "NEOBYATNAYA.NET-Ivan-04.conf",
    ]
    assert all(r.assignment_mode == "recipient_unassigned" for r in first.receipts)
    assert all(r.passport_device_id is None for r in first.receipts)
    assert all(r.expiry_policy == "indefinite" for r in first.receipts)
    assert len(peer_applier.applied) == 4
    assert len(attachments) == 4
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 4
    assert conn.execute("SELECT COUNT(*) FROM device_passports").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM devices WHERE duration_days IS NULL AND expires_at IS NULL"
    ).fetchone()[0] == 4


def test_full_batch_quota_rejects_before_recipient_or_peer_mutation(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
        max_devices_per_recipient=4,
    )

    with pytest.raises(ValueError, match="full-batch quota"):
        service.issue_manifest(_manifest(_unassigned_item("Иван", 5)))

    assert repo.get_user_by_operator_label("Иван") is None
    assert peer_applier.applied == []
    assert conn.execute("SELECT COUNT(*) FROM admin_config_issuance_requests").fetchone()[0] == 0


def test_new_request_filename_collision_is_rejected_before_second_peer(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
        max_devices_per_recipient=4,
    )
    service.issue_manifest(_manifest(_unassigned_item("Иван", 1)))
    second = _manifest(_unassigned_item("Иван", 1))
    second["request_id"] = "spain-second-002"

    with pytest.raises(ValueError, match="filename collision"):
        service.issue_manifest(second)

    assert len(peer_applier.applied) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_config_issuance_requests"
    ).fetchone()[0] == 1


def test_manifest_rejects_normalized_duplicate_recipient_device_before_mutation(
    tmp_path,
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    )

    with pytest.raises(ValueError, match="duplicate recipient/device"):
        service.issue_manifest(
            _manifest(
                _item("Alice", "Phone"),
                _item(" alice ", " phone "),
            )
        )

    assert peer_applier.applied == []
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_config_issuance_requests"
    ).fetchone()[0] == 0


def test_same_request_item_returns_completed_receipt_without_second_peer(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    attachments = []
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: attachments.append(
            (filename, content)
        ),
    )
    manifest = _manifest(_item("Alice", "Pixel 8"))

    first = service.issue_manifest(manifest)
    replay = service.issue_manifest(manifest)

    assert first.receipts == replay.receipts
    assert first.receipts[0].status == "completed"
    assert first.receipts[0].config_filename.endswith(".conf")
    assert first.receipts[0].passport_device_id
    assert len(peer_applier.applied) == 1
    assert len(attachments) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_config_issuance_receipts"
    ).fetchone()[0] == 1

    safe_receipt = json.dumps(first.receipts[0].to_safe_dict(), sort_keys=True)
    stored = dict(
        conn.execute("SELECT * FROM admin_config_issuance_receipts").fetchone()
    )
    forbidden = (
        "PrivateKey",
        "PresharedKey",
        "203.0.113.41",
        "vpn.private.example",
        "telegram",
        APP_SECRET,
    )
    assert all(value not in safe_receipt for value in forbidden)
    assert all(value not in json.dumps(stored, sort_keys=True) for value in forbidden)
    issuance_audit = conn.execute(
        "SELECT metadata_json FROM admin_actions WHERE action = ?",
        ("admin_config.issue_manifest",),
    ).fetchone()[0]
    assert all(value not in issuance_audit for value in forbidden)
    conn.close()


def test_changed_item_replay_is_rejected_without_second_peer(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    service.issue_manifest(_manifest(_item("Alice", "Pixel 8")))

    with pytest.raises(ValueError, match="does not match existing request"):
        service.issue_manifest(_manifest(_item("Alice", "Different Device")))

    assert len(peer_applier.applied) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    conn.close()


def test_reordered_item_replay_is_rejected_without_new_peers(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    service.issue_manifest(
        _manifest(_item("Alice", "Pixel 8"), _item("Bob", "iPhone"))
    )

    with pytest.raises(ValueError, match="does not match existing request"):
        service.issue_manifest(
            _manifest(_item("Bob", "iPhone"), _item("Alice", "Pixel 8"))
        )

    assert len(peer_applier.applied) == 2
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
    conn.close()


def test_changed_server_replay_is_rejected_without_new_peer(tmp_path):
    conn, repo = _repo(tmp_path)
    repo.create_server_for_admin(
        name="Other-Server",
        host="198.51.100.12",
        ssh_port=22,
        endpoint_host="other.private.example",
        vpn_port=51820,
        vpn_network_cidr="10.88.0.0/24",
        server_address="10.88.0.1/24",
        server_public_key="other-server-public-key",
        runtime="docker",
        firewall="iptables",
        status="active",
        max_devices=100,
    )
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    service.issue_manifest(_manifest(_item("Alice", "Pixel 8")))
    changed_server = _manifest(_item("Alice", "Pixel 8"))
    changed_server["server"] = "Other-Server"

    with pytest.raises(ValueError, match="does not match existing request"):
        service.issue_manifest(changed_server)

    assert len(peer_applier.applied) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    conn.close()


def test_appended_item_replay_is_rejected_before_new_recipient_or_peer(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    service.issue_manifest(_manifest(_item("Alice", "Pixel 8")))

    with pytest.raises(ValueError, match="does not match existing request"):
        service.issue_manifest(
            _manifest(_item("Alice", "Pixel 8"), _item("Bob", "iPhone"))
        )

    assert repo.get_user_by_operator_label("Bob") is None
    assert len(peer_applier.applied) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    conn.close()


def test_truncated_item_replay_is_rejected_before_receipt_processing(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    service.issue_manifest(
        _manifest(_item("Alice", "Pixel 8"), _item("Bob", "iPhone"))
    )

    with pytest.raises(ValueError, match="does not match existing request"):
        service.issue_manifest(_manifest(_item("Alice", "Pixel 8")))

    assert len(peer_applier.applied) == 2
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
    conn.close()


def test_receipt_completion_failure_rolls_back_completed_audit_and_is_replay_safe(
    tmp_path, monkeypatch
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    real_complete = repo.complete_admin_config_issuance_receipt

    def fail_completion(**kwargs):
        raise RuntimeError("receipt completion backend failed")

    monkeypatch.setattr(
        repo,
        "complete_admin_config_issuance_receipt",
        fail_completion,
    )
    manifest = _manifest(_item("Alice", "Pixel 8"))

    first = service.issue_manifest(manifest)
    monkeypatch.setattr(
        repo,
        "complete_admin_config_issuance_receipt",
        real_complete,
    )
    replay = service.issue_manifest(manifest)

    assert first.receipts[0].status == "partial_failure"
    assert replay.receipts == first.receipts
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_actions WHERE action = ?",
        ("admin_config.issue_manifest",),
    ).fetchone()[0] == 0
    assert len(peer_applier.applied) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    conn.close()


def test_manifest_is_fully_validated_before_any_mutation(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    manifest = _manifest(
        _item("Alice", "Pixel 8"),
        {
            **_item("Bob", "iPhone"),
            "telegram_target": "must-not-be-accepted",
        },
    )

    with pytest.raises(ValueError, match="unsupported fields"):
        service.issue_manifest(manifest)

    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_config_issuance_receipts"
    ).fetchone()[0] == 0
    assert peer_applier.applied == []
    conn.close()


def test_later_invalid_platform_is_rejected_before_first_peer_mutation(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )

    with pytest.raises(ValueError, match="unsupported device platform"):
        service.issue_manifest(
            _manifest(
                _item("Alice", "Pixel 8"),
                _item("Bob", "Unsupported Device", "not-a-platform"),
            )
        )

    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
    assert peer_applier.applied == []
    conn.close()


def test_failure_stops_before_next_item_and_persists_only_safe_error_code(tmp_path):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    access = FailOnSecondAccessService(_access(repo, peer_applier))
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=access,
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )

    result = service.issue_manifest(
        _manifest(
            _item("Alice", "Pixel 8"),
            _item("Bob", "iPhone"),
            _item("Carol", "Laptop", "windows"),
        )
    )

    assert [receipt.status for receipt in result.receipts] == [
        "completed",
        "partial_failure",
    ]
    assert access.calls == 2
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert repo.get_user_by_operator_label("Carol") is None
    failure = result.receipts[-1]
    assert failure.error_code == "runtime_error"
    assert "203.0.113.41" not in json.dumps(failure.to_safe_dict())
    assert "secret material" not in json.dumps(failure.to_safe_dict())

    replay = service.issue_manifest(
        _manifest(
            _item("Alice", "Pixel 8"),
            _item("Bob", "iPhone"),
            _item("Carol", "Laptop", "windows"),
        )
    )
    assert [receipt.status for receipt in replay.receipts] == [
        "completed",
        "partial_failure",
    ]
    assert access.calls == 2
    assert len(peer_applier.applied) == 1
    conn.close()


def test_issuance_audit_failure_is_partial_and_replay_never_duplicates_peer(
    tmp_path, monkeypatch
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=_access(repo, peer_applier),
        admin_telegram_id=7001,
        attachment_builder=lambda filename, content: None,
    )
    real_record_admin_action = repo.record_admin_action

    def fail_issuance_audit(**kwargs):
        if kwargs["action"] == "admin_config.issue_manifest":
            raise RuntimeError("audit backend included 203.0.113.41")
        return real_record_admin_action(**kwargs)

    monkeypatch.setattr(repo, "record_admin_action", fail_issuance_audit)
    manifest = _manifest(_item("Alice", "Pixel 8"))

    first = service.issue_manifest(manifest)
    replay = service.issue_manifest(manifest)

    assert first.receipts[0].status == "partial_failure"
    assert first.receipts[0].error_code == "runtime_error"
    assert replay.receipts == first.receipts
    assert len(peer_applier.applied) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    conn.close()
