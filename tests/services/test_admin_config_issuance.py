import json
import threading
from types import SimpleNamespace

import pytest

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.access import AccessService
from app.services.admin_config_issuance import (
    AdminConfigIssuanceService as _AdminConfigIssuanceService,
    _request_fingerprint,
    validate_admin_config_issuance_manifest,
)
from app.services.device_passports import create_device_passport
from app.services.protocol_admission import AdmissionResult
from app.services.protocol_issuance_barrier import ProtocolIssuanceBarrierService
from app.vpn.protocol_versions import ProtocolVersion


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


class StaticAdmissionService:
    def __init__(self, result: AdmissionResult) -> None:
        self._result = result
        self.calls = []

    def decide(self, request):
        self.calls.append(request)
        return self._result


class SequencedAdmissionService:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def decide(self, request):
        self.calls.append(request)
        if not self.results:
            raise AssertionError("unexpected admission call")
        return self.results.pop(0)


class SpyAccessService:
    def __init__(self) -> None:
        self.calls = []

    def create_operator_device(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            device_id=1,
            passport_device_id="dev_phase13",
            config_filename="phase13.conf",
            config_text="safe-test-config",
        )


class SyntheticAwg3AccessService:
    def __init__(self, repo, peer_applier):
        self.repo = repo
        self.peer_applier = peer_applier
        self.calls = []

    def create_operator_device(self, **kwargs):
        self.calls.append(kwargs)
        passport_device_id = kwargs["passport_device_id"]
        device_id = self.repo.create_device(
            user_id=kwargs["owner_user_id"],
            server_id=kwargs["server_id"],
            name="synthetic-awg3-admin-device",
            duration_days=30,
            vpn_ip="10.77.0.19",
            peer_public_key="synthetic-awg3-public",
            peer_private_key_encrypted="synthetic-awg3-encrypted-private",
            preshared_key_encrypted="synthetic-awg3-encrypted-psk",
            config_version="amneziawg_v3",
            protocol_version="awg3",
            runtime_instance_id="rt-spain-awg3",
            compatibility_evidence_id="compat-exact",
            client_identity_evidence_status="verified",
        )
        passport = create_device_passport(
            self.repo,
            device_id=passport_device_id,
            owner_user_id=kwargs["owner_user_id"],
            local_device_id=device_id,
            platform="windows",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
            import_method="conf_file",
            config_schema_version="amneziawg_v3",
            config_text="synthetic-admin-config-fingerprint-source",
            protocol_version="awg3",
            runtime_instance_id="rt-spain-awg3",
            client_identity_evidence_status="verified",
            compatibility_evidence_id="compat-exact",
        )
        self.peer_applier.applied.append(
            (kwargs["server_id"], "synthetic-awg3-public", "10.77.0.19")
        )
        return SimpleNamespace(
            device_id=device_id,
            passport_device_id=passport.device_id,
            config_filename="synthetic-awg3-admin.conf",
            config_text="synthetic-boundary-config",
        )


class FailNextCommitConnection:
    def __init__(self, delegate):
        self._delegate = delegate
        self._fail_next_commit = True

    def commit(self):
        marker_exists = self._delegate.execute(
            "SELECT EXISTS(SELECT 1 FROM protocol_issuance_attempts "
            "WHERE state = 'recovery_required' AND reason_code = 'issuer_in_progress')"
        ).fetchone()[0]
        if self._fail_next_commit and marker_exists:
            self._fail_next_commit = False
            raise RuntimeError("synthetic phase-a commit failed")
        return self._delegate.commit()

    def __getattr__(self, name):
        return getattr(self._delegate, name)


def _admission(decision: str = "admitted_awg2") -> StaticAdmissionService:
    protocol = ProtocolVersion.AWG3 if decision.endswith("awg3") else ProtocolVersion.AWG2
    return StaticAdmissionService(
        AdmissionResult(
            decision=decision,
            protocol_version=protocol,
            runtime_instance_id="rt-spain-" + protocol.value if decision.startswith("admitted") else None,
            compatibility_evidence_id="compat-exact" if decision.startswith("admitted") else None,
        )
    )


def AdminConfigIssuanceService(**kwargs):
    kwargs.setdefault("admission_service", _admission())
    return _AdminConfigIssuanceService(**kwargs)


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
        "client_application": "amnezia_vpn",
        "client_platform": platform,
        "client_version": "5.0.0.5",
        "protocol_version": "awg2",
    }


def _phase13_item(
    recipient="SooL",
    device="NOTEBOOK",
    version="5.0.0.5",
    build="exact-build",
):
    return {
        "recipient_label": recipient,
        "device_label": device,
        "client_application": "amnezia_vpn",
        "client_platform": "windows",
        "client_version": version,
        "client_build": build,
        "protocol_version": "awg3",
    }


def _unassigned_item(recipient, quantity):
    return {
        "mode": "recipient_unassigned",
        "recipient_label": recipient,
        "quantity": quantity,
    }


def test_unassigned_quantity_fails_closed_to_separate_reservation_workflow():
    with pytest.raises(ValueError, match="separate reservation workflow"):
        validate_admin_config_issuance_manifest(_manifest(_unassigned_item("Иван", 4)))


@pytest.mark.parametrize("quantity", [0, 101, True])
def test_unassigned_quantity_rejects_out_of_range_values(quantity):
    with pytest.raises(ValueError, match="separate reservation workflow"):
        validate_admin_config_issuance_manifest(
            _manifest(_unassigned_item("Иван", quantity))
        )


def test_unassigned_quantity_does_not_issue_any_slot(tmp_path):
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
    with pytest.raises(ValueError, match="separate reservation workflow"):
        service.issue_manifest(_manifest(_unassigned_item("Иван", 4)))
    assert peer_applier.applied == []
    assert attachments == []
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0


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
        service.issue_manifest(
            _manifest(*(_item("Иван", f"Device {index}") for index in range(5)))
        )

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
    first = service.issue_manifest(_manifest(_item("Alice", "Phone")))
    assert first.status == "completed"
    assert repo.list_completed_admin_config_filenames_for_recipient(
        first.receipts[0].recipient_user_id
    ) == [first.receipts[0].config_filename]
    assert first.receipts[0].config_filename == "NEOBYATNAYA.NET-Alice-Phone-d1.conf"
    second = _manifest(_item("Alice", "Phone"))
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
    assert first.receipts[0].status == "completed", first.receipts[0].error_code
    assert first.receipts[0].config_filename.endswith(".conf")
    assert first.receipts[0].passport_device_id
    assert len(peer_applier.applied) == 1
    assert len(attachments) == 1
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_config_issuance_receipts"
    ).fetchone()[0] == 1
    device = repo.get_device(first.receipts[0].device_id)
    assert device["protocol_version"] == "awg2"
    assert device["runtime_instance_id"] == "rt-spain-awg2"
    assert device["compatibility_evidence_id"] == "compat-exact"
    assert device["client_identity_evidence_status"] == "verified"

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


def test_unknown_client_is_rejected_before_recipient_peer_key_or_config_creation(
    tmp_path,
):
    conn, repo = _repo(tmp_path)
    access = SpyAccessService()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=access,
        admission_service=_admission("blocked_unknown_client"),
        admin_telegram_id=1,
        attachment_builder=lambda filename, config: (filename, config),
    )

    with pytest.raises(ValueError, match="blocked_unknown_client"):
        service.issue_manifest(_manifest(_phase13_item()))

    assert access.calls == []
    assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
    assert conn.execute(
        "SELECT count(*) FROM admin_config_issuance_receipts"
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT count(*) FROM admin_config_issuance_requests"
    ).fetchone()[0] == 0


def test_fingerprint_binds_exact_client_version():
    first = validate_admin_config_issuance_manifest(_manifest(_phase13_item(version="5.0.0.5")))
    changed = validate_admin_config_issuance_manifest(_manifest(_phase13_item(version="5.0.0.6")))
    assert _request_fingerprint(first) != _request_fingerprint(changed)


def test_awg3_manifest_requires_exact_client_build():
    item = _phase13_item()
    item.pop("client_build")

    with pytest.raises(ValueError, match="client_build"):
        validate_admin_config_issuance_manifest(_manifest(item))


def test_awg3_manifest_and_admission_bind_exact_client_build(tmp_path):
    validated = validate_admin_config_issuance_manifest(_manifest(_phase13_item()))
    assert validated.items[0].client_build == "exact-build"
    assert validated.expanded_slots[0].client_build == "exact-build"
    changed = validate_admin_config_issuance_manifest(
        _manifest(_phase13_item(build="changed-build"))
    )
    assert _request_fingerprint(validated) != _request_fingerprint(changed)

    conn, repo = _repo(tmp_path)
    admission = _admission("blocked_unknown_client")
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=SpyAccessService(),
        admission_service=admission,
        admin_telegram_id=1,
        attachment_builder=lambda filename, config: (filename, config),
    )
    with pytest.raises(ValueError, match="blocked_unknown_client"):
        service.issue_manifest(_manifest(_phase13_item()))
    assert admission.calls[0].client.build_id == "exact-build"
    conn.close()


def test_awg3_safe_receipt_carries_client_build_without_config_material(tmp_path):
    conn, repo = _repo(tmp_path)

    class SyntheticAwg3AccessService:
        def create_operator_device(self, **kwargs):
            device_id = repo.create_device(
                user_id=kwargs["owner_user_id"],
                server_id=kwargs["server_id"],
                name="synthetic-awg3-admin-device",
                duration_days=30,
                vpn_ip="10.77.0.19",
                peer_public_key="synthetic-awg3-public",
                peer_private_key_encrypted="synthetic-awg3-encrypted-private",
                preshared_key_encrypted="synthetic-awg3-encrypted-psk",
                config_version="amneziawg_v3",
                protocol_version="awg3",
                runtime_instance_id="rt-spain-awg3",
                compatibility_evidence_id="compat-exact",
                client_identity_evidence_status="verified",
            )
            passport = create_device_passport(
                repo,
                device_id=kwargs["passport_device_id"],
                owner_user_id=kwargs["owner_user_id"],
                local_device_id=device_id,
                platform="windows",
                official_client_type="amnezia_vpn",
                client_version="5.0.0.5",
                import_method="conf_file",
                config_schema_version="amneziawg_v3",
                config_text="synthetic-admin-config-fingerprint-source",
                protocol_version="awg3",
                runtime_instance_id="rt-spain-awg3",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="compat-exact",
            )
            return SimpleNamespace(
                device_id=device_id,
                passport_device_id=passport.device_id,
                config_filename="synthetic-awg3-admin.conf",
                config_text="synthetic-boundary-config",
            )

    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=SyntheticAwg3AccessService(),
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=1,
        attachment_builder=lambda filename, config: (filename, config),
    )

    result = service.issue_manifest(_manifest(_phase13_item()))

    assert result.receipts[0].client_build == "exact-build"
    safe = result.receipts[0].to_safe_dict()
    assert safe["client_build"] == "exact-build"
    serialized = json.dumps(safe)
    assert "synthetic-boundary-config" not in serialized
    assert "private_key" not in serialized
    assert "preshared_key" not in serialized
    assert "qr" not in serialized.casefold()
    stored = conn.execute(
        "SELECT client_build FROM admin_config_issuance_receipts "
        "WHERE request_id = ? AND item_index = 0",
        ("spain-first-real-001",),
    ).fetchone()
    assert stored["client_build"] == "exact-build"
    replay = service.replay_existing_request("spain-first-real-001")
    assert replay.receipts[0].client_build == "exact-build"
    conn.close()


class LegacyReplayRepository:
    def __init__(self) -> None:
        self.request_id = "phase12-spain-sool-remaining-20260801-002"
        self._request = {
            "request_id": self.request_id,
            "request_fingerprint": "sha256:" + "c" * 64,
            "item_count": 1,
        }
        self._receipts = [
            {
                "id": 1,
                "request_id": self.request_id,
                "item_index": 0,
                "recipient_user_id": 1,
                "device_id": 7,
                "passport_device_id": "dev_phase12",
                "assignment_mode": "dedicated_device",
                "slot_sequence": 1,
                "expiry_policy": "indefinite",
                "status": "completed",
                "config_filename": "SooL-NOTEBOOK.conf",
                "error_code": None,
                "config_version": "amneziawg_v2",
                "protocol_version": None,
                "runtime_instance_id": None,
                "compatibility_evidence_id": None,
                "client_application": None,
                "client_platform": None,
                "client_version": None,
                "created_at": "2026-08-01T00:00:00Z",
                "updated_at": "2026-08-01T00:00:00Z",
            }
        ]

    def get_admin_config_issuance_request(self, *, request_id: str):
        return self._request if request_id == self.request_id else None

    def list_admin_config_issuance_receipts(self, request_id: str):
        return list(self._receipts) if request_id == self.request_id else []

    def __getattr__(self, name: str):
        if name.startswith(("create_", "update_", "delete_", "complete_", "fail_")):
            raise AssertionError(f"legacy replay attempted mutation: {name}")
        raise AttributeError(name)


def test_completed_legacy_receipt_replays_without_reissue_or_forced_backfill():
    repo = LegacyReplayRepository()
    access = SpyAccessService()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=access,
        admission_service=_admission("blocked_unverified_version"),
        admin_telegram_id=1,
        attachment_builder=lambda filename, config: (filename, config),
    )
    result = service.replay_existing_request(repo.request_id)
    assert result.status == "completed"
    assert access.calls == []
    assert result.receipts[0].protocol_version is None
    assert result.receipts[0].client_build is None


def test_admin_awg3_persists_one_completed_attempt_profile_event_and_receipt_graph(
    tmp_path,
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    access = SyntheticAwg3AccessService(repo, peer_applier)

    class TransactionCheckingAccess:
        def create_operator_device(self, **kwargs):
            assert repo._transaction_depth == 1
            return access.create_operator_device(**kwargs)

    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=TransactionCheckingAccess(),
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    )

    result = service.issue_manifest(_manifest(_phase13_item()))

    receipt = result.receipts[0]
    attempt = conn.execute("SELECT * FROM protocol_issuance_attempts").fetchone()
    profile = conn.execute("SELECT * FROM device_protocol_profiles").fetchone()
    event = conn.execute(
        "SELECT * FROM protocol_config_events WHERE event_type = 'admin_config_issued'"
    ).fetchone()
    assert result.status == "completed", receipt.error_code
    assert attempt["state"] == "completed"
    assert attempt["owner_user_id"] == receipt.recipient_user_id
    assert attempt["intended_passport_device_id"] == receipt.passport_device_id
    assert attempt["passport_device_id"] == receipt.passport_device_id
    assert attempt["local_device_id"] == receipt.device_id
    assert attempt["client_build"] == "exact-build"
    assert profile["passport_device_id"] == receipt.passport_device_id
    assert profile["local_device_id"] == receipt.device_id
    assert profile["lifecycle_state"] == "active"
    assert event["passport_device_id"] == receipt.passport_device_id
    assert event["local_device_id"] == receipt.device_id
    assert json.loads(event["metadata_json"]) == {
        "attempt_id": int(attempt["id"]),
        "client_application": "amnezia_vpn",
        "client_build": "exact-build",
        "client_platform": "windows",
        "client_version": "5.0.0.5",
        "profile_id": int(profile["id"]),
        "receipt_id": receipt.receipt_id,
    }
    assert len(peer_applier.applied) == 1


def test_admin_awg3_issuance_wins_real_sqlite_race_and_block_removes_exact_peer(
    tmp_path,
):
    database_path = tmp_path / "issuance.sqlite3"
    setup_conn, setup_repo = _repo(tmp_path)
    user_id = setup_repo.create_operator_recipient(operator_label="SooL")
    setup_conn.close()
    issuer_entered = threading.Event()
    allow_issuer = threading.Event()
    block_begin_seen = threading.Event()
    block_finished = threading.Event()
    peer_applier = FakePeerApplier()
    known_peer_ids = set()
    removed_peer_ids = set()
    results = {}
    errors = []

    def issue_in_thread():
        conn = connect(database_path)
        repo = Repository(conn)
        delegate = SyntheticAwg3AccessService(repo, peer_applier)

        class PausingAccessService:
            def create_operator_device(self, **kwargs):
                issuer_entered.set()
                if not allow_issuer.wait(timeout=3):
                    raise AssertionError("block did not reach the admin issuance lock")
                issued = delegate.create_operator_device(**kwargs)
                known_peer_ids.add(int(issued.device_id))
                return issued

        try:
            service = AdminConfigIssuanceService(
                repo=repo,
                access_service=PausingAccessService(),
                admission_service=_admission("admitted_awg3"),
                admin_telegram_id=7001,
                attachment_builder=lambda _filename, _content: None,
            )
            results["issuance"] = service.issue_manifest(
                _manifest(_phase13_item())
            )
            results["issuer_calls"] = len(delegate.calls)
        except Exception as exc:
            errors.append(exc)
        finally:
            conn.close()

    def block_in_thread():
        conn = connect(database_path)
        conn.set_trace_callback(
            lambda statement: block_begin_seen.set()
            if statement.strip().upper() == "BEGIN IMMEDIATE"
            else None
        )
        repo = Repository(conn)
        try:
            barrier = ProtocolIssuanceBarrierService(repo)
            plan = barrier.begin_block(user_id)
            removed = {int(row["id"]) for row in plan.devices}
            removed_peer_ids.update(removed)
            known_peer_ids.difference_update(removed)
            results["block_complete"] = barrier.complete_block(
                user_id,
                removed_local_device_ids=removed,
            )
        except Exception as exc:
            errors.append(exc)
        finally:
            block_finished.set()
            conn.close()

    issuance_thread = threading.Thread(target=issue_in_thread)
    issuance_thread.start()
    assert issuer_entered.wait(timeout=3)
    block_thread = threading.Thread(target=block_in_thread)
    block_thread.start()
    assert block_begin_seen.wait(timeout=3)
    assert not block_finished.is_set()
    allow_issuer.set()
    issuance_thread.join(timeout=3)
    block_thread.join(timeout=3)

    assert not issuance_thread.is_alive()
    assert not block_thread.is_alive()
    assert errors == []
    receipt = results["issuance"].receipts[0]
    assert results["issuance"].status == "completed"
    assert results["issuer_calls"] == 1
    assert int(receipt.device_id) in removed_peer_ids
    assert known_peer_ids == set()
    assert results["block_complete"] is True
    verification_conn = connect(database_path)
    verification_repo = Repository(verification_conn)
    barrier = verification_repo.get_protocol_issuance_user_barrier(user_id)
    assert barrier["state"] == "blocked"
    verification_conn.close()


def test_admin_awg3_failure_after_issuer_persists_recovery_and_never_reissues(
    tmp_path,
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=SyntheticAwg3AccessService(repo, peer_applier),
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: (_ for _ in ()).throw(
            RuntimeError("synthetic attachment failure")
        ),
    )
    manifest = _manifest(_phase13_item())

    first = service.issue_manifest(manifest)
    replay = service.issue_manifest(manifest)

    attempt = conn.execute("SELECT * FROM protocol_issuance_attempts").fetchone()
    assert first.status == "partial_failure"
    assert replay.receipts == first.receipts
    assert attempt["state"] == "recovery_required"
    assert attempt["local_device_id"] == first.receipts[0].device_id
    assert attempt["passport_device_id"] == first.receipts[0].passport_device_id
    assert len(peer_applier.applied) == 1


def test_preissuer_recovery_marker_failure_prevents_admin_awg3_issuer_call(
    tmp_path,
    monkeypatch,
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    access = SyntheticAwg3AccessService(repo, peer_applier)
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=access,
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    )

    def fail_initial_marker(*_args, **_kwargs):
        raise RuntimeError("synthetic admin recovery marker failed")

    monkeypatch.setattr(
        repo,
        "mark_protocol_issuance_attempt_recovery_required",
        fail_initial_marker,
    )

    with pytest.raises(RuntimeError, match="synthetic admin recovery marker failed"):
        service.issue_manifest(_manifest(_phase13_item()))

    assert access.calls == []
    assert conn.execute("SELECT COUNT(*) FROM protocol_issuance_attempts").fetchone()[0] == 0


def test_admin_secondary_recovery_failure_commits_unknown_marker_and_never_reissues(
    tmp_path,
    monkeypatch,
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    access = SyntheticAwg3AccessService(repo, peer_applier)
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=access,
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: (_ for _ in ()).throw(
            RuntimeError("synthetic admin finalization failure")
        ),
    )
    original_mark = repo.mark_protocol_issuance_attempt_recovery_required
    mark_calls = []

    def fail_recovery_enrichment(*args, **kwargs):
        mark_calls.append(kwargs["reason_code"])
        if len(mark_calls) == 2:
            raise RuntimeError("synthetic admin recovery enrichment failed")
        return original_mark(*args, **kwargs)

    monkeypatch.setattr(
        repo,
        "mark_protocol_issuance_attempt_recovery_required",
        fail_recovery_enrichment,
    )
    manifest = _manifest(_phase13_item())

    with pytest.raises(RuntimeError, match="synthetic admin recovery enrichment failed"):
        service.issue_manifest(manifest)

    attempt = conn.execute("SELECT * FROM protocol_issuance_attempts").fetchone()
    assert attempt["state"] == "recovery_required"
    assert attempt["reason_code"] == "issuer_in_progress"
    replay = service.issue_manifest(manifest)
    assert replay.status == "partial_failure"
    assert len(peer_applier.applied) == 1


@pytest.mark.parametrize(
    "blocked_decision",
    [
        "blocked_global_acceptance",
        "blocked_runtime_suspended",
        "blocked_evidence_stale_or_failed",
    ],
    ids=["security_revoked", "emergency_suspended", "evidence_stale"],
)
def test_admin_awg3_batch_rechecks_fresh_admission_inside_each_serialized_slot(
    tmp_path,
    blocked_decision,
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    admitted = _admission("admitted_awg3").decide(None)
    blocked = AdmissionResult(
        blocked_decision,
        ProtocolVersion.AWG3,
        None,
        None,
    )
    admission = SequencedAdmissionService(
        [admitted, admitted, admitted, blocked]
    )
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=SyntheticAwg3AccessService(repo, peer_applier),
        admission_service=admission,
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    )

    result = service.issue_manifest(
        _manifest(
            _phase13_item(recipient="Alice", device="Laptop"),
            _phase13_item(recipient="Bob", device="Phone"),
        )
    )

    assert result.status == "partial_failure"
    assert len(admission.calls) == 4
    assert len(peer_applier.applied) == 1
    assert [receipt.status for receipt in result.receipts] == [
        "completed",
        "partial_failure",
    ]
    assert result.receipts[1].error_code == blocked_decision
    attempts = conn.execute(
        "SELECT state, compatibility_evidence_id FROM protocol_issuance_attempts "
        "ORDER BY id"
    ).fetchall()
    assert [tuple(row) for row in attempts] == [("completed", "compat-exact")]
    assert conn.execute("SELECT COUNT(*) FROM device_protocol_profiles").fetchone()[0] == 1


def test_admin_phase_a_marker_is_visible_before_remote_baseexception_and_restart(
    tmp_path,
):
    database_path = tmp_path / "issuance.sqlite3"
    conn, repo = _repo(tmp_path)
    observed_markers = []
    remote_side_effects = []

    class CrashingRemoteAccess:
        def create_operator_device(self, **kwargs):
            visibility_conn = connect(database_path)
            observed_markers.extend(
                tuple(row)
                for row in visibility_conn.execute(
                    "SELECT state, reason_code FROM protocol_issuance_attempts"
                ).fetchall()
            )
            visibility_conn.close()
            remote_side_effects.append(kwargs["passport_device_id"])
            raise SystemExit("synthetic admin remote crash")

    manifest = _manifest(_phase13_item())
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=CrashingRemoteAccess(),
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    )

    with pytest.raises(SystemExit, match="synthetic admin remote crash"):
        service.issue_manifest(manifest)
    conn.close()

    assert observed_markers == [("recovery_required", "issuer_in_progress")]
    assert len(remote_side_effects) == 1
    retry_conn = connect(database_path)
    retry_repo = Repository(retry_conn)
    retry_access = SpyAccessService()
    retry = AdminConfigIssuanceService(
        repo=retry_repo,
        access_service=retry_access,
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    ).issue_manifest(manifest)
    assert retry.status == "partial_failure"
    assert retry_access.calls == []
    retry_conn.close()


def test_admin_phase_a_commit_failure_prevents_remote_issuer(tmp_path):
    conn, repo = _repo(tmp_path)
    access = SpyAccessService()
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=access,
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    )
    delegate = conn
    repo._conn = FailNextCommitConnection(delegate)

    try:
        with pytest.raises(RuntimeError, match="synthetic phase-a commit failed"):
            service.issue_manifest(_manifest(_phase13_item()))
        assert access.calls == []
        assert delegate.in_transaction is False
        assert delegate.execute(
            "SELECT COUNT(*) FROM protocol_issuance_attempts"
        ).fetchone()[0] == 0
    finally:
        repo._conn = delegate
        delegate.rollback()


def test_admin_block_in_phase_gap_prevents_remote_issuer_and_keeps_marker(
    tmp_path,
    monkeypatch,
):
    conn, repo = _repo(tmp_path)
    peer_applier = FakePeerApplier()
    access = SyntheticAwg3AccessService(repo, peer_applier)
    service = AdminConfigIssuanceService(
        repo=repo,
        access_service=access,
        admission_service=_admission("admitted_awg3"),
        admin_telegram_id=7001,
        attachment_builder=lambda _filename, _content: None,
    )
    original_prepare = getattr(
        service,
        "_prepare_awg3_execution_marker",
        lambda **_kwargs: None,
    )

    def block_after_phase_a(**kwargs):
        prepared = original_prepare(**kwargs)
        recipient = repo.get_user_by_operator_label("SooL")
        ProtocolIssuanceBarrierService(repo).begin_block(int(recipient["id"]))
        return prepared

    monkeypatch.setattr(
        service,
        "_prepare_awg3_execution_marker",
        block_after_phase_a,
        raising=False,
    )

    result = service.issue_manifest(_manifest(_phase13_item()))

    assert result.status == "partial_failure"
    assert result.receipts[0].error_code == "user_issuance_blocked"
    assert access.calls == []
    attempt = conn.execute("SELECT * FROM protocol_issuance_attempts").fetchone()
    assert attempt["state"] == "recovery_required"
    assert attempt["reason_code"] == "issuer_in_progress"
