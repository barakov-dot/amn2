import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.access import AccessService
from app.services.admin_config_issuance import AdminConfigIssuanceService
from app.services.awg3_control import Awg3ControlService
from app.services.phase15_bootstrap import (
    AdminHealthEvent,
    Phase15BootstrapUnavailable,
    ProductionAwg3ConfigIssuer,
    build_phase15_awg3_components,
    load_phase15_awg3_issuer_material,
)
from app.services.protocol_admission import AdmissionRequest, ProtocolAdmissionService
from app.services.self_service_issuance import SelfServiceIssuanceRequest
from app.services.telegram_callback_state import TelegramCallbackStateService
from app.vpn.protocol_versions import ProtocolVersion
from app.services.client_compatibility import ClientIdentity


NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
SOURCE_HEAD = "a" * 40
PACKAGE_ID = "phase15-dual-protocol-bootstrap-20260811-001"
RUNTIME_RECEIPT = "sha256:" + "b" * 64
CLIENT = ClientIdentity("amnezia_vpn", "windows", "5.0.0.5", "50005")


class RecordingPeerApplier:
    def __init__(self):
        self.calls = []
        self.runtime_targets = []

    def for_runtime(self, runtime):
        targeted = RecordingRuntimePeerApplier(runtime)
        self.runtime_targets.append(targeted)
        return targeted


class RecordingRuntimePeerApplier:
    def __init__(self, runtime):
        self.runtime = runtime
        self.calls = []

    def list_allocated_ips(self, *, server):
        return []

    def apply_peer(self, **kwargs):
        self.calls.append(kwargs)


class RecordingAccessService:
    def __init__(self, peer_applier):
        self._peer_applier = peer_applier
        self.calls = []

    def create_protocol_device_for_existing_passport(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(device_id=42, local_device_id=42)


def _material_payload(secret: str) -> dict[str, object]:
    return {
        "provider_identity": "phase15-material-provider-001",
        "runtime_instance_id": "spain-awg3-runtime",
        "endpoint_host": "awg3.example.test",
        "server_public_key": "awg3-server-public",
        "s1": 12,
        "s2": 13,
        "s3": 14,
        "s4": 15,
        "content_padding_addition": "0-64",
        "rekey_after_time": "120",
        "rekey_timeout": "5",
        "reject_after_time": "180",
        "keepalive_timeout": "30",
        "max_handshake_attempts": "20",
        "header_protection_key_ref": "phase15-hpk-001",
        "header_protection_key_fingerprint": "sha256:"
        + hashlib.sha256(secret.encode("utf-8")).hexdigest(),
    }


def _write_provider_files(tmp_path):
    secret = "strict-phase15-header-protection-key"
    paths = {
        "runtime": tmp_path / "runtime.json",
        "evidence": tmp_path / "evidence.json",
        "build": tmp_path / "build.json",
        "material": tmp_path / "material.json",
        "hpk": tmp_path / "hpk.secret",
    }
    paths["runtime"].write_text(
        json.dumps(
            {
                "provider_identity": "phase15-runtime-provider-001",
                "runtimes": [
                    {
                        "runtime_instance_id": "spain-awg3-runtime",
                        "server_id": 1,
                        "protocol_version": "awg3",
                        "runtime_version": "awg3-runtime-1",
                        "interface_name": "awg3",
                        "udp_port": 30003,
                        "vpn_cidr": "10.9.0.0/24",
                        "container_name": None,
                        "service_name": "awg3.service",
                        "config_path": "/etc/amnezia/awg3.conf",
                        "lifecycle_state": "accepted",
                        "acceptance_receipt": RUNTIME_RECEIPT,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    evidence = []
    for source_kind in ("official_release", "local_import", "full_data"):
        evidence.append(
            {
                "evidence_id": f"evidence-{source_kind}",
                "client": {
                    "application": CLIENT.application,
                    "platform": CLIENT.platform,
                    "version": CLIENT.version,
                    "build_id": CLIENT.build_id,
                },
                "protocol_version": "awg3",
                "source_kind": source_kind,
                "status": "passed",
                "observed_at": NOW.isoformat(),
                "safe_reference": f"local:{source_kind}",
                "scope": "exact stable build",
                "release_kind": "stable",
            }
        )
    paths["evidence"].write_text(
        json.dumps(
            {
                "provider_identity": "phase15-evidence-provider-001",
                "evidence": evidence,
            }
        ),
        encoding="utf-8",
    )
    paths["build"].write_text(
        json.dumps(
            {
                "provider_identity": "phase15-build-provider-001",
                "package_id": PACKAGE_ID,
                "source_head": SOURCE_HEAD,
                "client": {
                    "application": CLIENT.application,
                    "platform": CLIENT.platform,
                    "version": CLIENT.version,
                    "build_id": CLIENT.build_id,
                },
            }
        ),
        encoding="utf-8",
    )
    paths["material"].write_text(
        json.dumps(_material_payload(secret)),
        encoding="utf-8",
    )
    paths["hpk"].write_text(secret, encoding="utf-8")
    return paths


def _settings(tmp_path, **updates):
    paths = _write_provider_files(tmp_path)
    values = {
        "_env_file": None,
        "telegram_bot_token": "TEST_TOKEN",
        "app_secret_key": "test-secret-value-with-more-than-32-characters",
        "admin_telegram_ids": "9001",
        "server_name": "local",
        "awg3_bootstrap_enabled": True,
        "awg3_runtime_provider_path": str(paths["runtime"]),
        "awg3_runtime_provider_identity": "phase15-runtime-provider-001",
        "awg3_evidence_provider_path": str(paths["evidence"]),
        "awg3_evidence_provider_identity": "phase15-evidence-provider-001",
        "awg3_exact_build_provider_path": str(paths["build"]),
        "awg3_exact_build_provider_identity": "phase15-build-provider-001",
        "awg3_expected_runtime_instance_id": "spain-awg3-runtime",
        "awg3_expected_package_id": PACKAGE_ID,
        "awg3_expected_source_head": SOURCE_HEAD,
        "awg3_issuer_material_provider_path": str(paths["material"]),
        "awg3_issuer_material_provider_identity": "phase15-material-provider-001",
        "awg3_hpk_secret_path": str(paths["hpk"]),
        "awg3_hpk_secret_reference": "phase15-hpk-001",
    }
    values.update(updates)
    return Settings(**values), paths


def _accepted_repo(tmp_path):
    conn = connect(tmp_path / "phase15.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    repo.update_awg3_control_state(
        runtime_accepted=True,
        global_accepted=True,
        issuance_enabled=True,
        emergency_suspended=False,
        runtime_receipt=RUNTIME_RECEIPT,
        actor_id=9001,
        reason="test acceptance",
    )
    repo.upsert_client_build_acceptance(
        application=CLIENT.application,
        platform=CLIENT.platform,
        client_version=CLIENT.version,
        client_build=CLIENT.build_id,
        state="accepted",
        evidence_ids=(
            "evidence-official_release",
            "evidence-local_import",
            "evidence-full_data",
        ),
        actor_id=9001,
        reason="test acceptance",
    )
    return conn, repo


@pytest.mark.parametrize("mutation", ["missing", "unknown", "wrong_type", "nonce"])
def test_issuer_material_json_is_strict_and_fail_closed(tmp_path, mutation):
    settings, paths = _settings(tmp_path)
    payload = _material_payload("strict-phase15-header-protection-key")
    if mutation == "missing":
        payload.pop("rekey_timeout")
    elif mutation == "unknown":
        payload["fallback"] = "forbidden"
    elif mutation == "wrong_type":
        payload["content_padding_addition"] = 16
    else:
        payload["s3"] = 11
    paths["material"].write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(Phase15BootstrapUnavailable):
        load_phase15_awg3_issuer_material(settings)


def test_issuer_material_rejects_wrong_hpk_reference_before_secret_read(tmp_path, monkeypatch):
    settings, paths = _settings(tmp_path)
    payload = _material_payload("strict-phase15-header-protection-key")
    payload["header_protection_key_ref"] = "other-hpk"
    paths["material"].write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("secret read"))

    with pytest.raises(Phase15BootstrapUnavailable, match="reference"):
        load_phase15_awg3_issuer_material(settings)


@pytest.mark.parametrize("mutation", ["missing", "fingerprint"])
def test_hpk_file_resolver_fails_closed_without_fallback(tmp_path, mutation):
    settings, paths = _settings(tmp_path)
    if mutation == "missing":
        paths["hpk"].unlink()
    else:
        paths["hpk"].write_text("wrong-secret", encoding="utf-8")
    material = load_phase15_awg3_issuer_material(settings)

    with pytest.raises(ValueError, match="header_protection_key"):
        material.secret_resolver.resolve(material.header_protection_key.reference)


def test_disabled_bootstrap_reads_no_provider_or_secret(tmp_path, monkeypatch):
    settings = Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret-value-with-more-than-32-characters",
    )
    conn = connect(tmp_path / "disabled.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: pytest.fail("provider read"))
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("secret read"))

    components = build_phase15_awg3_components(settings, repo, None, None)

    assert components.available is False
    assert components.awg3_client_choices == ()


def test_build_components_wires_real_services_without_startup_effects(tmp_path):
    settings, _paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is True
    assert isinstance(components.callback_state, TelegramCallbackStateService)
    assert components.callback_state._repo is repo
    assert isinstance(components.control_service, Awg3ControlService)
    assert isinstance(components.protocol_admission_service, ProtocolAdmissionService)
    assert isinstance(components.issuer, ProductionAwg3ConfigIssuer)
    assert len(components.awg3_client_choices) == 1
    assert access.calls == []
    assert peer.calls == []


def test_fresh_provider_failure_blocks_real_issuer_boundary(tmp_path):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)
    components = build_phase15_awg3_components(settings, repo, access, peer)
    request = AdmissionRequest(client=CLIENT, protocol_version=ProtocolVersion.AWG3)
    admission, _state = components.admission_provider(request)
    assert admission.admitted is True
    paths["build"].write_text("{}", encoding="utf-8")

    with pytest.raises(Phase15BootstrapUnavailable):
        components.issuer.issue(
            request=SelfServiceIssuanceRequest(
                user_id=1,
                telegram_id=1001,
                passport_device_id="dev_0123456789abcdef0123456789abcdef",
                protocol_version=ProtocolVersion.AWG3,
                client=CLIENT,
            ),
            admission=admission,
        )

    assert access.calls == []
    assert peer.calls == []


def test_global_acceptance_needs_no_per_user_admin_but_admin_factory_is_configured_only(
    tmp_path,
):
    settings, _paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)
    components = build_phase15_awg3_components(settings, repo, access, peer)
    admission, state = components.admission_provider(
        AdmissionRequest(client=CLIENT, protocol_version=ProtocolVersion.AWG3)
    )

    assert admission.decision == "admitted_awg3"
    assert state.permits_new_issuance is True
    service = components.admin_config_issuance_factory(
        admin_telegram_id=9001,
        attachment_builder=lambda filename, text: None,
    )
    assert isinstance(service, AdminConfigIssuanceService)
    with pytest.raises(Phase15BootstrapUnavailable, match="admin"):
        components.admin_config_issuance_factory(
            admin_telegram_id=9002,
            attachment_builder=lambda filename, text: None,
        )


def test_future_admin_health_event_taxonomy_has_no_runtime_activation():
    assert {event.value for event in AdminHealthEvent} == {
        "server_unreachable",
        "awg2_degraded",
        "awg3_degraded",
    }


def test_issuer_material_is_bound_to_exact_runtime_endpoint_and_public_key(tmp_path):
    settings, paths = _settings(tmp_path)
    payload = _material_payload("strict-phase15-header-protection-key")
    payload.update(
        {
            "runtime_instance_id": "spain-awg3-runtime",
            "endpoint_host": "awg3.example.test",
            "server_public_key": "awg3-server-public",
            "content_padding_addition": "0-64",
        }
    )
    paths["material"].write_text(json.dumps(payload), encoding="utf-8")

    material = load_phase15_awg3_issuer_material(settings)

    assert material.runtime_instance_id == "spain-awg3-runtime"
    assert material.endpoint_host == "awg3.example.test"
    assert material.server_public_key == "awg3-server-public"


def test_bootstrap_rejects_multiple_or_mismatching_awg3_runtime_candidates(tmp_path):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    payload = json.loads(paths["runtime"].read_text(encoding="utf-8"))
    second = dict(payload["runtimes"][0])
    second.update(
        {
            "runtime_instance_id": "other-awg3-runtime",
            "interface_name": "awg3-other",
            "udp_port": 30004,
            "vpn_cidr": "10.10.0.0/24",
            "service_name": "awg3-other.service",
            "config_path": "/etc/amnezia/awg3-other.conf",
        }
    )
    payload["runtimes"].append(second)
    paths["runtime"].write_text(json.dumps(payload), encoding="utf-8")

    peer = RecordingPeerApplier()
    components = build_phase15_awg3_components(
        settings,
        repo,
        RecordingAccessService(peer),
        peer,
    )

    assert components.available is False
    assert components.awg3_client_choices == ()
    assert components.unavailable_reason == "AWG3 bootstrap providers are invalid"


def test_self_service_issuer_passes_only_selected_runtime_target(tmp_path):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    runtime_payload = json.loads(paths["runtime"].read_text(encoding="utf-8"))
    awg2 = dict(runtime_payload["runtimes"][0])
    awg2.update(
        {
            "runtime_instance_id": "legacy-awg2-runtime",
            "protocol_version": "awg2",
            "interface_name": "awg0",
            "udp_port": 30001,
            "vpn_cidr": "10.8.0.0/24",
            "service_name": "awg-quick@awg0",
            "config_path": "/etc/amnezia/awg0.conf",
        }
    )
    runtime_payload["runtimes"].insert(0, awg2)
    paths["runtime"].write_text(json.dumps(runtime_payload), encoding="utf-8")
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)
    components = build_phase15_awg3_components(settings, repo, access, peer)
    request = AdmissionRequest(client=CLIENT, protocol_version=ProtocolVersion.AWG3)
    admission, _state = components.admission_provider(request)

    components.issuer.issue(
        request=SelfServiceIssuanceRequest(
            user_id=1,
            telegram_id=1001,
            passport_device_id="dev_0123456789abcdef0123456789abcdef",
            protocol_version=ProtocolVersion.AWG3,
            client=CLIENT,
        ),
        admission=admission,
    )

    call = access.calls[0]
    assert call["runtime_target"].runtime_instance_id == "spain-awg3-runtime"
    assert call["runtime_target"].interface_name == "awg3"
    assert call["runtime_target"].vpn_cidr == "10.9.0.0/24"
    assert call["runtime_peer_applier"].runtime.runtime_instance_id == "spain-awg3-runtime"
    assert all(target.runtime.interface_name != "awg0" for target in peer.runtime_targets)


def _phase15_admin_manifest(request_id, *items):
    return {
        "request_id": request_id,
        "server": "local",
        "items": list(items),
    }


def _phase15_admin_item(device_label):
    return {
        "recipient_label": "Phase15 recipient",
        "device_label": device_label,
        "client_application": CLIENT.application,
        "client_platform": CLIENT.platform,
        "client_version": CLIENT.version,
        "client_build": CLIENT.build_id,
        "protocol_version": "awg3",
    }


def test_admin_factory_uses_fresh_material_aware_runtime_issuer_success_boundary(tmp_path):
    settings, _paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    peer = RecordingPeerApplier()
    access = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "phase15-admin-success-secret-with-more-than-32-chars"
        ),
        peer_applier=peer,
    )
    attachments = []
    components = build_phase15_awg3_components(settings, repo, access, peer)
    service = components.admin_config_issuance_factory(
        admin_telegram_id=9001,
        attachment_builder=lambda filename, text: attachments.append((filename, text)),
    )

    result = service.issue_manifest(
        _phase15_admin_manifest(
            "phase15-admin-success-001",
            _phase15_admin_item("AWG3 laptop"),
        )
    )

    assert result.status == "completed"
    assert result.receipts[0].status == "completed"
    assert len(attachments) == 1
    assert len(peer.runtime_targets) >= 1
    assert sum(len(target.calls) for target in peer.runtime_targets) == 1
    assert peer.calls == []


def test_admin_factory_reloads_providers_at_each_item_boundary(tmp_path):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    peer = RecordingPeerApplier()
    access = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "phase15-admin-fresh-secret-with-more-than-32-chars"
        ),
        peer_applier=peer,
    )
    attachments = []

    def attach_and_invalidate(filename, text):
        attachments.append((filename, text))
        paths["build"].write_text("{}", encoding="utf-8")

    components = build_phase15_awg3_components(settings, repo, access, peer)
    service = components.admin_config_issuance_factory(
        admin_telegram_id=9001,
        attachment_builder=attach_and_invalidate,
    )

    result = service.issue_manifest(
        _phase15_admin_manifest(
            "phase15-admin-fresh-001",
            _phase15_admin_item("AWG3 laptop"),
            _phase15_admin_item("AWG3 phone"),
        )
    )

    assert result.status == "partial_failure"
    assert [receipt.status for receipt in result.receipts] == ["completed", "partial_failure"]
    assert len(attachments) == 1
    assert sum(len(target.calls) for target in peer.runtime_targets) == 1


def test_provider_json_bytes_rows_and_nesting_are_bounded(tmp_path):
    from app.services import phase15_bootstrap

    oversized = tmp_path / "oversized.json"
    oversized.write_text('{"provider_identity":"x"}' + " " * 70_000, encoding="utf-8")
    deeply_nested = tmp_path / "deep.json"
    deeply_nested.write_text(
        json.dumps({"root": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}}),
        encoding="utf-8",
    )

    with pytest.raises(Phase15BootstrapUnavailable, match="size"):
        phase15_bootstrap._read_json_object(str(oversized), "test provider")
    with pytest.raises(Phase15BootstrapUnavailable, match="nesting"):
        phase15_bootstrap._read_json_object(str(deeply_nested), "test provider")


def test_runtime_provider_row_count_is_bounded_before_domain_materialization(tmp_path):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    payload = json.loads(paths["runtime"].read_text(encoding="utf-8"))
    payload["runtimes"] = payload["runtimes"] * 101
    paths["runtime"].write_text(json.dumps(payload), encoding="utf-8")

    peer = RecordingPeerApplier()
    components = build_phase15_awg3_components(
        settings,
        repo,
        RecordingAccessService(peer),
        peer,
    )

    assert components.available is False
    assert components.unavailable_reason == "AWG3 bootstrap providers are invalid"
