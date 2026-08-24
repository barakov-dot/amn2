import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.access import AccessService, OperatorDeviceContext
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
from app.services.device_passports import create_device_passport


NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
SOURCE_HEAD = "a" * 40
PACKAGE_ID = "phase16-awg3-family-3-1-spain-pilot-20260824-002"
PROTOCOL_FAMILY = "awg3"
PROTOCOL_REVISION = "3.1"
CONFIG_REVISION = "amneziawg_v3_1"
RUNTIME_SOURCE_COMMIT = "1f50ad736ecca22a9bfc7b4606805ec9ca49fe48"
RUNTIME_ARTIFACT_IDENTITY = (
    "docker.io/amneziavpn/amneziawg-go@"
    "sha256:4e1fd2840f8d26eb6ec8bc1598e66f2f17f5d0201cd2baadbde560c104d4fc9d"
)
RUNTIME_CAPABILITIES = ["disable_cookies", "random_trailers"]
CLIENT_ARTIFACT_IDENTITY = (
    "github:amnezia-vpn/amneziawg-android/releases/v3.1.20260814/"
    "AmneziaWG-3.1.202060814.apk@"
    "sha256:74f109a948f012e8b90b4055e98bb9bee77bbb8e5d0fe7d5a057dd9698009697"
)
CLIENT = ClientIdentity("amneziawg", "android", "v3.1.20260814", "12")


def _content_identity(kind: str, payload: object) -> str:
    canonical = json.dumps(
        {
            "kind": kind,
            "package_id": PACKAGE_ID,
            "source_head": SOURCE_HEAD,
            "payload": payload,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


class RecordingPeerApplier:
    def __init__(self):
        self.calls = []
        self.runtime_targets = []

    def for_runtime(self, runtime):
        targeted = RecordingRuntimePeerApplier(runtime)
        self.runtime_targets.append(targeted)
        return targeted

    def list_allocated_ips(self, *, server):
        return []

    def apply_peer(self, **kwargs):
        self.calls.append(kwargs)


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


class _ReadSizeSpy:
    def __init__(self, handle, sizes):
        self._handle = handle
        self._sizes = sizes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._handle.__exit__(exc_type, exc_value, traceback)

    def read(self, size=-1):
        self._sizes.append(size)
        return self._handle.read(size)


def _material_payload(secret: str) -> dict[str, object]:
    payload = {
        "protocol_family": PROTOCOL_FAMILY,
        "protocol_revision": PROTOCOL_REVISION,
        "config_revision": CONFIG_REVISION,
        "runtime_artifact_identity": RUNTIME_ARTIFACT_IDENTITY,
        "runtime_capabilities": RUNTIME_CAPABILITIES,
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
        "random_trailers": "on",
        "disable_cookies": "on",
        "header_protection_key_ref": "phase16-hpk-001",
        "header_protection_key_fingerprint": "sha256:"
        + hashlib.sha256(secret.encode("utf-8")).hexdigest(),
    }
    return {
        "provider_identity": _content_identity("issuer_material", payload),
        **payload,
    }


def _provider_payloads(secret: str) -> dict[str, dict[str, object]]:
    runtime_row = {
        "runtime_instance_id": "spain-awg3-runtime",
        "server_id": 1,
        "protocol_version": "awg3",
        "protocol_family": PROTOCOL_FAMILY,
        "protocol_revision": PROTOCOL_REVISION,
        "config_revision": CONFIG_REVISION,
        "runtime_version": "3.1.20260814",
        "runtime_source_commit": RUNTIME_SOURCE_COMMIT,
        "runtime_artifact_identity": RUNTIME_ARTIFACT_IDENTITY,
        "runtime_capabilities": RUNTIME_CAPABILITIES,
        "capability_evidence": (
            "github:amnezia-vpn/amneziawg-go/commit/" + RUNTIME_SOURCE_COMMIT
        ),
        "interface_name": "awg3",
        "udp_port": 30003,
        "vpn_cidr": "10.9.0.0/24",
        "container_name": None,
        "service_name": "awg3.service",
        "config_path": "/etc/amnezia/awg3.conf",
        "lifecycle_state": "accepted",
    }
    runtime_row["acceptance_receipt"] = _content_identity(
        "runtime_acceptance", runtime_row
    )
    evidence = []
    for source_kind in ("official_release", "local_import", "full_data"):
        evidence_row = {
            "client": {
                "application": CLIENT.application,
                "platform": CLIENT.platform,
                "version": CLIENT.version,
                "build_id": CLIENT.build_id,
            },
            "protocol_version": "awg3",
            "protocol_family": PROTOCOL_FAMILY,
            "protocol_revision": PROTOCOL_REVISION,
            "config_revision": CONFIG_REVISION,
            "runtime_artifact_identity": RUNTIME_ARTIFACT_IDENTITY,
            "runtime_capabilities": RUNTIME_CAPABILITIES,
            "source_kind": source_kind,
            "status": "passed",
            "observed_at": NOW.isoformat(),
            "safe_reference": f"local:{source_kind}",
            "scope": "exact stable build",
            "release_kind": "stable",
        }
        evidence.append(
            {
                "evidence_id": _content_identity("compatibility_evidence", evidence_row),
                **evidence_row,
            }
        )
    build_body = {
        "package_id": PACKAGE_ID,
        "source_head": SOURCE_HEAD,
        "protocol_family": PROTOCOL_FAMILY,
        "protocol_revision": PROTOCOL_REVISION,
        "config_revision": CONFIG_REVISION,
        "runtime_artifact_identity": RUNTIME_ARTIFACT_IDENTITY,
        "runtime_capabilities": RUNTIME_CAPABILITIES,
        "client_artifact_identity": CLIENT_ARTIFACT_IDENTITY,
        "release_kind": "stable",
        "client": {
            "application": CLIENT.application,
            "platform": CLIENT.platform,
            "version": CLIENT.version,
            "build_id": CLIENT.build_id,
        },
    }
    provider_bodies = {
        "runtime": {"runtimes": [runtime_row]},
        "evidence": {"evidence": evidence},
        "build": build_body,
    }
    return {
        name: {
            "provider_identity": _content_identity(f"{name}_provider", body),
            **body,
        }
        for name, body in provider_bodies.items()
    } | {"material": _material_payload(secret)}


def _write_provider_files(tmp_path):
    secret = "strict-phase16-header-protection-key"
    paths = {
        "runtime": tmp_path / "runtime.json",
        "evidence": tmp_path / "evidence.json",
        "build": tmp_path / "build.json",
        "material": tmp_path / "material.json",
        "hpk": tmp_path / "hpk.secret",
    }
    payloads = _provider_payloads(secret)
    for name in ("runtime", "evidence", "build", "material"):
        paths[name].write_text(json.dumps(payloads[name]), encoding="utf-8")
    paths["hpk"].write_text(secret, encoding="utf-8")
    return paths


def _settings(tmp_path, **updates):
    paths = _write_provider_files(tmp_path)
    payloads = {
        name: json.loads(paths[name].read_text(encoding="utf-8"))
        for name in ("runtime", "evidence", "build", "material")
    }
    values = {
        "_env_file": None,
        "telegram_bot_token": "TEST_TOKEN",
        "app_secret_key": "test-secret-value-with-more-than-32-characters",
        "admin_telegram_ids": "9001",
        "server_name": "local",
        "awg3_bootstrap_enabled": True,
        "awg3_runtime_provider_path": str(paths["runtime"]),
        "awg3_runtime_provider_identity": payloads["runtime"]["provider_identity"],
        "awg3_evidence_provider_path": str(paths["evidence"]),
        "awg3_evidence_provider_identity": payloads["evidence"]["provider_identity"],
        "awg3_exact_build_provider_path": str(paths["build"]),
        "awg3_exact_build_provider_identity": payloads["build"]["provider_identity"],
        "awg3_expected_runtime_instance_id": "spain-awg3-runtime",
        "awg3_expected_package_id": PACKAGE_ID,
        "awg3_expected_source_head": SOURCE_HEAD,
        "awg3_issuer_material_provider_path": str(paths["material"]),
        "awg3_issuer_material_provider_identity": payloads["material"]["provider_identity"],
        "awg3_hpk_secret_path": str(paths["hpk"]),
        "awg3_hpk_secret_reference": "phase16-hpk-001",
    }
    values.update(updates)
    return Settings(**values), paths


def _accepted_repo(tmp_path):
    payloads = _provider_payloads("strict-phase16-header-protection-key")
    runtime_receipt = payloads["runtime"]["runtimes"][0]["acceptance_receipt"]
    evidence_ids = tuple(
        row["evidence_id"] for row in payloads["evidence"]["evidence"]
    )
    conn = connect(tmp_path / "phase15.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    repo.update_awg3_control_state(
        runtime_accepted=True,
        global_accepted=True,
        issuance_enabled=True,
        emergency_suspended=False,
        runtime_receipt=runtime_receipt,
        actor_id=9001,
        reason="test acceptance",
    )
    repo.upsert_client_build_acceptance(
        application=CLIENT.application,
        platform=CLIENT.platform,
        client_version=CLIENT.version,
        client_build=CLIENT.build_id,
        state="accepted",
        evidence_ids=evidence_ids,
        actor_id=9001,
        reason="test acceptance",
    )
    return conn, repo


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "unknown",
        "wrong_type",
        "nonce",
        "random_trailers_off",
        "disable_cookies_malformed",
    ],
)
def test_issuer_material_json_is_strict_and_fail_closed(tmp_path, mutation):
    settings, paths = _settings(tmp_path)
    payload = _material_payload("strict-phase16-header-protection-key")
    if mutation == "missing":
        payload.pop("rekey_timeout")
    elif mutation == "unknown":
        payload["fallback"] = "forbidden"
    elif mutation == "wrong_type":
        payload["content_padding_addition"] = 16
    elif mutation == "nonce":
        payload["s3"] = 11
    elif mutation == "random_trailers_off":
        payload["random_trailers"] = "off"
    else:
        payload["disable_cookies"] = True
    paths["material"].write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(Phase15BootstrapUnavailable):
        load_phase15_awg3_issuer_material(settings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("random_trailers", "off"),
        ("random_trailers", ""),
        ("disable_cookies", "true"),
        ("disable_cookies", True),
    ],
)
def test_phase16_material_rejects_resigned_non_on_toggles(tmp_path, field, value):
    settings, paths = _settings(tmp_path)
    payload = _material_payload("strict-phase16-header-protection-key")
    payload[field] = value
    payload["provider_identity"] = _content_identity(
        "issuer_material",
        {key: item for key, item in payload.items() if key != "provider_identity"},
    )
    settings = settings.model_copy(
        update={"awg3_issuer_material_provider_identity": payload["provider_identity"]}
    )
    paths["material"].write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(Phase15BootstrapUnavailable):
        load_phase15_awg3_issuer_material(settings)


def test_issuer_material_rejects_wrong_hpk_reference_before_secret_read(tmp_path, monkeypatch):
    settings, paths = _settings(tmp_path)
    payload = _material_payload("strict-phase16-header-protection-key")
    payload["header_protection_key_ref"] = "other-hpk"
    payload["provider_identity"] = _content_identity(
        "issuer_material",
        {key: value for key, value in payload.items() if key != "provider_identity"},
    )
    settings = settings.model_copy(
        update={
            "awg3_issuer_material_provider_identity": payload["provider_identity"]
        }
    )
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


def test_invalid_awg3_runtime_provider_fails_before_issuer_or_peer_side_effects(
    tmp_path,
):
    settings, paths = _settings(tmp_path)
    runtime_payload = json.loads(paths["runtime"].read_text(encoding="utf-8"))
    runtime_row = runtime_payload["runtimes"][0]
    runtime_row["vpn_cidr"] = "2001:db8::/120"
    runtime_row["acceptance_receipt"] = _content_identity(
        "runtime_acceptance",
        {
            key: value
            for key, value in runtime_row.items()
            if key != "acceptance_receipt"
        },
    )
    runtime_payload["provider_identity"] = _content_identity(
        "runtime_provider",
        {
            key: value
            for key, value in runtime_payload.items()
            if key != "provider_identity"
        },
    )
    settings = settings.model_copy(
        update={
            "awg3_runtime_provider_identity": runtime_payload["provider_identity"]
        }
    )
    paths["runtime"].write_text(json.dumps(runtime_payload), encoding="utf-8")
    conn, repo = _accepted_repo(tmp_path)
    repo.update_awg3_control_state(
        runtime_accepted=True,
        global_accepted=True,
        issuance_enabled=True,
        emergency_suspended=False,
        runtime_receipt=runtime_row["acceptance_receipt"],
        actor_id=9001,
        reason="invalid runtime regression setup",
    )
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)
    devices_before = int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0])

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is False
    assert components.unavailable_reason == "AWG3 bootstrap providers are invalid"
    assert components.awg3_client_choices == ()
    assert access.calls == []
    assert peer.calls == []
    assert peer.runtime_targets == []
    assert int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]) == (
        devices_before
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_revision", "3.0"),
        ("config_revision", "amneziawg_v3"),
        ("runtime_source_commit", "b" * 40),
        (
            "runtime_artifact_identity",
            "docker.io/amneziavpn/amneziawg-go@sha256:" + "b" * 64,
        ),
        ("runtime_capabilities", ["random_trailers"]),
        (
            "runtime_capabilities",
            ["disable_cookies", "random_trailers", "unknown_capability"],
        ),
        ("capability_evidence", "github:unverified"),
    ],
)
def test_phase16_runtime_revision_and_capabilities_fail_closed_before_side_effects(
    tmp_path,
    field,
    value,
):
    settings, paths = _settings(tmp_path)
    runtime_payload = json.loads(paths["runtime"].read_text(encoding="utf-8"))
    runtime_row = runtime_payload["runtimes"][0]
    runtime_row[field] = value
    unsigned_runtime = {
        key: item for key, item in runtime_row.items() if key != "acceptance_receipt"
    }
    runtime_row["acceptance_receipt"] = _content_identity(
        "runtime_acceptance", unsigned_runtime
    )
    runtime_payload["provider_identity"] = _content_identity(
        "runtime_provider",
        {
            key: item
            for key, item in runtime_payload.items()
            if key != "provider_identity"
        },
    )
    settings = settings.model_copy(
        update={"awg3_runtime_provider_identity": runtime_payload["provider_identity"]}
    )
    paths["runtime"].write_text(json.dumps(runtime_payload), encoding="utf-8")
    conn, repo = _accepted_repo(tmp_path)
    repo.update_awg3_control_state(
        runtime_accepted=True,
        global_accepted=True,
        issuance_enabled=True,
        emergency_suspended=False,
        runtime_receipt=runtime_row["acceptance_receipt"],
        actor_id=9001,
        reason="mutated Phase 16 runtime contract",
    )
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)
    devices_before = int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0])

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is False
    assert components.unavailable_reason == "AWG3 bootstrap providers are invalid"
    assert access.calls == []
    assert peer.calls == []
    assert peer.runtime_targets == []
    assert int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]) == devices_before


@pytest.mark.parametrize(
    ("provider_name", "mutate"),
    [
        ("runtime", lambda payload: payload["runtimes"][0].__setitem__("udp_port", 30004)),
        (
            "evidence",
            lambda payload: payload["evidence"][0].__setitem__(
                "safe_reference", "local:changed"
            ),
        ),
        (
            "build",
            lambda payload: payload["client"].__setitem__(
                "application", "amneziavpn"
            ),
        ),
        (
            "material",
            lambda payload: payload.__setitem__(
                "endpoint_host", "changed.example.test"
            ),
        ),
    ],
)
def test_stale_content_identity_disables_awg3(
    tmp_path, provider_name, mutate
):
    settings, paths = _settings(tmp_path)
    payload = json.loads(paths[provider_name].read_text(encoding="utf-8"))
    mutate(payload)
    paths[provider_name].write_text(json.dumps(payload), encoding="utf-8")
    _conn, repo = _accepted_repo(tmp_path)
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is False
    assert components.awg3_client_choices == ()
    assert access.calls == []
    assert peer.calls == []


@pytest.mark.parametrize(
    "evidence_ids",
    [
        lambda ids: ids[:-1],
        lambda ids: (*ids, "sha256:" + "f" * 64),
        lambda ids: tuple(reversed(ids)),
        lambda ids: (*ids, ids[0]),
        lambda ids: (ids[0], 7, ids[2]),
    ],
)
def test_acceptance_requires_exact_current_evidence_id_sequence(
    tmp_path, evidence_ids
):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    provider = json.loads(paths["evidence"].read_text(encoding="utf-8"))
    exact_ids = tuple(row["evidence_id"] for row in provider["evidence"])
    repo._conn.execute(
        "UPDATE client_build_acceptances SET evidence_ids_json = ?",
        (json.dumps(evidence_ids(exact_ids), separators=(",", ":")),),
    )
    repo._conn.commit()
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is False
    assert components.awg3_client_choices == ()


@pytest.mark.parametrize(
    ("setting_name", "provider_field", "invalid_identity"),
    [
        ("awg3_expected_package_id", "package_id", "other-package"),
        ("awg3_expected_source_head", "source_head", "A" * 40),
        ("awg3_expected_source_head", "source_head", "a" * 39),
        ("awg3_expected_source_head", "source_head", "g" * 40),
    ],
)
def test_noncanonical_matching_build_identity_disables_only_awg3(
    tmp_path,
    setting_name,
    provider_field,
    invalid_identity,
):
    settings, paths = _settings(tmp_path, **{setting_name: invalid_identity})
    build_payload = json.loads(paths["build"].read_text(encoding="utf-8"))
    build_payload[provider_field] = invalid_identity
    paths["build"].write_text(json.dumps(build_payload), encoding="utf-8")
    _conn, repo = _accepted_repo(tmp_path)
    peer = RecordingPeerApplier()
    access = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "phase15-invalid-identity-secret-with-more-than-32-chars"
        ),
        peer_applier=peer,
    )

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is False
    assert components.awg3_client_choices == ()
    owner_user_id = repo.create_operator_recipient(
        operator_label="AWG2 identity isolation"
    )
    result = access.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=int(repo.get_server_by_name("local")["id"]),
        device_name="AWG2 laptop",
        duration_days=30,
        admin_telegram_id=9001,
        config_version="amneziawg_v2",
        device_context=OperatorDeviceContext(
            platform="windows",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
            protocol_version="awg2",
            runtime_instance_id="legacy-awg2-runtime",
            client_identity_evidence_status="verified",
            compatibility_evidence_id="legacy-awg2-evidence",
        ),
    )
    assert result.passport_device_id is not None
    assert len(peer.calls) == 1


def test_missing_server_dependency_returns_unavailable_components(tmp_path):
    settings, _paths = _settings(tmp_path)
    conn, repo = _accepted_repo(tmp_path)
    conn.execute("DELETE FROM servers")
    conn.commit()
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is False
    assert components.unavailable_reason == "AWG3 bootstrap providers are invalid"
    assert components.awg3_client_choices == ()
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


def test_provider_change_before_access_returns_retryable_blocked_result(
    tmp_path,
    monkeypatch,
):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="phase15-user",
        first_name="Phase",
        last_name="Fifteen",
    )
    server_id = int(repo.get_server_by_name("local")["id"])
    awg2_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phase15-existing-awg2",
        duration_days=30,
        vpn_ip="10.8.0.2",
        peer_public_key="phase15-existing-public",
        peer_private_key_encrypted="phase15-existing-encrypted-private",
        preshared_key_encrypted="phase15-existing-encrypted-psk",
        config_version="amneziawg_v2",
        protocol_version="awg2",
    )
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=awg2_device_id,
        platform=CLIENT.platform,
        official_client_type=CLIENT.application,
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_text="phase15-existing-config-fingerprint-source",
        protocol_version="awg2",
    )
    peer = RecordingPeerApplier()
    access = RecordingAccessService(peer)
    components = build_phase15_awg3_components(settings, repo, access, peer)
    service = components.self_service_issuance_service
    request = SelfServiceIssuanceRequest(
        user_id=user_id,
        telegram_id=1001,
        passport_device_id=passport.device_id,
        protocol_version=ProtocolVersion.AWG3,
        client=CLIENT,
    )
    token = service.decide(request).token
    original_prepare = service._prepare_execution_marker

    def invalidate_after_admission(*args, **kwargs):
        prepared = original_prepare(*args, **kwargs)
        paths["build"].write_text("{}", encoding="utf-8")
        return prepared

    monkeypatch.setattr(service, "_prepare_execution_marker", invalidate_after_admission)

    result = service.issue_after_confirmation(
        request,
        confirmation_token=token,
    )

    assert result.status == "blocked"
    assert result.reason_code == "admission_view_unavailable"
    attempt = repo.list_protocol_issuance_attempts(
        passport_device_id=passport.device_id,
        protocol_version="awg3",
    )[0]
    assert attempt["state"] == "cancelled"
    assert attempt["reason_code"] == "issuer_unavailable_before_side_effect"
    confirmation = repo.claim_issuance_confirmation(
        hashlib.sha256(token.encode()).hexdigest(),
        user_id,
        NOW.isoformat(),
        claim_id_digest="c" * 64,
        claim_expires_at=(NOW.replace(minute=NOW.minute + 1)).isoformat(),
    )
    assert confirmation is not None
    assert confirmation["consumed_at"] is None
    assert access.calls == []
    assert peer.calls == []


@pytest.mark.parametrize("hpk_failure", ["resolver", "fingerprint"])
def test_hpk_failure_before_access_side_effects_is_retryable(
    tmp_path,
    monkeypatch,
    hpk_failure,
):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1002,
        username="phase15-hpk-user",
        first_name="Phase",
        last_name="HPK",
    )
    server_id = int(repo.get_server_by_name("local")["id"])
    awg2_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phase15-hpk-existing-awg2",
        duration_days=30,
        vpn_ip="10.8.0.3",
        peer_public_key="phase15-hpk-existing-public",
        peer_private_key_encrypted="phase15-hpk-existing-encrypted-private",
        preshared_key_encrypted="phase15-hpk-existing-encrypted-psk",
        config_version="amneziawg_v2",
        protocol_version="awg2",
    )
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=awg2_device_id,
        platform=CLIENT.platform,
        official_client_type=CLIENT.application,
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_text="phase15-hpk-existing-config-fingerprint-source",
        protocol_version="awg2",
    )
    peer = RecordingPeerApplier()
    access = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "phase15-hpk-boundary-secret-with-more-than-32-chars"
        ),
        peer_applier=peer,
    )
    components = build_phase15_awg3_components(settings, repo, access, peer)
    request = SelfServiceIssuanceRequest(
        user_id=user_id,
        telegram_id=1002,
        passport_device_id=passport.device_id,
        protocol_version=ProtocolVersion.AWG3,
        client=CLIENT,
    )
    token = components.self_service_issuance_service.decide(request).token
    if hpk_failure == "resolver":
        paths["hpk"].unlink()
    else:
        paths["hpk"].write_text("wrong-hpk", encoding="utf-8")
    key_calls = []

    def unexpected_key_generation():
        key_calls.append("key")
        raise AssertionError("key generation must follow HPK resolution")

    monkeypatch.setattr("app.services.access.generate_keypair", unexpected_key_generation)
    monkeypatch.setattr("app.services.access.generate_key", unexpected_key_generation)

    result = components.self_service_issuance_service.issue_after_confirmation(
        request,
        confirmation_token=token,
    )

    assert result.status == "blocked"
    assert result.reason_code == "admission_view_unavailable"
    attempt = repo.list_protocol_issuance_attempts(
        passport_device_id=passport.device_id,
        protocol_version="awg3",
    )[0]
    assert attempt["state"] == "cancelled"
    assert attempt["reason_code"] == "issuer_unavailable_before_side_effect"
    confirmation = components.callback_state.claim_confirmation(
        token,
        owner_user_id=user_id,
    )
    assert confirmation is not None
    assert components.callback_state.release_confirmation(confirmation) is True
    assert key_calls == []
    assert repo.count_active_devices(user_id) == 1
    assert peer.calls == []
    assert sum(len(target.calls) for target in peer.runtime_targets) == 0


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
    payload = _material_payload("strict-phase16-header-protection-key")
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
    runtime_payload["provider_identity"] = _content_identity(
        "runtime_provider",
        {
            key: value
            for key, value in runtime_payload.items()
            if key != "provider_identity"
        },
    )
    settings = settings.model_copy(
        update={"awg3_runtime_provider_identity": runtime_payload["provider_identity"]}
    )
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


def _admin_adapter_test_doubles():
    access = SimpleNamespace(calls=[])

    def create_operator_device(**kwargs):
        access.calls.append(kwargs)
        return SimpleNamespace(device_id=42)

    access.create_operator_device = create_operator_device
    boundary = SimpleNamespace(
        snapshot=SimpleNamespace(
            client=CLIENT,
            material=object(),
            runtime=object(),
        ),
        admission=SimpleNamespace(
            runtime_instance_id="spain-awg3-runtime",
            compatibility_evidence_id="accepted-evidence-id",
        ),
        runtime_peer_applier=object(),
    )
    issuer = SimpleNamespace(calls=[])

    def fresh_boundary():
        issuer.calls.append("fresh_boundary")
        return boundary

    issuer.fresh_boundary = fresh_boundary
    return access, issuer, boundary


@pytest.mark.parametrize(
    "protocol_version",
    (None, "awg2", "AWG3", "", " awg3", "awg3 "),
)
def test_admin_adapter_rejects_noncanonical_awg3_protocol_before_fresh_boundary(
    protocol_version,
):
    from app.services import phase15_bootstrap

    access, issuer, _boundary = _admin_adapter_test_doubles()
    adapter = phase15_bootstrap._FreshAwg3AdminAccessAdapter(
        access_service=access,
        issuer=issuer,
    )

    with pytest.raises(Phase15BootstrapUnavailable):
        adapter.create_operator_device(
            config_version="amneziawg_v3_1",
            device_context=OperatorDeviceContext(
                platform=CLIENT.platform,
                official_client_type=CLIENT.application,
                client_version=CLIENT.version,
                protocol_version=protocol_version,
                runtime_instance_id="spain-awg3-runtime",
                client_identity_evidence_status="verified",
                compatibility_evidence_id="accepted-evidence-id",
            ),
        )

    assert issuer.calls == []
    assert access.calls == []


def test_admin_adapter_forwards_only_exact_fresh_admission_evidence():
    from app.services import phase15_bootstrap

    access, issuer, boundary = _admin_adapter_test_doubles()
    adapter = phase15_bootstrap._FreshAwg3AdminAccessAdapter(
        access_service=access,
        issuer=issuer,
    )
    exact_context = OperatorDeviceContext(
        platform=CLIENT.platform,
        official_client_type=CLIENT.application,
        client_version=CLIENT.version,
        protocol_version="awg3",
        runtime_instance_id="spain-awg3-runtime",
        client_identity_evidence_status="verified",
        compatibility_evidence_id="accepted-evidence-id",
    )

    adapter.create_operator_device(
        config_version="amneziawg_v3_1",
        device_context=exact_context,
    )

    assert issuer.calls == ["fresh_boundary"]
    assert len(access.calls) == 1
    assert access.calls[0]["device_context"] is exact_context
    assert access.calls[0]["client_build"] == CLIENT.build_id
    assert access.calls[0]["awg3_material"] is boundary.snapshot.material
    assert access.calls[0]["runtime_target"] is boundary.snapshot.runtime
    assert (
        access.calls[0]["runtime_peer_applier"]
        is boundary.runtime_peer_applier
    )

    mismatching_access, mismatching_issuer, _ = _admin_adapter_test_doubles()
    mismatching_adapter = phase15_bootstrap._FreshAwg3AdminAccessAdapter(
        access_service=mismatching_access,
        issuer=mismatching_issuer,
    )
    with pytest.raises(Phase15BootstrapUnavailable):
        mismatching_adapter.create_operator_device(
            config_version="amneziawg_v3_1",
            device_context=replace(
                exact_context,
                compatibility_evidence_id="different-evidence-id",
            ),
        )
    assert mismatching_issuer.calls == ["fresh_boundary"]
    assert mismatching_access.calls == []


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


def test_oversized_runtime_provider_is_bounded_before_domain_materialization(tmp_path):
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
    assert components.unavailable_reason == "AWG3 runtime provider size exceeds limit"


def test_provider_and_hpk_reads_are_capped_to_limit_plus_one(tmp_path, monkeypatch):
    from app.services import phase15_bootstrap

    settings, paths = _settings(tmp_path)
    original_open = Path.open
    provider_read_sizes = []
    hpk_read_sizes = []

    def tracked_open(path, *args, **kwargs):
        handle = original_open(path, *args, **kwargs)
        if path == paths["runtime"]:
            return _ReadSizeSpy(handle, provider_read_sizes)
        if path == paths["hpk"]:
            return _ReadSizeSpy(handle, hpk_read_sizes)
        return handle

    monkeypatch.setattr(Path, "open", tracked_open)

    phase15_bootstrap._read_json_object(str(paths["runtime"]), "runtime provider")
    material = load_phase15_awg3_issuer_material(settings)
    assert material.secret_resolver.resolve(
        material.header_protection_key.reference
    ) == "strict-phase16-header-protection-key"

    assert provider_read_sizes == [phase15_bootstrap._MAX_PROVIDER_BYTES + 1]
    assert hpk_read_sizes == [4097]


def test_json_nesting_walk_is_iterative_and_stops_at_bound():
    from app.services import phase15_bootstrap

    nested = 0
    for _ in range(1500):
        nested = {"next": nested}

    assert phase15_bootstrap._json_nesting(nested) == 9


def test_extreme_provider_nesting_disables_awg3_while_awg2_remains_buildable(tmp_path):
    settings, paths = _settings(tmp_path)
    _conn, repo = _accepted_repo(tmp_path)
    paths["runtime"].write_text(
        '{"provider_identity":"phase15-runtime-provider-001","runtimes":'
        + "[" * 1500
        + "0"
        + "]" * 1500
        + "}",
        encoding="utf-8",
    )
    peer = RecordingPeerApplier()
    access = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret(
            "phase15-deep-provider-secret-with-more-than-32-chars"
        ),
        peer_applier=peer,
    )

    components = build_phase15_awg3_components(settings, repo, access, peer)

    assert components.available is False
    assert components.awg3_client_choices == ()
    owner_user_id = repo.create_operator_recipient(operator_label="AWG2 remains")
    result = access.create_operator_device(
        owner_user_id=owner_user_id,
        server_id=int(repo.get_server_by_name("local")["id"]),
        device_name="AWG2 laptop",
        duration_days=30,
        admin_telegram_id=9001,
        config_version="amneziawg_v2",
        device_context=OperatorDeviceContext(
            platform="windows",
            official_client_type="amnezia_vpn",
            client_version="5.0.0.5",
            protocol_version="awg2",
            runtime_instance_id="legacy-awg2-runtime",
            client_identity_evidence_status="verified",
            compatibility_evidence_id="legacy-awg2-evidence",
        ),
    )
    assert result.passport_device_id is not None
    assert len(peer.calls) == 1
