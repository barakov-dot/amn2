from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from app.config.settings import Settings
from app.db.repositories import Repository
from app.security.crypto import SecretBox
from app.services.access import AccessService, Awg3IssuerMaterial, OperatorDeviceContext
from app.services.admin_config_issuance import AdminConfigIssuanceService
from app.services.awg3_control import Awg3ControlService, Awg3ControlState
from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
)
from app.services.config_delivery import build_device_config_delivery
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.protocol_admission import (
    AdmissionRequest,
    AdmissionResult,
    ProtocolAdmissionService,
)
from app.services.self_service_issuance import (
    ConfigIssuer,
    SelfServiceIssuanceRequest,
    SelfServiceIssuanceService,
)
from app.services.telegram_callback_state import TelegramCallbackStateService
from app.services.vpn_runtime_instances import RuntimeInstanceSpec, runtime_spec_from_row
from app.vpn.amneziawg_v3.config import HeaderProtectionSecretRef
from app.vpn.protocol_versions import ProtocolVersion, config_version_for_protocol


class Phase15BootstrapUnavailable(RuntimeError):
    pass


class AdminHealthEvent(StrEnum):
    SERVER_UNREACHABLE = "server_unreachable"
    AWG2_DEGRADED = "awg2_degraded"
    AWG3_DEGRADED = "awg3_degraded"


class AdminHealthEventSink(Protocol):
    def record(
        self,
        event: AdminHealthEvent,
        *,
        safe_metadata: Mapping[str, str],
    ) -> None: ...


@dataclass(frozen=True)
class _HpkFileResolver:
    path: Path
    reference: str
    fingerprint: str

    def resolve(self, reference: str) -> str:
        if reference != self.reference:
            raise ValueError("header_protection_key reference mismatch")
        try:
            raw = self.path.read_bytes()
        except OSError:
            raise ValueError("header_protection_key file is unavailable") from None
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if actual != self.fingerprint:
            raise ValueError("header_protection_key fingerprint mismatch")
        try:
            secret = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("header_protection_key is not UTF-8") from None
        if (
            not secret
            or secret != secret.strip()
            or len(secret) > 4096
            or any(ord(character) < 32 for character in secret)
        ):
            raise ValueError("header_protection_key content is invalid")
        return secret


_MATERIAL_FIELDS = frozenset(
    {
        "provider_identity",
        "s1",
        "s2",
        "s3",
        "s4",
        "content_padding_addition",
        "rekey_after_time",
        "rekey_timeout",
        "reject_after_time",
        "keepalive_timeout",
        "max_handshake_attempts",
        "header_protection_key_ref",
        "header_protection_key_fingerprint",
    }
)


def load_phase15_awg3_issuer_material(settings: Settings) -> Awg3IssuerMaterial:
    payload = _read_json_object(
        settings.awg3_issuer_material_provider_path,
        "AWG3 issuer material provider",
    )
    try:
        _require_exact_fields(payload, _MATERIAL_FIELDS, "AWG3 issuer material")
        identity = _exact_text(payload["provider_identity"], "provider_identity")
        reference = _exact_text(
            payload["header_protection_key_ref"],
            "header_protection_key reference",
        )
        if identity != settings.awg3_issuer_material_provider_identity:
            raise ValueError("provider identity mismatch")
        if reference != settings.awg3_hpk_secret_reference:
            raise Phase15BootstrapUnavailable(
                "header_protection_key reference mismatch"
            )
        secret_ref = HeaderProtectionSecretRef(
            reference=reference,
            fingerprint=payload["header_protection_key_fingerprint"],
        )
        resolver = _HpkFileResolver(
            path=Path(settings.awg3_hpk_secret_path),
            reference=reference,
            fingerprint=secret_ref.fingerprint,
        )
        return Awg3IssuerMaterial(
            provider_identity=identity,
            s1=payload["s1"],
            s2=payload["s2"],
            s3=payload["s3"],
            s4=payload["s4"],
            content_padding_addition=payload["content_padding_addition"],
            rekey_after_time=payload["rekey_after_time"],
            rekey_timeout=payload["rekey_timeout"],
            reject_after_time=payload["reject_after_time"],
            keepalive_timeout=payload["keepalive_timeout"],
            max_handshake_attempts=payload["max_handshake_attempts"],
            header_protection_key=secret_ref,
            secret_resolver=resolver,
        )
    except (KeyError, TypeError, ValueError):
        raise Phase15BootstrapUnavailable(
            "AWG3 issuer material is invalid"
        ) from None


@dataclass(frozen=True)
class _BootstrapSnapshot:
    admission_service: ProtocolAdmissionService
    control_state: Awg3ControlState
    client: ClientIdentity
    material: Awg3IssuerMaterial


class ProductionAwg3ConfigIssuer(ConfigIssuer):
    def __init__(
        self,
        *,
        settings: Settings,
        repo: Repository,
        access_service: AccessService | None,
        peer_applier: object | None,
        snapshot_loader: Callable[[], _BootstrapSnapshot],
    ) -> None:
        self._settings = settings
        self._repo = repo
        self._access_service = access_service
        self._peer_applier = peer_applier
        self._snapshot_loader = snapshot_loader

    def issue(
        self,
        *,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
    ) -> object:
        snapshot = self._snapshot_loader()
        fresh = snapshot.admission_service.decide(
            AdmissionRequest(
                client=request.client,
                protocol_version=request.protocol_version,
            )
        )
        if (
            request.protocol_version is not ProtocolVersion.AWG3
            or not fresh.admitted
            or fresh != admission
            or not snapshot.control_state.permits_new_issuance
            or request.client != snapshot.client
        ):
            raise Phase15BootstrapUnavailable("AWG3 issuance gates changed")
        if (
            self._access_service is None
            or self._peer_applier is None
            or getattr(self._access_service, "_peer_applier", None)
            is not self._peer_applier
        ):
            raise Phase15BootstrapUnavailable("AWG3 issuer boundary is unavailable")
        try:
            server = self._repo.get_server_by_name(self._settings.server_name)
        except LookupError:
            raise Phase15BootstrapUnavailable("AWG3 server is unavailable") from None
        return self._access_service.create_protocol_device_for_existing_passport(
            owner_user_id=request.user_id,
            passport_device_id=request.passport_device_id,
            server_id=int(server["id"]),
            device_name=(
                f"{request.client.application}-{request.client.platform}-AWG3"
            ),
            config_version=config_version_for_protocol(ProtocolVersion.AWG3),
            client_build=str(request.client.build_id),
            device_context=OperatorDeviceContext(
                platform=request.client.platform,
                official_client_type=request.client.application,
                client_version=request.client.version,
                protocol_version="awg3",
                runtime_instance_id=fresh.runtime_instance_id,
                client_identity_evidence_status="verified",
                compatibility_evidence_id=fresh.compatibility_evidence_id,
            ),
            awg3_material=snapshot.material,
        )


@dataclass(frozen=True)
class Phase15Awg3Components:
    available: bool
    unavailable_reason: str | None
    callback_state: TelegramCallbackStateService
    control_service: Awg3ControlService
    protocol_admission_service: ProtocolAdmissionService | None
    admission_provider: Callable[
        [AdmissionRequest], tuple[AdmissionResult | None, Awg3ControlState | None]
    ]
    issuer: ProductionAwg3ConfigIssuer
    self_service_issuance_service: SelfServiceIssuanceService
    admin_config_issuance_factory: Callable[..., AdminConfigIssuanceService]
    awg3_client_choices: tuple[ClientIdentity, ...]
    delivery_builder: Callable[[int], object]
    health_event_sink: AdminHealthEventSink | None = None


def build_phase15_awg3_components(
    settings: Settings,
    repo: Repository,
    access_service: AccessService | None,
    peer_applier: object | None,
) -> Phase15Awg3Components:
    now = datetime.now(timezone.utc)
    callback_state = TelegramCallbackStateService(repo=repo)
    control_service = Awg3ControlService(repo, now=now)

    def snapshot_loader() -> _BootstrapSnapshot:
        if not settings.awg3_bootstrap_enabled:
            raise Phase15BootstrapUnavailable("AWG3 bootstrap is disabled")
        if (
            access_service is None
            or peer_applier is None
            or getattr(access_service, "_peer_applier", None) is not peer_applier
        ):
            raise Phase15BootstrapUnavailable("AWG3 issuer boundary is unavailable")
        return _load_snapshot(settings, repo)

    issuer = ProductionAwg3ConfigIssuer(
        settings=settings,
        repo=repo,
        access_service=access_service,
        peer_applier=peer_applier,
        snapshot_loader=snapshot_loader,
    )
    initial: _BootstrapSnapshot | None = None
    reason: str | None = None
    if settings.awg3_bootstrap_enabled:
        try:
            initial = snapshot_loader()
        except Phase15BootstrapUnavailable as exc:
            reason = str(exc)
    else:
        reason = "AWG3 bootstrap is disabled"

    def admission_provider(
        request: AdmissionRequest,
    ) -> tuple[AdmissionResult | None, Awg3ControlState | None]:
        try:
            snapshot = snapshot_loader()
        except Phase15BootstrapUnavailable:
            return None, None
        return snapshot.admission_service.decide(request), snapshot.control_state

    profile_service = DualProtocolProfileService(repo)
    self_service = SelfServiceIssuanceService(
        repo=repo,
        admission_provider=admission_provider,
        profile_service=profile_service,
        issuer=issuer,
        callback_state=callback_state,
    )

    def admin_factory(*, admin_telegram_id: int, attachment_builder):
        if admin_telegram_id not in set(settings.admin_ids):
            raise Phase15BootstrapUnavailable("configured admin is required")
        snapshot = snapshot_loader()
        return AdminConfigIssuanceService(
            repo=repo,
            access_service=access_service,
            admission_service=snapshot.admission_service,
            admin_telegram_id=admin_telegram_id,
            attachment_builder=attachment_builder,
            max_devices_per_recipient=settings.max_devices_per_user,
        )

    secret_box = SecretBox.from_app_secret(settings.app_secret_key)

    def delivery_builder(device_id: int):
        return build_device_config_delivery(
            repo=repo,
            secret_box=secret_box,
            device=repo.get_device(device_id),
            client_config_template_dir=settings.client_config_template_dir,
            client_config_defaults=settings.client_config_defaults,
        ).delivery

    return Phase15Awg3Components(
        available=initial is not None,
        unavailable_reason=reason,
        callback_state=callback_state,
        control_service=control_service,
        protocol_admission_service=(
            initial.admission_service if initial is not None else None
        ),
        admission_provider=admission_provider,
        issuer=issuer,
        self_service_issuance_service=self_service,
        admin_config_issuance_factory=admin_factory,
        awg3_client_choices=(initial.client,) if initial is not None else (),
        delivery_builder=delivery_builder,
    )


def _load_snapshot(settings: Settings, repo: Repository) -> _BootstrapSnapshot:
    try:
        runtime_payload = _read_json_object(
            settings.awg3_runtime_provider_path,
            "AWG3 runtime provider",
        )
        _require_exact_fields(
            runtime_payload,
            frozenset({"provider_identity", "runtimes"}),
            "AWG3 runtime provider",
        )
        if runtime_payload["provider_identity"] != settings.awg3_runtime_provider_identity:
            raise ValueError("runtime provider identity mismatch")
        runtime_rows = runtime_payload["runtimes"]
        if not isinstance(runtime_rows, list) or not runtime_rows:
            raise ValueError("runtimes")
        runtimes = tuple(runtime_spec_from_row(_mapping(row, "runtime")) for row in runtime_rows)
        runtime = next(
            item
            for item in runtimes
            if item.runtime_instance_id == settings.awg3_expected_runtime_instance_id
            and item.protocol_version is ProtocolVersion.AWG3
        )

        evidence_payload = _read_json_object(
            settings.awg3_evidence_provider_path,
            "AWG3 evidence provider",
        )
        _require_exact_fields(
            evidence_payload,
            frozenset({"provider_identity", "evidence"}),
            "AWG3 evidence provider",
        )
        if evidence_payload["provider_identity"] != settings.awg3_evidence_provider_identity:
            raise ValueError("evidence provider identity mismatch")
        evidence_rows = evidence_payload["evidence"]
        if not isinstance(evidence_rows, list) or not evidence_rows:
            raise ValueError("evidence")
        evidence = tuple(_evidence_from_json(_mapping(row, "evidence")) for row in evidence_rows)

        build_payload = _read_json_object(
            settings.awg3_exact_build_provider_path,
            "AWG3 exact build provider",
        )
        _require_exact_fields(
            build_payload,
            frozenset({"provider_identity", "package_id", "source_head", "client"}),
            "AWG3 exact build provider",
        )
        if build_payload["provider_identity"] != settings.awg3_exact_build_provider_identity:
            raise ValueError("build provider identity mismatch")
        if build_payload["package_id"] != settings.awg3_expected_package_id:
            raise ValueError("package identity mismatch")
        if build_payload["source_head"] != settings.awg3_expected_source_head:
            raise ValueError("source identity mismatch")
        client = _client_from_json(_mapping(build_payload["client"], "client"))
        if client.build_id is None:
            raise ValueError("exact build")

        state = _control_state(repo)
        accepted = repo.get_client_build_acceptance(
            application=client.application,
            platform=client.platform,
            client_version=client.version,
            client_build=client.build_id,
        )
        if accepted is None or str(accepted["state"]) != "accepted":
            raise ValueError("exact build acceptance")
        if state.runtime_receipt != runtime.acceptance_receipt:
            raise ValueError("runtime acceptance receipt mismatch")
        material = load_phase15_awg3_issuer_material(settings)
        admission = ProtocolAdmissionService(
            evidence=evidence,
            runtimes=runtimes,
            now=datetime.now(timezone.utc),
            awg3_control_state=state,
            accepted_awg3_builds=frozenset({client}),
        )
        return _BootstrapSnapshot(admission, state, client, material)
    except (KeyError, StopIteration, TypeError, ValueError, OSError, json.JSONDecodeError):
        raise Phase15BootstrapUnavailable("AWG3 bootstrap providers are invalid") from None


def _control_state(repo: Repository) -> Awg3ControlState:
    row = repo.get_awg3_control_state()
    return Awg3ControlState(
        runtime_accepted=bool(row["runtime_accepted"]),
        global_accepted=bool(row["global_accepted"]),
        issuance_enabled=bool(row["issuance_enabled"]),
        emergency_suspended=bool(row["emergency_suspended"]),
        runtime_receipt=row["runtime_receipt"],
    )


def _evidence_from_json(row: Mapping[str, object]) -> ClientCompatibilityEvidence:
    _require_exact_fields(
        row,
        frozenset(
            {
                "evidence_id",
                "client",
                "protocol_version",
                "source_kind",
                "status",
                "observed_at",
                "safe_reference",
                "scope",
                "release_kind",
            }
        ),
        "compatibility evidence",
    )
    return ClientCompatibilityEvidence(
        evidence_id=row["evidence_id"],
        client=_client_from_json(_mapping(row["client"], "client")),
        protocol_version=ProtocolVersion(row["protocol_version"]),
        source_kind=row["source_kind"],
        status=CompatibilityEvidenceStatus(row["status"]),
        observed_at=datetime.fromisoformat(row["observed_at"]),
        safe_reference=row["safe_reference"],
        scope=row["scope"],
        release_kind=SourceReleaseKind(row["release_kind"]),
    )


def _client_from_json(row: Mapping[str, object]) -> ClientIdentity:
    _require_exact_fields(
        row,
        frozenset({"application", "platform", "version", "build_id"}),
        "client identity",
    )
    return ClientIdentity(
        row["application"],
        row["platform"],
        row["version"],
        row["build_id"],
    )


def _read_json_object(path: str, label: str) -> Mapping[str, object]:
    if not path:
        raise Phase15BootstrapUnavailable(f"{label} path is missing")
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise Phase15BootstrapUnavailable(f"{label} is unavailable") from None
    if not isinstance(payload, dict):
        raise Phase15BootstrapUnavailable(f"{label} must be an object")
    return payload


def _require_exact_fields(
    payload: Mapping[str, object], expected: frozenset[str], label: str
) -> None:
    if set(payload) != expected:
        raise ValueError(f"{label} fields are invalid")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(label)
    return value


def _exact_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(label)
    return value
