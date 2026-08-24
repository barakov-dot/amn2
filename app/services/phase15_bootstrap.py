from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from app.config.settings import Settings
from app.db.repositories import Repository
from app.security.crypto import SecretBox
from app.services.access import (
    AccessService,
    Awg3HeaderProtectionKeyUnavailable,
    Awg3IssuerMaterial,
    OperatorDeviceContext,
)
from app.services.admin_config_issuance import AdminConfigIssuanceService
from app.services.awg3_control import Awg3ControlService, Awg3ControlState
from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
    current_awg3_compatibility_evidence,
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
    IssuerUnavailableBeforeSideEffect,
    SelfServiceIssuanceRequest,
    SelfServiceIssuanceService,
)
from app.services.telegram_callback_state import TelegramCallbackStateService
from app.services.vpn_runtime_instances import RuntimeInstanceSpec, runtime_spec_from_row
from app.vpn.amneziawg_v3.config import HeaderProtectionSecretRef
from app.vpn.protocol_versions import ProtocolVersion, config_version_for_protocol


_PHASE15_PACKAGE_ID = "phase15-dual-protocol-bootstrap-20260811-001"
_CANONICAL_GIT_SOURCE_HEAD = re.compile(r"[0-9a-f]{40}\Z")
_MAX_PROVIDER_BYTES = 65_536
_MAX_HPK_BYTES = 4_096
_MAX_PROVIDER_ROWS = 100
_MAX_PROVIDER_NESTING = 8
_RUNTIME_FIELDS = frozenset(
    {
        "runtime_instance_id",
        "server_id",
        "protocol_version",
        "runtime_version",
        "interface_name",
        "udp_port",
        "vpn_cidr",
        "container_name",
        "service_name",
        "config_path",
        "lifecycle_state",
        "acceptance_receipt",
    }
)


class Phase15BootstrapUnavailable(RuntimeError):
    pass


class _Phase15IssuerUnavailableBeforeSideEffect(
    Phase15BootstrapUnavailable,
    IssuerUnavailableBeforeSideEffect,
):
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
            with self.path.open("rb") as secret_file:
                raw = secret_file.read(_MAX_HPK_BYTES + 1)
        except OSError:
            raise ValueError("header_protection_key file is unavailable") from None
        if len(raw) > _MAX_HPK_BYTES:
            raise ValueError("header_protection_key file size exceeds limit")
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
        "runtime_instance_id",
        "endpoint_host",
        "server_public_key",
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
        if settings.awg3_expected_package_id != _PHASE15_PACKAGE_ID:
            raise ValueError("package identity")
        if _CANONICAL_GIT_SOURCE_HEAD.fullmatch(
            settings.awg3_expected_source_head
        ) is None:
            raise ValueError("source identity")
        _require_exact_fields(payload, _MATERIAL_FIELDS, "AWG3 issuer material")
        identity = _exact_text(payload["provider_identity"], "provider_identity")
        _require_content_identity(
            payload,
            kind="issuer_material",
            expected_identity=settings.awg3_issuer_material_provider_identity,
            package_id=settings.awg3_expected_package_id,
            source_head=settings.awg3_expected_source_head,
        )
        runtime_instance_id = _exact_text(
            payload["runtime_instance_id"],
            "runtime_instance_id",
        )
        endpoint_host = _exact_text(payload["endpoint_host"], "endpoint_host")
        server_public_key = _exact_text(
            payload["server_public_key"],
            "server_public_key",
        )
        reference = _exact_text(
            payload["header_protection_key_ref"],
            "header_protection_key reference",
        )
        if runtime_instance_id != settings.awg3_expected_runtime_instance_id:
            raise ValueError("runtime_instance_id mismatch")
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
            runtime_instance_id=runtime_instance_id,
            endpoint_host=endpoint_host,
            server_public_key=server_public_key,
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
    runtime: RuntimeInstanceSpec


@dataclass(frozen=True)
class _FreshAwg3Boundary:
    snapshot: _BootstrapSnapshot
    admission: AdmissionResult
    runtime_peer_applier: object


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

    def fresh_boundary(
        self,
        *,
        client: ClientIdentity | None = None,
        expected_admission: AdmissionResult | None = None,
    ) -> _FreshAwg3Boundary:
        snapshot = self._snapshot_loader()
        exact_client = snapshot.client if client is None else client
        fresh = snapshot.admission_service.decide(
            AdmissionRequest(
                client=exact_client,
                protocol_version=ProtocolVersion.AWG3,
            )
        )
        if (
            not fresh.admitted
            or (expected_admission is not None and fresh != expected_admission)
            or not snapshot.control_state.permits_new_issuance
            or exact_client != snapshot.client
        ):
            raise Phase15BootstrapUnavailable("AWG3 issuance gates changed")
        if (
            self._access_service is None
            or self._peer_applier is None
            or getattr(self._access_service, "_peer_applier", None)
            is not self._peer_applier
        ):
            raise Phase15BootstrapUnavailable("AWG3 issuer boundary is unavailable")
        targeter = getattr(self._peer_applier, "for_runtime", None)
        if not callable(targeter):
            raise Phase15BootstrapUnavailable(
                "AWG3 runtime-targeted peer boundary is unavailable"
            )
        try:
            runtime_peer_applier = targeter(snapshot.runtime)
        except Exception:
            raise Phase15BootstrapUnavailable(
                "AWG3 runtime-targeted peer boundary is unavailable"
            ) from None
        return _FreshAwg3Boundary(snapshot, fresh, runtime_peer_applier)

    def issue(
        self,
        *,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
    ) -> object:
        try:
            if request.protocol_version is not ProtocolVersion.AWG3:
                raise Phase15BootstrapUnavailable("AWG3 issuance gates changed")
            boundary = self.fresh_boundary(
                client=request.client,
                expected_admission=admission,
            )
            server = self._repo.get_server_by_name(self._settings.server_name)
        except (LookupError, Phase15BootstrapUnavailable):
            raise _Phase15IssuerUnavailableBeforeSideEffect(
                "AWG3 issuer is unavailable before side effects"
            ) from None
        try:
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
                    runtime_instance_id=boundary.admission.runtime_instance_id,
                    client_identity_evidence_status="verified",
                    compatibility_evidence_id=(
                        boundary.admission.compatibility_evidence_id
                    ),
                ),
                awg3_material=boundary.snapshot.material,
                runtime_target=boundary.snapshot.runtime,
                runtime_peer_applier=boundary.runtime_peer_applier,
            )
        except Awg3HeaderProtectionKeyUnavailable:
            raise _Phase15IssuerUnavailableBeforeSideEffect(
                "AWG3 issuer is unavailable before side effects"
            ) from None


class _FreshAwg3AdminAccessAdapter:
    def __init__(
        self,
        *,
        access_service: AccessService,
        issuer: ProductionAwg3ConfigIssuer,
    ) -> None:
        self._access_service = access_service
        self._issuer = issuer

    def create_operator_device(self, **kwargs):
        if kwargs.get("config_version") != config_version_for_protocol(
            ProtocolVersion.AWG3
        ):
            return self._access_service.create_operator_device(**kwargs)
        context = kwargs.get("device_context")
        if (
            not isinstance(context, OperatorDeviceContext)
            or context.protocol_version != ProtocolVersion.AWG3.value
        ):
            raise Phase15BootstrapUnavailable("AWG3 admin client context is invalid")
        boundary = self._issuer.fresh_boundary()
        client = boundary.snapshot.client
        if (
            context.official_client_type != client.application
            or context.platform != client.platform
            or context.client_version != client.version
            or context.runtime_instance_id != boundary.admission.runtime_instance_id
            or context.compatibility_evidence_id
            != boundary.admission.compatibility_evidence_id
            or context.client_identity_evidence_status != "verified"
        ):
            raise Phase15BootstrapUnavailable("AWG3 admin issuance gates changed")
        return self._access_service.create_operator_device(
            **kwargs,
            client_build=client.build_id,
            awg3_material=boundary.snapshot.material,
            runtime_target=boundary.snapshot.runtime,
            runtime_peer_applier=boundary.runtime_peer_applier,
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
        if access_service is None:
            raise Phase15BootstrapUnavailable("AWG3 issuer boundary is unavailable")
        return AdminConfigIssuanceService(
            repo=repo,
            access_service=_FreshAwg3AdminAccessAdapter(
                access_service=access_service,
                issuer=issuer,
            ),
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
        if settings.awg3_expected_package_id != _PHASE15_PACKAGE_ID:
            raise ValueError("package identity")
        if _CANONICAL_GIT_SOURCE_HEAD.fullmatch(
            settings.awg3_expected_source_head
        ) is None:
            raise ValueError("source identity")
        runtime_payload = _read_json_object(
            settings.awg3_runtime_provider_path,
            "AWG3 runtime provider",
        )
        _require_exact_fields(
            runtime_payload,
            frozenset({"provider_identity", "runtimes"}),
            "AWG3 runtime provider",
        )
        _require_content_identity(
            runtime_payload,
            kind="runtime_provider",
            expected_identity=settings.awg3_runtime_provider_identity,
            package_id=settings.awg3_expected_package_id,
            source_head=settings.awg3_expected_source_head,
        )
        runtime_rows = runtime_payload["runtimes"]
        if (
            not isinstance(runtime_rows, list)
            or not 1 <= len(runtime_rows) <= _MAX_PROVIDER_ROWS
        ):
            raise ValueError("runtimes")
        runtime_mappings = tuple(_mapping(row, "runtime") for row in runtime_rows)
        for row in runtime_mappings:
            _require_exact_fields(row, _RUNTIME_FIELDS, "runtime")
        runtimes = tuple(runtime_spec_from_row(row) for row in runtime_mappings)
        awg3_candidates = tuple(
            item for item in runtimes if item.protocol_version is ProtocolVersion.AWG3
        )
        if (
            len(awg3_candidates) != 1
            or awg3_candidates[0].runtime_instance_id
            != settings.awg3_expected_runtime_instance_id
        ):
            raise ValueError("exact AWG3 runtime candidate")
        runtime = awg3_candidates[0]
        selected_runtime_row = next(
            row
            for row in runtime_mappings
            if row["runtime_instance_id"] == runtime.runtime_instance_id
            and row["protocol_version"] == "awg3"
        )
        runtime_receipt = _exact_text(
            selected_runtime_row["acceptance_receipt"],
            "runtime acceptance receipt",
        )
        if runtime_receipt != _content_identity(
            "runtime_acceptance",
            _without_field(selected_runtime_row, "acceptance_receipt"),
            package_id=settings.awg3_expected_package_id,
            source_head=settings.awg3_expected_source_head,
        ):
            raise ValueError("runtime acceptance receipt mismatch")
        physical_server = repo.get_server_by_name(settings.server_name)
        if runtime.server_id != int(physical_server["id"]):
            raise ValueError("runtime physical server mismatch")

        evidence_payload = _read_json_object(
            settings.awg3_evidence_provider_path,
            "AWG3 evidence provider",
        )
        _require_exact_fields(
            evidence_payload,
            frozenset({"provider_identity", "evidence"}),
            "AWG3 evidence provider",
        )
        _require_content_identity(
            evidence_payload,
            kind="evidence_provider",
            expected_identity=settings.awg3_evidence_provider_identity,
            package_id=settings.awg3_expected_package_id,
            source_head=settings.awg3_expected_source_head,
        )
        evidence_rows = evidence_payload["evidence"]
        if (
            not isinstance(evidence_rows, list)
            or not 1 <= len(evidence_rows) <= _MAX_PROVIDER_ROWS
        ):
            raise ValueError("evidence")
        evidence_mappings = tuple(_mapping(row, "evidence") for row in evidence_rows)
        for row in evidence_mappings:
            evidence_id = _exact_text(row.get("evidence_id"), "evidence_id")
            if evidence_id != _content_identity(
                "compatibility_evidence",
                _without_field(row, "evidence_id"),
                package_id=settings.awg3_expected_package_id,
                source_head=settings.awg3_expected_source_head,
            ):
                raise ValueError("compatibility evidence identity mismatch")
        evidence = tuple(_evidence_from_json(row) for row in evidence_mappings)

        build_payload = _read_json_object(
            settings.awg3_exact_build_provider_path,
            "AWG3 exact build provider",
        )
        _require_exact_fields(
            build_payload,
            frozenset({"provider_identity", "package_id", "source_head", "client"}),
            "AWG3 exact build provider",
        )
        _require_content_identity(
            build_payload,
            kind="build_provider",
            expected_identity=settings.awg3_exact_build_provider_identity,
            package_id=settings.awg3_expected_package_id,
            source_head=settings.awg3_expected_source_head,
        )
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
        accepted_evidence_ids = _accepted_evidence_ids(
            accepted["evidence_ids_json"]
        )
        current_evidence_ids = tuple(
            item.evidence_id
            for item in current_awg3_compatibility_evidence(
                evidence,
                client=client,
            )
        )
        if accepted_evidence_ids != current_evidence_ids:
            raise ValueError("exact build evidence acceptance mismatch")
        if state.runtime_receipt != runtime.acceptance_receipt:
            raise ValueError("runtime acceptance receipt mismatch")
        material = load_phase15_awg3_issuer_material(settings)
        admission = ProtocolAdmissionService(
            evidence=evidence,
            runtimes=(runtime,),
            now=datetime.now(timezone.utc),
            awg3_control_state=state,
            accepted_awg3_builds=frozenset({client}),
        )
        return _BootstrapSnapshot(admission, state, client, material, runtime)
    except (
        KeyError,
        LookupError,
        StopIteration,
        TypeError,
        ValueError,
        OSError,
        json.JSONDecodeError,
    ):
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


def _content_identity(
    kind: str,
    payload: object,
    *,
    package_id: str,
    source_head: str,
) -> str:
    canonical = json.dumps(
        {
            "kind": kind,
            "package_id": package_id,
            "source_head": source_head,
            "payload": payload,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _without_field(
    payload: Mapping[str, object], field: str
) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != field}


def _require_content_identity(
    payload: Mapping[str, object],
    *,
    kind: str,
    expected_identity: str,
    package_id: str,
    source_head: str,
) -> None:
    identity = _exact_text(payload.get("provider_identity"), "provider_identity")
    canonical_identity = _content_identity(
        kind,
        _without_field(payload, "provider_identity"),
        package_id=package_id,
        source_head=source_head,
    )
    if identity != canonical_identity or identity != expected_identity:
        raise ValueError("provider identity mismatch")


def _accepted_evidence_ids(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, str) or len(raw) > _MAX_PROVIDER_BYTES:
        raise ValueError("accepted evidence identities")
    values = json.loads(raw)
    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= _MAX_PROVIDER_ROWS
        or any(
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or any(ord(character) < 32 for character in value)
            for value in values
        )
        or len(set(values)) != len(values)
    ):
        raise ValueError("accepted evidence identities")
    return tuple(values)


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
    provider_path = Path(path)
    try:
        with provider_path.open("rb") as provider_file:
            raw = provider_file.read(_MAX_PROVIDER_BYTES + 1)
    except OSError:
        raise Phase15BootstrapUnavailable(f"{label} is unavailable") from None
    if len(raw) > _MAX_PROVIDER_BYTES:
        raise Phase15BootstrapUnavailable(f"{label} size exceeds limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Phase15BootstrapUnavailable(f"{label} is unavailable") from None
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        raise Phase15BootstrapUnavailable(f"{label} is unavailable") from None
    if _json_nesting(payload) > _MAX_PROVIDER_NESTING:
        raise Phase15BootstrapUnavailable(f"{label} nesting exceeds limit")
    if not isinstance(payload, dict):
        raise Phase15BootstrapUnavailable(f"{label} must be an object")
    return payload


def _json_nesting(value: object) -> int:
    deepest = 0
    pending = [(value, 0)]
    while pending:
        current, parent_depth = pending.pop()
        if isinstance(current, dict):
            children = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        depth = parent_depth + 1
        if depth > _MAX_PROVIDER_NESTING:
            return _MAX_PROVIDER_NESTING + 1
        deepest = max(deepest, depth)
        pending.extend((child, depth) for child in children)
    return deepest


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
