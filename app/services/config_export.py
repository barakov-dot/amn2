from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from app.services.config_delivery import DeviceConfigDelivery


ConfigExportStatus = Literal[
    "success",
    "unsupported_artifact",
    "unsupported_target_client",
    "runtime_config_path_missing",
    "export_failed",
]
RuntimeConfigPathStatus = Literal["not_required", "provided", "missing"]
ConfigExportArtifactKind = Literal[
    "wireguard_conf",
    "qr_payload",
    "qr_png",
    "amnezia_import_uri",
    "delivery_message",
]

CLIENT_CONFIG_SECRET = "client-config-secret"
SUPPORTED_TARGET_CLIENTS = frozenset({"amnezia_generic"})
SUPPORTED_ARTIFACTS = frozenset(
    {
        "wireguard_conf",
        "qr_payload",
        "qr_png",
        "amnezia_import_uri",
        "delivery_message",
    }
)
DEFAULT_ARTIFACTS: tuple[str, ...] = (
    "wireguard_conf",
    "qr_payload",
    "qr_png",
    "amnezia_import_uri",
    "delivery_message",
)


@dataclass(frozen=True)
class ConfigExportRequest:
    actor_type: str
    actor_id: str
    device_id: int
    user_id: int
    server_id: int
    protocol_id: str
    config_version: str
    target_client: str = "amnezia_generic"
    requested_artifacts: tuple[str, ...] = DEFAULT_ARTIFACTS
    delivery_channel: str = "internal"
    require_runtime_config_path: bool = False
    runtime_config_path: str | None = None


@dataclass(frozen=True)
class ConfigExportWarning:
    code: str


@dataclass(frozen=True)
class ConfigExportArtifact:
    kind: str
    target_client: str
    payload: bytes | str
    filename: str | None = None
    media_type: str = "application/octet-stream"
    content_encoding: str = "binary"
    secret_class: str = CLIENT_CONFIG_SECRET
    metadata: dict[str, object] = field(default_factory=dict)

    def safe_metadata(self) -> dict[str, object]:
        safe = {
            "kind": self.kind,
            "target_client": self.target_client,
            "filename": self.filename,
            "media_type": self.media_type,
            "content_encoding": self.content_encoding,
            "secret_class": self.secret_class,
            "payload_size": _payload_size(self.payload),
        }
        safe.update(self.metadata)
        return safe


@dataclass(frozen=True)
class ConfigExportResult:
    status: ConfigExportStatus
    protocol_id: str
    device_id: int
    user_id: int
    server_id: int
    config_version: str
    target_client: str
    secret_class: str = CLIENT_CONFIG_SECRET
    runtime_config_path_status: RuntimeConfigPathStatus = "not_required"
    artifacts: tuple[ConfigExportArtifact, ...] = ()
    warnings: tuple[ConfigExportWarning, ...] = ()

    def safe_metadata(self) -> dict[str, object]:
        return {
            "status": self.status,
            "protocol_id": self.protocol_id,
            "config_version": self.config_version,
            "target_client": self.target_client,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "server_id": self.server_id,
            "secret_class": self.secret_class,
            "runtime_config_path_status": self.runtime_config_path_status,
            "artifact_kinds": [artifact.kind for artifact in self.artifacts],
            "warnings": [warning.code for warning in self.warnings],
        }


class ConfigExporter(Protocol):
    def export_config(self, request: ConfigExportRequest) -> ConfigExportResult: ...


def export_device_config_delivery(
    delivery: DeviceConfigDelivery,
    request: ConfigExportRequest,
) -> ConfigExportResult:
    if request.target_client not in SUPPORTED_TARGET_CLIENTS:
        return _blocked_result(request, status="unsupported_target_client")

    if request.require_runtime_config_path and not request.runtime_config_path:
        return _blocked_result(request, status="runtime_config_path_missing")

    requested = tuple(request.requested_artifacts or DEFAULT_ARTIFACTS)
    if any(artifact not in SUPPORTED_ARTIFACTS for artifact in requested):
        return _blocked_result(request, status="unsupported_artifact")

    artifacts = _artifacts_from_delivery(delivery, request)
    artifacts_by_kind = {artifact.kind: artifact for artifact in artifacts}
    return ConfigExportResult(
        status="success",
        protocol_id=request.protocol_id,
        device_id=request.device_id,
        user_id=request.user_id,
        server_id=request.server_id,
        config_version=request.config_version,
        target_client=request.target_client,
        runtime_config_path_status=_runtime_config_path_status(request),
        artifacts=tuple(artifacts_by_kind[kind] for kind in requested),
    )


def run_config_exporter(
    exporter: ConfigExporter,
    request: ConfigExportRequest,
) -> ConfigExportResult:
    try:
        return exporter.export_config(request)
    except Exception:
        return _blocked_result(request, status="export_failed")


def _artifacts_from_delivery(
    delivery: DeviceConfigDelivery,
    request: ConfigExportRequest,
) -> tuple[ConfigExportArtifact, ...]:
    package = delivery.delivery
    target = request.target_client
    return (
        ConfigExportArtifact(
            kind="wireguard_conf",
            target_client=target,
            payload=package.config_bytes,
            filename=package.config_filename,
            media_type="text/plain",
            content_encoding=package.config_content_encoding,
            secret_class=package.config_secret_class,
        ),
        ConfigExportArtifact(
            kind="qr_payload",
            target_client=target,
            payload=package.qr_payload_text,
            media_type="text/plain",
            content_encoding="utf-8",
            metadata={"qr_payload_kind": "wireguard_conf"},
        ),
        ConfigExportArtifact(
            kind="qr_png",
            target_client=target,
            payload=package.qr_png_bytes,
            filename=package.qr_filename,
            media_type="image/png",
            content_encoding="binary",
            metadata={"qr_payload_kind": "wireguard_conf"},
        ),
        ConfigExportArtifact(
            kind="amnezia_import_uri",
            target_client=target,
            payload=package.vpn_import_link,
            media_type="text/uri-list",
            content_encoding=package.vpn_import_link_encoding,
            metadata={"uri_scheme": "vpn", "uri_payload_kind": "wireguard_conf"},
        ),
        ConfigExportArtifact(
            kind="delivery_message",
            target_client=target,
            payload=package.message_text,
            media_type="text/plain",
            content_encoding="utf-8",
        ),
    )


def _blocked_result(
    request: ConfigExportRequest,
    *,
    status: ConfigExportStatus,
) -> ConfigExportResult:
    return ConfigExportResult(
        status=status,
        protocol_id=request.protocol_id,
        device_id=request.device_id,
        user_id=request.user_id,
        server_id=request.server_id,
        config_version=request.config_version,
        target_client="unsupported" if status == "unsupported_target_client" else request.target_client,
        runtime_config_path_status=_runtime_config_path_status(request, missing_status=status),
        warnings=(ConfigExportWarning(status),),
    )


def _runtime_config_path_status(
    request: ConfigExportRequest,
    *,
    missing_status: ConfigExportStatus | None = None,
) -> RuntimeConfigPathStatus:
    if missing_status == "runtime_config_path_missing":
        return "missing"
    if request.runtime_config_path:
        return "provided"
    return "not_required"


def _payload_size(payload: bytes | str) -> int:
    if isinstance(payload, bytes):
        return len(payload)
    return len(payload.encode("utf-8"))
