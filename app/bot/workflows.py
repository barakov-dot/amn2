from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from app.bot.delivery import (
    CONFIG_READY_TEMPLATE_KEY,
    DEFAULT_CONFIG_READY_TEMPLATE,
    ConfigDeliveryPackage,
    build_config_delivery,
)
from app.bot.ux import render_access_request_created, render_admin_approval, render_user_config_ready
from app.db.repositories import Repository
from app.security.crypto import SecretBox
from app.security.redaction import redact
from app.server.operations import remote_changed_local_failed_result
from app.server.peer_apply import PeerApplyError
from app.services.config_delivery import build_device_config_delivery
from app.services.admin_config_issuance import AdminConfigIssuanceService
from app.services.device_lifecycle import LifecycleEvidence, record_device_lifecycle_stage
from app.services.device_revoke import cascade_revoke_physical_device
from app.services.access import (
    AccessService,
    RemoteOperationPartialFailure,
)
from app.services.operator_credential_status import (
    OperatorCredentialStatusView,
    build_operator_credential_statuses,
)
from app.services.operator_server_status import (
    OperatorServerStatusView,
    build_operator_server_statuses,
)
from app.services.operator_status import OperatorStatusSummary, build_operator_status
from app.services.traffic import DeviceTrafficView, build_device_traffic_view
from app.vpn.amneziawg_v2.config import ClientConfigDefaults
from app.vpn.config_versions import validate_config_version


@dataclass(frozen=True)
class AccessRequestResult:
    order_id: int
    text: str


@dataclass(frozen=True)
class ApprovalResult:
    device_id: int
    user_telegram_id: int
    admin_text: str
    user_text: str
    config_text: str
    delivery: ConfigDeliveryPackage


@dataclass(frozen=True)
class ResendResult:
    device_id: int
    user_telegram_id: int
    config_text: str
    delivery: ConfigDeliveryPackage


@dataclass(frozen=True)
class AdminConfigHandoff:
    recipient_user_id: int
    device_id: int
    passport_device_id: str
    filename: str
    config_bytes: bytes


class PeerRemover:
    def remove_peer(self, *, server, peer_public_key: str) -> None:
        pass


class BotWorkflow:
    def __init__(
        self,
        *,
        repo: Repository,
        admin_telegram_ids: set[int],
        access_service: AccessService | None = None,
        default_server_id: int | None = None,
        secret_box: SecretBox | None = None,
        peer_remover: PeerRemover | None = None,
        client_config_template_dir: str | None = None,
        client_config_defaults: ClientConfigDefaults | None = None,
        device_name_prefix: str = "Neobyatnaya-AMNZ",
        device_name_sequence_seed: int = 4,
        vps_writes_enabled: bool = False,
        admin_config_issuance_factory=None,
    ) -> None:
        self._repo = repo
        self._admin_telegram_ids = admin_telegram_ids
        self._access_service = access_service
        self._default_server_id = default_server_id
        self._secret_box = secret_box
        self._peer_remover = peer_remover
        self._client_config_template_dir = client_config_template_dir
        self._client_config_defaults = client_config_defaults or ClientConfigDefaults()
        self._device_name_prefix = device_name_prefix.strip()
        self._device_name_sequence_seed = max(0, int(device_name_sequence_seed))
        self._vps_writes_enabled = bool(vps_writes_enabled)
        self._admin_config_issuance_factory = admin_config_issuance_factory
        self._admin_config_filenames: dict[int, str] = {}
        if not self._device_name_prefix:
            raise ValueError("device_name_prefix must be non-blank")

    def is_admin(self, telegram_id: int) -> bool:
        if telegram_id in self._admin_telegram_ids:
            return True
        user = self._repo.get_user_by_telegram_id(telegram_id)
        return bool(user is not None and int(user["is_admin"]) == 1)

    def issue_admin_config(
        self,
        *,
        admin_telegram_id: int,
        recipient_label: str,
        device_label: str,
        platform: str,
    ) -> AdminConfigHandoff | None:
        if not self.is_admin(admin_telegram_id):
            return None
        if self._default_server_id is None or (
            self._access_service is None
            and self._admin_config_issuance_factory is None
        ):
            raise RuntimeError("Admin config issuance workflow is not configured")

        captured_attachment: tuple[str, bytes] | None = None

        def capture_attachment(filename: str, config_text: str) -> None:
            nonlocal captured_attachment
            captured_attachment = (filename, config_text.encode("utf-8"))

        factory = self._admin_config_issuance_factory
        if factory is None:
            factory = lambda **kwargs: AdminConfigIssuanceService(
                repo=self._repo,
                access_service=self._access_service,
                duration_days=self._access_service._duration_days,
                **kwargs,
            )
        service = factory(
            admin_telegram_id=admin_telegram_id,
            attachment_builder=capture_attachment,
        )
        server = self._repo.get_server(self._default_server_id)
        issued = service.issue_manifest(
            {
                "request_id": f"telegram-{admin_telegram_id}-{uuid4().hex}",
                "server": str(server["name"]),
                "items": [
                    {
                        "recipient_label": recipient_label,
                        "device_label": device_label,
                        "platform": platform,
                    }
                ],
            }
        )
        if issued.status != "completed" or len(issued.receipts) != 1:
            raise RuntimeError("Admin config issuance did not complete")
        receipt = issued.receipts[0]
        if (
            receipt.recipient_user_id is None
            or receipt.device_id is None
            or receipt.passport_device_id is None
            or receipt.config_filename is None
            or captured_attachment is None
        ):
            raise RuntimeError("Admin config issuance returned incomplete handoff")
        captured_filename, config_bytes = captured_attachment
        if captured_filename != receipt.config_filename or not captured_filename.endswith(
            ".conf"
        ):
            raise RuntimeError("Admin config issuance returned invalid attachment")
        handoff = AdminConfigHandoff(
            recipient_user_id=int(receipt.recipient_user_id),
            device_id=int(receipt.device_id),
            passport_device_id=str(receipt.passport_device_id),
            filename=str(receipt.config_filename),
            config_bytes=config_bytes,
        )
        self._admin_config_filenames[handoff.device_id] = handoff.filename
        return handoff

    def record_admin_config_delivery(
        self,
        *,
        admin_telegram_id: int,
        passport_device_id: str,
        delivered: bool,
        reference: str,
    ) -> bool:
        if not self.is_admin(admin_telegram_id):
            return False
        now = datetime.now(timezone.utc)
        record_device_lifecycle_stage(
            self._repo,
            passport_device_id=passport_device_id,
            stage="delivered",
            status="completed" if delivered else "failed",
            started_at=now,
            occurred_at=now,
            evidence=LifecycleEvidence(
                source="telegram_admin_document",
                reference=reference,
            ),
        )
        return True

    def build_admin_config_handoff_for_device(
        self,
        *,
        admin_telegram_id: int,
        device_id: int,
    ) -> AdminConfigHandoff | None:
        if not self.is_admin(admin_telegram_id):
            return None
        if self._secret_box is None:
            raise RuntimeError("Config resend workflow is not configured")
        device = self._repo.get_device(device_id)
        passport = self._repo.get_device_passport_by_local_device_id(device_id)
        if passport is None:
            raise RuntimeError("device passport was not created")
        resend = self._build_delivery_for_device(device)
        return AdminConfigHandoff(
            recipient_user_id=int(device["user_id"]),
            device_id=device_id,
            passport_device_id=str(passport["device_id"]),
            filename=self._admin_config_filenames.get(
                device_id, resend.delivery.config_filename
            ),
            config_bytes=resend.delivery.config_bytes,
        )

    def register_user(
        self,
        *,
        telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
    ) -> int:
        return self._repo.upsert_user(
            telegram_id=telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )

    def set_user_locale(
        self,
        *,
        telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
        locale: str,
    ) -> bool:
        self.register_user(
            telegram_id=telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        return self._repo.set_user_locale(telegram_id=telegram_id, locale=locale)

    def get_user_locale(self, *, telegram_id: int) -> str:
        return self._repo.get_user_locale(telegram_id)

    def request_access(
        self,
        *,
        telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
        config_version: str,
        plan_id: str | None = None,
    ) -> AccessRequestResult:
        config_version = validate_config_version(config_version)
        plan = self._repo.get_plan(plan_id) if plan_id is not None else None
        user_id = self._repo.upsert_user(
            telegram_id=telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        order_id = self._repo.create_order(
            user_id=user_id,
            plan_id=plan_id,
            payment_mode="free_test",
            requested_config_version=config_version,
        )
        return AccessRequestResult(
            order_id=order_id,
            text=render_access_request_created(
                order_id=order_id,
                config_version=config_version,
                plan_name=str(plan["name"]) if plan is not None else None,
            ),
        )

    def create_manual_user(
        self,
        *,
        admin_telegram_id: int,
        target_telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
    ) -> int | None:
        if not self.is_admin(admin_telegram_id):
            return None
        user_id = self._repo.upsert_user(
            telegram_id=target_telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="create_manual_user",
            target_user_id=user_id,
            metadata={"target_telegram_id": target_telegram_id},
        )
        return user_id

    def create_manual_access_request(
        self,
        *,
        admin_telegram_id: int,
        target_telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
        config_version: str,
        plan_id: str | None,
    ) -> AccessRequestResult | None:
        if not self.is_admin(admin_telegram_id):
            return None
        user_id = self.create_manual_user(
            admin_telegram_id=admin_telegram_id,
            target_telegram_id=target_telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        if user_id is None:
            return None
        config_version = validate_config_version(config_version)
        plan = self._repo.get_plan(plan_id) if plan_id is not None else None
        order_id = self._repo.create_order(
            user_id=user_id,
            plan_id=plan_id,
            payment_mode="manual_admin",
            requested_config_version=config_version,
        )
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="create_manual_access_request",
            target_user_id=user_id,
            metadata={
                "order_id": order_id,
                "target_telegram_id": target_telegram_id,
                "config_version": config_version,
                "plan_id": plan_id,
            },
        )
        return AccessRequestResult(
            order_id=order_id,
            text=render_access_request_created(
                order_id=order_id,
                config_version=config_version,
                plan_name=str(plan["name"]) if plan is not None else None,
            ),
        )

    def grant_admin(
        self,
        *,
        admin_telegram_id: int,
        target_telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
    ) -> bool:
        if not self.is_admin(admin_telegram_id):
            return False
        self._repo.upsert_user(
            telegram_id=target_telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        return self._repo.set_user_admin(
            telegram_id=target_telegram_id,
            is_admin=True,
            granted_by_admin_telegram_id=admin_telegram_id,
        )

    def list_active_plans(self):
        return self._repo.list_active_plans()

    def build_user_traffic_views(
        self,
        *,
        telegram_id: int,
        now: str | None = None,
    ) -> list[DeviceTrafficView]:
        user = self._repo.get_user_by_telegram_id(telegram_id)
        if user is None:
            return []
        return [
            build_device_traffic_view(
                device,
                self._repo.get_latest_device_traffic(int(device["id"])),
                now=now,
            )
            for device in self._repo.list_user_devices(int(user["id"]))
        ]

    def list_user_devices(self, *, telegram_id: int):
        user = self._repo.get_user_by_telegram_id(telegram_id)
        if user is None:
            return []
        return self._repo.list_user_devices(
            int(user["id"]),
            statuses=("active", "disabled", "revoked"),
        )

    def build_admin_traffic_views(
        self,
        *,
        admin_telegram_id: int,
        now: str | None = None,
    ) -> list[DeviceTrafficView]:
        if not self.is_admin(admin_telegram_id):
            return []
        views = [
            build_device_traffic_view(
                device,
                self._repo.get_latest_device_traffic(int(device["id"])),
                now=now,
            )
            for device in self._repo.list_active_devices_with_users()
        ]
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="bot_admin_traffic_read",
            metadata={
                "device_count": len(views),
                "source": "local_traffic_snapshots",
            },
        )
        return views

    def list_pending_orders(self, *, admin_telegram_id: int):
        if not self.is_admin(admin_telegram_id):
            return []
        return self._repo.list_pending_orders()

    def get_operator_status(
        self,
        *,
        admin_telegram_id: int,
        now: datetime | str | None = None,
    ) -> OperatorStatusSummary | None:
        if not self.is_admin(admin_telegram_id):
            return None
        status = build_operator_status(
            self._repo,
            now=now,
            vps_writes_enabled=self._vps_writes_enabled,
        )
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="bot_operator_status_read",
            metadata=status.safe_metadata(),
        )
        return status

    def get_operator_server_statuses(
        self,
        *,
        admin_telegram_id: int,
        limit: int = 20,
    ) -> list[OperatorServerStatusView] | None:
        if not self.is_admin(admin_telegram_id):
            return None
        statuses = build_operator_server_statuses(self._repo, limit=limit)
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="bot_admin_servers_read",
            metadata={
                "server_count": len(statuses),
                "source": "local_server_summaries",
            },
        )
        return statuses

    def get_operator_credential_statuses(
        self,
        *,
        admin_telegram_id: int,
        limit: int = 20,
    ) -> list[OperatorCredentialStatusView] | None:
        if not self.is_admin(admin_telegram_id):
            return None
        statuses = build_operator_credential_statuses(self._repo, limit=limit)
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="bot_admin_integrations_read",
            metadata={
                "credential_count": len(statuses),
                "source": "local_integration_registry",
            },
        )
        return statuses

    def list_users(self, *, admin_telegram_id: int):
        if not self.is_admin(admin_telegram_id):
            return []
        return self._repo.list_users_for_admin()

    def approve_order(
        self,
        *,
        admin_telegram_id: int,
        order_id: int,
        config_version: str,
    ) -> ApprovalResult | None:
        if not self.is_admin(admin_telegram_id):
            return None
        if self._access_service is None or self._default_server_id is None:
            raise RuntimeError("Access approval workflow is not configured")

        order = self._repo.get_order(order_id)
        user = self._repo.get_user(int(order["user_id"]))
        try:
            result = self._access_service.approve_order(
                order_id,
                self._default_server_id,
                self._next_device_name(),
                admin_telegram_id=admin_telegram_id,
                config_version=config_version,
            )
        except PeerApplyError as exc:
            self._repo.record_admin_action(
                admin_telegram_id=admin_telegram_id,
                action="approve_order_vps_failed",
                target_user_id=int(user["id"]),
                metadata={
                    "operation": "approve_order",
                    "order_id": order_id,
                    "server_id": self._default_server_id,
                    "config_version": config_version,
                    "error_type": type(exc).__name__,
                    "redacted_error": redact(str(exc)),
                },
            )
            raise
        template_text = self._repo.get_message_template(
            CONFIG_READY_TEMPLATE_KEY,
            default_text=DEFAULT_CONFIG_READY_TEMPLATE,
        )
        device = self._repo.get_device(result.device_id)
        delivery = build_config_delivery(
            device_id=result.device_id,
            device_name=str(device["name"]),
            config_version=config_version,
            config_text=result.config_text,
            template_text=template_text,
        )
        return ApprovalResult(
            device_id=result.device_id,
            user_telegram_id=int(user["telegram_id"]),
            admin_text=render_admin_approval(
                order_id=order_id,
                device_id=result.device_id,
                user_telegram_id=int(user["telegram_id"]),
                config_version=config_version,
            ),
            user_text=render_user_config_ready(config_version=config_version),
            config_text=result.config_text,
            delivery=delivery,
        )

    def get_config_ready_template(self, *, admin_telegram_id: int) -> str | None:
        if not self.is_admin(admin_telegram_id):
            return None
        return self._repo.get_message_template(
            CONFIG_READY_TEMPLATE_KEY,
            default_text=DEFAULT_CONFIG_READY_TEMPLATE,
        )

    def set_config_ready_template(self, *, admin_telegram_id: int, text: str) -> bool:
        if not self.is_admin(admin_telegram_id):
            return False
        self._repo.set_message_template(CONFIG_READY_TEMPLATE_KEY, text)
        return True

    def reset_config_ready_template(self, *, admin_telegram_id: int) -> bool:
        if not self.is_admin(admin_telegram_id):
            return False
        self._repo.set_message_template(
            CONFIG_READY_TEMPLATE_KEY,
            DEFAULT_CONFIG_READY_TEMPLATE,
        )
        return True

    def build_resend_delivery(
        self,
        *,
        admin_telegram_id: int,
        device_id: int,
    ) -> ResendResult | None:
        if not self.is_admin(admin_telegram_id):
            return None
        if self._secret_box is None:
            raise RuntimeError("Config resend workflow is not configured")

        device = self._repo.get_device(device_id)
        return self._build_delivery_for_device(device)

    def build_user_resend_delivery(
        self,
        *,
        telegram_id: int,
        device_id: int,
    ) -> ResendResult | None:
        if self._secret_box is None:
            raise RuntimeError("Config resend workflow is not configured")

        user = self._repo.get_user_by_telegram_id(telegram_id)
        if user is None:
            return None
        device = self._repo.get_user_device(
            user_id=int(user["id"]),
            device_id=device_id,
        )
        if device is None:
            return None
        return self._build_delivery_for_device(device)

    def revoke_user_device(
        self,
        *,
        telegram_id: int,
        device_id: int,
        revoked_at: str | None = None,
    ) -> bool:
        user = self._repo.get_user_by_telegram_id(telegram_id)
        if user is None:
            return False
        device = self._repo.get_user_device(
            user_id=int(user["id"]),
            device_id=device_id,
        )
        if device is None:
            return False
        result = cascade_revoke_physical_device(
            self._repo,
            local_device_id=device_id,
            reason="user_requested",
            revoked_at=_parse_utc(revoked_at or _utc_now()),
            peer_remover=self._peer_remover,
            apply_remote=self._peer_remover is not None,
        )
        return result.device_rows_revoked > 0 or result.remote_peer_removed

    def reset_user_devices(
        self,
        *,
        telegram_id: int,
        revoked_at: str | None = None,
    ) -> int:
        user = self._repo.get_user_by_telegram_id(telegram_id)
        if user is None:
            return 0
        devices = sorted(
            self._repo.list_user_devices(int(user["id"])),
            key=lambda device: int(device["id"]),
        )
        if self._peer_remover is not None:
            remote_removed_device_ids: list[int] = []
            for device in devices:
                try:
                    self._peer_remover.remove_peer(
                        server=self._repo.get_server(int(device["server_id"])),
                        peer_public_key=str(device["peer_public_key"]),
                    )
                except Exception as exc:
                    if remote_removed_device_ids:
                        raise RemoteOperationPartialFailure(
                            remote_changed_local_failed_result(
                                operation_id="bot.reset_user_devices",
                                recovery_note=(
                                    "One or more remote peers were removed before "
                                    "local device reset completed. Put affected "
                                    "devices into manual review, verify server "
                                    "peers, and reconcile local device statuses. "
                                    f"Remote removed device ids: {remote_removed_device_ids}."
                                ),
                            ),
                            exc,
                        ) from exc
                    raise
                remote_removed_device_ids.append(int(device["id"]))
        actual_revoked_at = _parse_utc(revoked_at or _utc_now())
        revoked_count = 0
        for device in devices:
            result = cascade_revoke_physical_device(
                self._repo,
                local_device_id=int(device["id"]),
                reason="user_reset",
                revoked_at=actual_revoked_at,
                peer_remover=None,
                apply_remote=False,
                remote_already_removed=self._peer_remover is not None,
            )
            revoked_count += result.device_rows_revoked
        return revoked_count

    def _build_delivery_for_device(self, device) -> ResendResult:
        result = build_device_config_delivery(
            repo=self._repo,
            secret_box=self._secret_box,
            device=device,
            client_config_template_dir=self._client_config_template_dir,
            client_config_defaults=self._client_config_defaults,
        )
        return ResendResult(
            device_id=result.device_id,
            user_telegram_id=result.user_telegram_id,
            config_text=result.config_text,
            delivery=result.delivery,
        )

    def _next_device_name(self) -> str:
        sequence = self._repo.next_device_sequence(
            self._device_name_prefix,
            minimum_sequence=self._device_name_sequence_seed,
        )
        return f"{self._device_name_prefix}-{sequence}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
