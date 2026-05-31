from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

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
from app.server.peer_apply import PeerApplyError
from app.services.config_delivery import build_device_config_delivery
from app.services.access import (
    AccessService,
    RemoteMutationResult,
    RemoteOperationPartialFailure,
)
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
    ) -> None:
        self._repo = repo
        self._admin_telegram_ids = admin_telegram_ids
        self._access_service = access_service
        self._default_server_id = default_server_id
        self._secret_box = secret_box
        self._peer_remover = peer_remover
        self._client_config_template_dir = client_config_template_dir
        self._client_config_defaults = client_config_defaults or ClientConfigDefaults()

    def is_admin(self, telegram_id: int) -> bool:
        if telegram_id in self._admin_telegram_ids:
            return True
        user = self._repo.get_user_by_telegram_id(telegram_id)
        return bool(user is not None and int(user["is_admin"]) == 1)

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
        return self._repo.list_user_devices(int(user["id"]))

    def build_admin_traffic_views(
        self,
        *,
        admin_telegram_id: int,
        now: str | None = None,
    ) -> list[DeviceTrafficView]:
        if not self.is_admin(admin_telegram_id):
            return []
        return [
            build_device_traffic_view(
                device,
                self._repo.get_latest_device_traffic(int(device["id"])),
                now=now,
            )
            for device in self._repo.list_active_devices_with_users()
        ]

    def list_pending_orders(self, *, admin_telegram_id: int):
        if not self.is_admin(admin_telegram_id):
            return []
        return self._repo.list_pending_orders()

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
                _default_device_name(order_id),
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
        delivery = build_config_delivery(
            device_id=result.device_id,
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
        if self._peer_remover is not None:
            self._peer_remover.remove_peer(
                server=self._repo.get_server(int(device["server_id"])),
                peer_public_key=str(device["peer_public_key"]),
            )
        return self._repo.revoke_device(
            device_id,
            reason="user_requested",
            revoked_at=revoked_at or _utc_now(),
        )

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
                            RemoteMutationResult(
                                operation_id="bot.reset_user_devices",
                                consistency_status="partial-failure",
                                remote_applied=True,
                                local_applied=False,
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
        return self._repo.revoke_user_devices(
            int(user["id"]),
            reason="user_reset",
            revoked_at=revoked_at or _utc_now(),
        )

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


def _default_device_name(order_id: int) -> str:
    return f"device-{order_id}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
