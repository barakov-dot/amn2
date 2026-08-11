from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.db.repositories import Repository


@dataclass(frozen=True)
class ProtocolIssuanceBlockPlan:
    devices: tuple[sqlite3.Row, ...]
    recovery_attempts: tuple[sqlite3.Row, ...]


class ProtocolIssuanceBarrierService:
    def __init__(self, repo: Repository) -> None:
        self._repo = repo

    def begin_block(self, user_id: int) -> ProtocolIssuanceBlockPlan:
        with self._repo.transaction():
            self._repo.get_user(user_id)
            self._repo.set_protocol_issuance_user_barrier(user_id, "blocking")
            self._repo.set_user_status_for_admin(user_id, "blocked")
            self._repo.cancel_reserved_protocol_issuance_attempts_for_user(
                user_id, reason_code="user_block_started"
            )
            devices = tuple(self._repo.list_user_devices_for_vpn_removal(user_id))
            recovery_attempts = tuple(
                self._repo.list_recovery_protocol_issuance_attempts_for_user(user_id)
            )
        return ProtocolIssuanceBlockPlan(
            devices=devices,
            recovery_attempts=recovery_attempts,
        )

    def complete_block(
        self, user_id: int, *, removed_local_device_ids: set[int]
    ) -> bool:
        with self._repo.transaction():
            barrier = self._repo.get_protocol_issuance_user_barrier(user_id)
            if barrier is None or str(barrier["state"]) != "blocking":
                raise ValueError("protocol issuance barrier is not blocking")
            for attempt in self._repo.list_recovery_protocol_issuance_attempts_for_user(
                user_id
            ):
                local_device_id = attempt["local_device_id"]
                if local_device_id is None:
                    continue
                known_id = int(local_device_id)
                if known_id in removed_local_device_ids:
                    self._repo.reconcile_protocol_issuance_recovery(
                        int(attempt["id"]),
                        local_device_id=known_id,
                        reason_code="peer_removed_during_user_block",
                    )
            unresolved = self._repo.list_recovery_protocol_issuance_attempts_for_user(
                user_id
            )
            if unresolved:
                return False
            self._repo.set_protocol_issuance_user_barrier(user_id, "blocked")
            return True

    def begin_enable(self, user_id: int) -> None:
        barrier = self._repo.get_protocol_issuance_user_barrier(user_id)
        if barrier is None or str(barrier["state"]) != "blocked":
            raise ValueError("protocol issuance barrier is not blocked")
        if str(self._repo.get_user(user_id)["status"]) != "blocked":
            raise ValueError("user is not blocked")

    def complete_enable(self, user_id: int) -> int:
        with self._repo.transaction():
            self.begin_enable(user_id)
            enabled_count = self._repo.enable_user_devices(user_id)
            self._repo.set_user_status_for_admin(user_id, "active")
            if not self._repo.delete_protocol_issuance_user_barrier(user_id):
                raise ValueError("protocol issuance barrier disappeared")
            return enabled_count
