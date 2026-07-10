from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.services.api_tokens import API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS


class OperatorStatusStore(Protocol):
    def get_operator_status_summary(
        self,
        *,
        now: str,
        rotation_notice_at: str,
    ) -> dict[str, int]: ...


@dataclass(frozen=True)
class OperatorStatusSummary:
    users_active: int
    users_blocked: int
    servers_active: int
    servers_degraded: int
    devices_active: int
    devices_disabled: int
    pending_orders: int
    credentials_active: int
    credentials_rotation_due: int
    credentials_expired: int
    credentials_revoked: int
    mode: str = "read-only"
    vps_writes_enabled: bool = False
    public_config_delivery_enabled: bool = False
    public_exposure_enabled: bool = False

    def safe_metadata(self) -> dict[str, object]:
        return asdict(self)


def build_operator_status(
    store: OperatorStatusStore,
    *,
    now: datetime | str | None = None,
    vps_writes_enabled: bool = False,
) -> OperatorStatusSummary:
    current_time = _as_datetime(now)
    rotation_notice_at = current_time + timedelta(
        days=API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS
    )
    counts = store.get_operator_status_summary(
        now=current_time.isoformat(),
        rotation_notice_at=rotation_notice_at.isoformat(),
    )
    return OperatorStatusSummary(
        **counts,
        vps_writes_enabled=vps_writes_enabled,
    )


def _as_datetime(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
