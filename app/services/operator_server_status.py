from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence


class OperatorServerStatusStore(Protocol):
    def list_api_server_summaries(
        self,
        *,
        limit: int,
    ) -> Sequence[Mapping[str, object]]: ...


@dataclass(frozen=True)
class OperatorServerStatusView:
    name: str
    status: str
    runtime: str
    total_device_count: int
    active_device_count: int
    health_status: str | None
    health_latency_ms: int | None
    health_checked_at: str | None
    health_ssh_ok: bool | None
    health_awg_ok: bool | None
    health_udp_port_ok: bool | None


def build_operator_server_statuses(
    store: OperatorServerStatusStore,
    *,
    limit: int = 20,
) -> list[OperatorServerStatusView]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")

    return [
        OperatorServerStatusView(
            name=str(row["name"]),
            status=str(row["status"]),
            runtime=str(row["runtime"]),
            total_device_count=int(row["total_device_count"]),
            active_device_count=int(row["active_device_count"]),
            health_status=_optional_text(row["health_status"]),
            health_latency_ms=_optional_int(row["health_latency_ms"]),
            health_checked_at=_optional_text(row["health_checked_at"]),
            health_ssh_ok=_optional_bool(row["health_ssh_ok"]),
            health_awg_ok=_optional_bool(row["health_awg_ok"]),
            health_udp_port_ok=_optional_bool(row["health_udp_port_ok"]),
        )
        for row in store.list_api_server_summaries(limit=limit)
    ]


def _optional_text(value: object) -> str | None:
    return None if value is None else str(value)


def _optional_int(value: object) -> int | None:
    return None if value is None else int(value)


def _optional_bool(value: object) -> bool | None:
    return None if value is None else bool(value)
