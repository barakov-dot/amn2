import asyncio
import os
import socket
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any


_AF_UNIX = getattr(socket, "AF_UNIX", 1)


class SystemdNotifyError(RuntimeError):
    pass


@dataclass
class SystemdNotifier:
    _socket_address: str | None
    _watchdog_usec: int | None
    _socket_factory: Callable[[int, int], Any] = socket.socket
    _sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    @classmethod
    def from_environment(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        socket_factory: Callable[[int, int], Any] = socket.socket,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> "SystemdNotifier":
        source = os.environ if env is None else env
        configured_socket = str(source.get("NOTIFY_SOCKET", "") or "").strip()
        socket_address: str | None = configured_socket or None
        if socket_address is not None and socket_address.startswith("@"):
            socket_address = "\0" + socket_address[1:]

        watchdog_usec = _parse_watchdog_usec(source.get("WATCHDOG_USEC"))
        return cls(
            _socket_address=socket_address,
            _watchdog_usec=watchdog_usec,
            _socket_factory=socket_factory,
            _sleep=sleep,
        )

    def ready(self, status: str) -> None:
        safe_status = _validate_status(status)
        self._send(f"READY=1\nSTATUS={safe_status}".encode("utf-8"))

    def stopping(self, status: str) -> None:
        safe_status = _validate_status(status)
        self._send(f"STOPPING=1\nSTATUS={safe_status}".encode("utf-8"))

    def watchdog_interval_seconds(self) -> float | None:
        if self._watchdog_usec is None:
            return None
        return self._watchdog_usec / 2_000_000

    async def run_watchdog(self) -> None:
        interval = self.watchdog_interval_seconds()
        if interval is None:
            return
        while True:
            await self._sleep(interval)
            self._send(b"WATCHDOG=1")

    def _send(self, payload: bytes) -> None:
        if self._socket_address is None:
            return
        try:
            with self._socket_factory(_AF_UNIX, socket.SOCK_DGRAM) as client:
                client.sendto(payload, self._socket_address)
        except OSError:
            raise SystemdNotifyError("Systemd notification failed") from None


def _parse_watchdog_usec(value: str | None) -> int | None:
    if value is None or not str(value).strip():
        return None
    try:
        watchdog_usec = int(str(value).strip())
    except ValueError:
        raise SystemdNotifyError("WATCHDOG_USEC must be a positive integer") from None
    if watchdog_usec <= 0:
        raise SystemdNotifyError("WATCHDOG_USEC must be a positive integer")
    return watchdog_usec


def _validate_status(status: str) -> str:
    value = str(status).strip()
    if not value or "\n" in value or "\r" in value or "\0" in value:
        raise SystemdNotifyError("Systemd status is invalid")
    return value
