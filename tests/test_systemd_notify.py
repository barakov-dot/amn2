import asyncio
import socket

import pytest

from app.systemd_notify import SystemdNotifier, SystemdNotifyError


class FakeSocket:
    def __init__(self, sent, *, send_error=None):
        self.sent = sent
        self.send_error = send_error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def sendto(self, payload, address):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append((payload, address))


class FakeSocketFactory:
    def __init__(self, *, send_error=None):
        self.sent = []
        self.calls = []
        self.send_error = send_error

    def __call__(self, family, kind):
        self.calls.append((family, kind))
        return FakeSocket(self.sent, send_error=self.send_error)


def test_notifier_is_noop_without_notify_socket():
    factory = FakeSocketFactory()
    notifier = SystemdNotifier.from_environment(
        env={},
        socket_factory=factory,
    )

    notifier.ready("Telegram polling admitted")
    notifier.stopping("Telegram polling stopped")

    assert factory.calls == []
    assert notifier.watchdog_interval_seconds() is None


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("/run/systemd/notify", "/run/systemd/notify"),
        ("@abstract-notify", "\0abstract-notify"),
    ],
)
def test_notifier_normalizes_socket_and_sends_ready_and_stopping(
    configured,
    expected,
):
    factory = FakeSocketFactory()
    notifier = SystemdNotifier.from_environment(
        env={"NOTIFY_SOCKET": configured},
        socket_factory=factory,
    )

    notifier.ready("Telegram polling admitted")
    notifier.stopping("Telegram polling stopped")

    unix_family = getattr(socket, "AF_UNIX", 1)
    assert factory.calls == [
        (unix_family, socket.SOCK_DGRAM),
        (unix_family, socket.SOCK_DGRAM),
    ]
    assert factory.sent == [
        (b"READY=1\nSTATUS=Telegram polling admitted", expected),
        (b"STOPPING=1\nSTATUS=Telegram polling stopped", expected),
    ]


def test_notifier_watchdog_uses_half_interval_and_emits_heartbeat():
    factory = FakeSocketFactory()
    sleep_intervals = []

    async def fake_sleep(interval):
        sleep_intervals.append(interval)
        if len(sleep_intervals) > 1:
            raise asyncio.CancelledError

    notifier = SystemdNotifier.from_environment(
        env={
            "NOTIFY_SOCKET": "/run/systemd/notify",
            "WATCHDOG_USEC": "4000000",
            "TELEGRAM_BOT_TOKEN": "must-not-be-read-or-emitted",
        },
        socket_factory=factory,
        sleep=fake_sleep,
    )

    assert notifier.watchdog_interval_seconds() == 2.0
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(notifier.run_watchdog())

    assert sleep_intervals == [2.0, 2.0]
    assert factory.sent == [
        (b"WATCHDOG=1", "/run/systemd/notify"),
    ]
    assert b"must-not-be-read-or-emitted" not in factory.sent[0][0]


@pytest.mark.parametrize("value", ["0", "-1", "not-an-integer"])
def test_notifier_rejects_invalid_watchdog_environment(value):
    with pytest.raises(SystemdNotifyError, match="WATCHDOG_USEC"):
        SystemdNotifier.from_environment(
            env={
                "NOTIFY_SOCKET": "/run/systemd/notify",
                "WATCHDOG_USEC": value,
            }
        )


@pytest.mark.parametrize("status", ["bad\nstatus", "bad\0status", ""])
def test_notifier_rejects_invalid_status(status):
    notifier = SystemdNotifier.from_environment(
        env={"NOTIFY_SOCKET": "/run/systemd/notify"},
        socket_factory=FakeSocketFactory(),
    )

    with pytest.raises(SystemdNotifyError, match="status is invalid"):
        notifier.ready(status)


def test_notifier_maps_socket_failure_without_raw_path_or_error():
    factory = FakeSocketFactory(
        send_error=OSError("raw-notify-path-and-secret-marker")
    )
    notifier = SystemdNotifier.from_environment(
        env={"NOTIFY_SOCKET": "/private/raw/notify.sock"},
        socket_factory=factory,
    )

    with pytest.raises(SystemdNotifyError, match="notification failed") as error:
        notifier.ready("Telegram polling admitted")

    message = str(error.value)
    assert "/private/raw/notify.sock" not in message
    assert "raw-notify-path-and-secret-marker" not in message
