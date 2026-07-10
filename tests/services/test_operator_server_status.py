from app.services.operator_server_status import build_operator_server_statuses


def test_operator_server_status_uses_explicit_safe_field_allowlist():
    store = FakeStore(
        [
            {
                "name": "primary",
                "status": "active",
                "runtime": "docker",
                "total_device_count": 3,
                "active_device_count": 2,
                "health_status": "online",
                "health_latency_ms": 24,
                "health_checked_at": "2026-07-10T12:00:00Z",
                "health_ssh_ok": 1,
                "health_awg_ok": 1,
                "health_udp_port_ok": 0,
                "endpoint_host": "must-not-leak.example",
                "server_public_key": "must-not-leak",
            }
        ]
    )

    statuses = build_operator_server_statuses(store, limit=20)

    assert store.limit == 20
    assert statuses[0].name == "primary"
    assert statuses[0].active_device_count == 2
    assert statuses[0].health_udp_port_ok is False
    assert not hasattr(statuses[0], "endpoint_host")
    assert not hasattr(statuses[0], "server_public_key")


class FakeStore:
    def __init__(self, rows):
        self.rows = rows
        self.limit = None

    def list_api_server_summaries(self, *, limit):
        self.limit = limit
        return self.rows
