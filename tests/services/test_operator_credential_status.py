from app.services.operator_credential_status import build_operator_credential_statuses


def test_operator_credential_status_is_hash_free_and_computes_lifecycle():
    store = FakeStore(
        [
            {
                "id": "hidden-id",
                "name": "monitor",
                "owner_label": "operations",
                "integration_kind": "monitoring",
                "purpose": "health dashboards",
                "scopes_json": '["server:read", "metrics:read"]',
                "expires_at": "2026-07-15T00:00:00Z",
                "revoked_at": None,
                "last_used_at": "2026-07-09T00:00:00Z",
                "created_at": "2026-07-01T00:00:00Z",
                "token_hash": "must-not-leak",
                "raw_token": "must-not-leak",
            }
        ]
    )

    statuses = build_operator_credential_statuses(
        store,
        now="2026-07-10T00:00:00Z",
    )

    assert statuses[0].status == "rotation-due"
    assert statuses[0].scopes == ("server:read", "metrics:read")
    assert not hasattr(statuses[0], "token_hash")
    assert not hasattr(statuses[0], "raw_token")
    assert not hasattr(statuses[0], "token_id")


class FakeStore:
    def __init__(self, rows):
        self.rows = rows

    def list_api_tokens_for_admin(self, *, limit):
        assert limit == 20
        return self.rows
