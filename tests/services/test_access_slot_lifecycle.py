from datetime import datetime, timezone

import pytest

from app.access_expiry import AccessExpiry, INDEFINITE
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.access import AccessService
from app.services.access_slot_lifecycle import (
    AccessSlotApplyRequired,
    disable_access_slot,
    revoke_access_slot,
)


class PeerClient:
    def __init__(self):
        self.removed = []

    def list_allocated_ips(self, *, server):
        return []

    def apply_peer(self, **kwargs):
        return None

    def remove_peer(self, *, server, peer_public_key):
        self.removed.append((int(server["id"]), peer_public_key))


def _slots(tmp_path):
    conn = connect(tmp_path / "lifecycle.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    owner_id = repo.create_operator_recipient(operator_label="Иван")
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer = PeerClient()
    service = AccessService(
        repo=repo,
        secret_box=SecretBox.from_app_secret("test-secret-lifecycle-1234567890123"),
        peer_applier=peer,
    )
    ids = []
    for ordinal in (1, 2):
        ids.append(
            service.create_operator_device(
                owner_user_id=owner_id,
                server_id=server_id,
                device_name=f"{ordinal:02d}",
                duration_days=None,
                expiry=AccessExpiry(INDEFINITE, None, None),
                admin_telegram_id=7001,
                assignment_mode="recipient_unassigned",
            ).device_id
        )
    return conn, repo, peer, ids


def test_disable_is_remote_first_and_independent(tmp_path):
    _conn, repo, peer, ids = _slots(tmp_path)
    with pytest.raises(AccessSlotApplyRequired):
        disable_access_slot(
            repo,
            local_device_id=ids[0],
            reason="operator disabled",
            changed_at=datetime.now(timezone.utc),
            peer_remover=None,
            apply_remote=False,
            admin_telegram_id=7001,
        )
    result = disable_access_slot(
        repo,
        local_device_id=ids[0],
        reason="operator disabled",
        changed_at=datetime.now(timezone.utc),
        peer_remover=peer,
        apply_remote=True,
        admin_telegram_id=7001,
    )
    assert result.status == "disabled"
    assert repo.get_device(ids[0])["status"] == "disabled"
    assert repo.get_device(ids[1])["status"] == "active"
    assert len(peer.removed) == 1


def test_revoke_is_remote_first_and_independent(tmp_path):
    _conn, repo, peer, ids = _slots(tmp_path)
    result = revoke_access_slot(
        repo,
        local_device_id=ids[0],
        reason="access withdrawn",
        changed_at=datetime.now(timezone.utc),
        peer_remover=peer,
        apply_remote=True,
        admin_telegram_id=7001,
    )
    assert result.status == "revoked"
    assert repo.get_device(ids[0])["status"] == "revoked"
    assert repo.get_device(ids[1])["status"] == "active"
    assert len(peer.removed) == 1
