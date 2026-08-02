from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import shutil
import sqlite3

import pytest

from app.db.schema import initialize_schema


def migration_module():
    try:
        from app.migration import bot_web
    except ModuleNotFoundError as error:
        pytest.fail(f"Phase 13 bot/web migration preview is missing: {error}")
    return bot_web


class MigrationFixture:
    def __init__(self, root: Path) -> None:
        self.usa_db = root / "usa.sqlite3"
        self.spain_db = root / "spain.sqlite3"
        self.spain_copy = root / "spain.copy.sqlite3"
        self._create_database(self.usa_db)
        self._create_database(self.spain_db)
        self._seed_usa()
        self._seed_spain()
        self.refresh_spain_copy()

    @staticmethod
    def _create_database(path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            initialize_schema(connection)
        finally:
            connection.close()

    @staticmethod
    def _open(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _seed_usa(self) -> None:
        connection = self._open(self.usa_db)
        try:
            connection.execute(
                """
                INSERT INTO servers(
                    id, name, host, ssh_port, endpoint_host, vpn_port,
                    vpn_network_cidr, server_address, runtime, firewall,
                    status, max_devices
                ) VALUES (1, 'usa-legacy', NULL, 22, NULL, 51820,
                          '10.60.0.0/24', '10.60.0.1', 'legacy', 'legacy',
                          'disabled', 100)
                """
            )
            for index in range(6):
                connection.execute(
                    """
                    INSERT INTO users(
                        id, telegram_id, operator_label, username, status,
                        locale, is_admin
                    ) VALUES (?, ?, ?, ?, 'active', 'ru', 0)
                    """,
                    (index + 1, 1000 + index, f"usa-user-{index}", f"source-{index}"),
                )
            for index in range(8):
                plan_id = f"plan-{index + 1}"
                connection.execute(
                    """
                    INSERT INTO plans(
                        id, name, duration_days, max_devices, price,
                        currency, is_free, is_active
                    ) VALUES (?, ?, ?, 5, ?, 'RUB', 0, 1)
                    """,
                    (plan_id, f"Plan {index + 1}", 30 + index, 1000 + index),
                )
                user_id = (index % 6) + 1
                device_id = index + 1
                connection.execute(
                    """
                    INSERT INTO devices(
                        id, user_id, server_id, name, expiry_policy, status,
                        vpn_ip, peer_public_key, peer_private_key_encrypted,
                        preshared_key_encrypted, config_version,
                        config_material_status, assignment_mode
                    ) VALUES (?, ?, 1, ?, 'indefinite', 'active', ?, ?, ?, ?,
                              'amneziawg_v2', 'available', 'dedicated_device')
                    """,
                    (
                        device_id,
                        user_id,
                        f"USA legacy {device_id}",
                        f"10.60.0.{device_id + 1}",
                        f"usa-public-{device_id}",
                        f"synthetic-private-{device_id}",
                        f"synthetic-psk-{device_id}",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO orders(
                        id, user_id, device_id, plan_id,
                        requested_config_version, status, payment_mode
                    ) VALUES (?, ?, ?, ?, 'amneziawg_v2', 'fulfilled', 'manual')
                    """,
                    (index + 1, user_id, device_id, plan_id),
                )
            for index in range(12):
                connection.execute(
                    """
                    INSERT INTO api_tokens(
                        id, name, owner_user_id, owner_label, token_hash,
                        scopes_json
                    ) VALUES (?, ?, ?, ?, ?, '[""read""]')
                    """,
                    (
                        f"token-{index + 1}",
                        f"Integration {index + 1}",
                        (index % 6) + 1,
                        f"owner-{index + 1}",
                        f"synthetic-token-hash-{index + 1}",
                    ),
                )
            connection.execute(
                "INSERT INTO message_templates(key, text) VALUES ('welcome', 'hello')"
            )
            connection.commit()
        finally:
            connection.close()

    def _seed_spain(self) -> None:
        connection = self._open(self.spain_db)
        try:
            connection.execute(
                """
                INSERT INTO servers(
                    id, name, host, ssh_port, endpoint_host, vpn_port,
                    vpn_network_cidr, server_address, runtime, firewall,
                    status, max_devices
                ) VALUES (1, 'spain-primary', NULL, 22, NULL, 51821,
                          '10.70.0.0/24', '10.70.0.1', 'accepted-awg2',
                          'accepted', 'active', 100)
                """
            )
            connection.execute(
                """
                INSERT INTO users(
                    id, telegram_id, operator_label, username, status,
                    locale, is_admin
                ) VALUES (1, 1000, 'spain-owner', 'target-owner',
                          'active', 'ru', 1)
                """
            )
            for index in range(7):
                sequence = index + 1
                connection.execute(
                    """
                    INSERT INTO devices(
                        id, user_id, server_id, name, expiry_policy, status,
                        vpn_ip, peer_public_key, peer_private_key_encrypted,
                        preshared_key_encrypted, config_version,
                        config_material_status, assignment_mode,
                        config_fingerprint
                    ) VALUES (?, 1, 1, ?, 'indefinite', 'active', ?, ?, ?, ?,
                              'amneziawg_v2', 'available', 'dedicated_device', ?)
                    """,
                    (
                        sequence,
                        f"d{sequence}",
                        f"10.70.0.{sequence + 1}",
                        f"spain-public-{sequence}",
                        f"target-private-{sequence}",
                        f"target-psk-{sequence}",
                        f"sha256:{sequence:064x}",
                    ),
                )
                passport_id = f"dev_{sequence:032x}"
                connection.execute(
                    """
                    INSERT INTO device_passports(
                        device_id, local_device_id, owner_user_id, platform,
                        official_client_type, client_version, import_method,
                        config_schema_version, config_fingerprint
                    ) VALUES (?, ?, 1, 'unknown', 'unknown_official', '5.0.0.5',
                              'conf_file', 'amneziawg_v2', ?)
                    """,
                    (passport_id, sequence, f"sha256:{sequence:064x}"),
                )
            for request_index, item_count in ((1, 4), (2, 3)):
                request_id = f"spain-request-{request_index}"
                connection.execute(
                    """
                    INSERT INTO admin_config_issuance_requests(
                        request_id, request_fingerprint, item_count
                    ) VALUES (?, ?, ?)
                    """,
                    (request_id, f"sha256:{request_index:064x}", item_count),
                )
            for index in range(7):
                sequence = index + 1
                request_id = "spain-request-1" if sequence <= 4 else "spain-request-2"
                item_index = index if sequence <= 4 else index - 4
                passport_id = f"dev_{sequence:032x}"
                connection.execute(
                    """
                    INSERT INTO admin_config_issuance_receipts(
                        request_id, item_index, item_fingerprint,
                        recipient_user_id, device_id, passport_device_id,
                        assignment_mode, slot_sequence, expiry_policy, status,
                        config_filename
                    ) VALUES (?, ?, ?, 1, ?, ?, 'dedicated_device', ?,
                              'indefinite', 'completed', ?)
                    """,
                    (
                        request_id,
                        item_index,
                        f"sha256:{(100 + sequence):064x}",
                        sequence,
                        passport_id,
                        sequence,
                        f"d{sequence}.conf",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO device_lifecycle_events(
                        passport_device_id, stage, status, occurred_at,
                        duration_ms, evidence_json
                    ) VALUES (?, 'acceptance_verified', 'completed',
                              '2026-08-01T00:00:00Z', 1, '{}')
                    """,
                    (passport_id,),
                )
            connection.commit()
        finally:
            connection.close()

    def add_conflicting_target_plan(self, plan_id: str) -> None:
        connection = self._open(self.spain_db)
        try:
            connection.execute(
                """
                INSERT INTO plans(
                    id, name, duration_days, max_devices, price,
                    currency, is_free, is_active
                ) VALUES (?, 'Conflicting plan', 999, 1, 0, 'RUB', 1, 0)
                """,
                (plan_id,),
            )
            connection.commit()
        finally:
            connection.close()

    def break_order_device_mapping(self) -> None:
        connection = self._open(self.usa_db)
        try:
            connection.execute("UPDATE orders SET device_id=NULL WHERE id=1")
            connection.commit()
        finally:
            connection.close()

    def mismatch_order_device_owner(self) -> None:
        connection = self._open(self.usa_db)
        try:
            connection.execute("UPDATE orders SET user_id=2 WHERE id=1")
            connection.commit()
        finally:
            connection.close()

    def add_operator_label_collision(self) -> None:
        connection = self._open(self.usa_db)
        try:
            connection.execute(
                "UPDATE users SET operator_label='spain-owner' WHERE id=2"
            )
            connection.commit()
        finally:
            connection.close()

    def add_conflicting_target_template(self) -> None:
        connection = self._open(self.spain_db)
        try:
            connection.execute(
                "INSERT INTO message_templates(key, text) VALUES ('welcome', 'different')"
            )
            connection.commit()
        finally:
            connection.close()

    def add_rejecting_target_trigger(self) -> None:
        connection = self._open(self.spain_db)
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_migrated_user
                BEFORE INSERT ON users
                WHEN NEW.telegram_id != 1000
                BEGIN
                    SELECT RAISE(ABORT, 'synthetic apply rejection');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

    def change_target_copy_row_without_changing_counts(self) -> None:
        connection = self._open(self.spain_copy)
        try:
            connection.execute(
                "UPDATE users SET username='changed-after-preview' WHERE id=1"
            )
            connection.commit()
        finally:
            connection.close()

    def refresh_spain_copy(self) -> None:
        if self.spain_copy.exists():
            self.spain_copy.unlink()
        shutil.copy2(self.spain_db, self.spain_copy)

    def build_preview(self):
        bot_web = migration_module()
        return bot_web.build_bot_web_migration_preview(
            self.usa_db,
            self.spain_db,
            migration_id="phase13-copy-apply-test",
        )

    def apply(self, preview=None):
        bot_web = migration_module()
        actual_preview = preview or self.build_preview()
        return bot_web.apply_bot_web_migration_to_copy(
            actual_preview,
            source_db=self.usa_db,
            target_copy_db=self.spain_copy,
        )


@pytest.fixture
def migration_fixture(tmp_path: Path) -> MigrationFixture:
    return MigrationFixture(tmp_path)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_preview_preserves_target_spain_invariants_and_excludes_credentials(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()

    preview = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-001",
    )

    assert preview.users_create == 5
    assert preview.users_preserve == 1
    assert preview.users_update == 0
    assert preview.target_privileged_users_preserved == 1
    assert preview.plans_create == 8
    assert preview.orders_create == 8
    assert preview.legacy_devices_external_only == 8
    assert preview.legacy_devices_revoked == 8
    assert preview.spain_devices_preserved == 7
    assert preview.spain_passports_preserved == 7
    assert preview.spain_issuance_requests_preserved == 2
    assert preview.spain_issuance_receipts_preserved == 7
    assert preview.spain_lifecycle_events_preserved == 7
    assert preview.api_tokens_reissue_required == 12
    assert preview.usable_secret_records_imported == 0
    assert preview.apply_allowed is True
    assert preview.stop_reasons == ()


def test_preview_blocks_divergent_plan_id(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    migration_fixture.add_conflicting_target_plan("plan-1")

    preview = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-002",
    )

    assert preview.apply_allowed is False
    assert preview.stop_reasons == ("PLAN_SEMANTIC_CONFLICT",)
    assert preview.conflict_count == 1


def test_preview_blocks_order_without_resolvable_device(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    migration_fixture.break_order_device_mapping()

    preview = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-003",
    )

    assert preview.apply_allowed is False
    assert preview.stop_reasons == ("ORDER_DEVICE_MAPPING_AMBIGUOUS",)
    assert preview.orders_create == 7


def test_preview_blocks_order_whose_device_belongs_to_another_user(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    migration_fixture.mismatch_order_device_owner()

    preview = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-order-owner",
    )

    assert preview.apply_allowed is False
    assert preview.stop_reasons == ("ORDER_DEVICE_OWNER_MISMATCH",)
    assert preview.orders_create == 7


def test_preview_blocks_operator_label_collision_without_overwriting_target(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    migration_fixture.add_operator_label_collision()

    preview = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-operator-label",
    )

    assert preview.apply_allowed is False
    assert preview.stop_reasons == ("USER_OPERATOR_LABEL_CONFLICT",)
    assert preview.users_update == 0


def test_preview_blocks_divergent_message_template(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    migration_fixture.add_conflicting_target_template()

    preview = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-template",
    )

    assert preview.apply_allowed is False
    assert preview.stop_reasons == ("MESSAGE_TEMPLATE_CONFLICT",)


def test_preview_is_deterministic_and_never_changes_input_database_bytes(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    before = {
        path: file_sha256(path)
        for path in (migration_fixture.usa_db, migration_fixture.spain_db)
    }

    first = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-004",
    )
    second = bot_web.build_bot_web_migration_preview(
        migration_fixture.usa_db,
        migration_fixture.spain_db,
        migration_id="phase13-test-004",
    )

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64
    assert {
        path: file_sha256(path)
        for path in (migration_fixture.usa_db, migration_fixture.spain_db)
    } == before


def test_readonly_database_boundary_rejects_write_attempt(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    before = file_sha256(migration_fixture.usa_db)

    with bot_web._readonly_connection(migration_fixture.usa_db) as connection:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("CREATE TABLE forbidden_write(id INTEGER)")

    assert file_sha256(migration_fixture.usa_db) == before


def test_policy_is_immutable_and_excludes_every_secret_bearing_surface() -> None:
    bot_web = migration_module()
    policy = bot_web.MigrationPolicy.default()

    assert policy.allowed_tables == frozenset(
        {"users", "plans", "orders", "devices", "message_templates"}
    )
    assert {
        "api_tokens",
        "servers",
        "server_health_checks",
        "device_enrollment_tickets",
        "email_recovery_tokens",
        "admin_actions",
        "device_traffic_snapshots",
        "ignored_remote_peers",
    } <= policy.excluded_tables
    assert {
        "device_passports",
        "admin_config_issuance_requests",
        "admin_config_issuance_receipts",
        "device_lifecycle_events",
        "access_slot_assignment_requests",
    } <= policy.preserved_target_tables
    with pytest.raises(FrozenInstanceError):
        policy.allowed_tables = frozenset()


def test_apply_to_copy_imports_history_without_resurrecting_config_material(
    migration_fixture: MigrationFixture,
) -> None:
    preview = migration_fixture.build_preview()
    source_before = file_sha256(migration_fixture.usa_db)
    target_before = file_sha256(migration_fixture.spain_db)

    result = migration_fixture.apply(preview)

    assert result.integrity_ok is True
    assert result.foreign_key_issues == 0
    assert result.spain_device_fingerprint_unchanged is True
    assert result.spain_passport_fingerprint_unchanged is True
    assert result.spain_issuance_fingerprints_unchanged is True
    assert result.spain_lifecycle_fingerprint_unchanged is True
    assert result.spain_server_fingerprint_unchanged is True
    assert result.imported_users == 5
    assert result.imported_plans == 8
    assert result.imported_orders == 8
    assert result.imported_legacy_devices == 8
    assert result.imported_message_templates == 1
    assert result.usable_secret_records_imported == 0
    assert file_sha256(migration_fixture.usa_db) == source_before
    assert file_sha256(migration_fixture.spain_db) == target_before

    connection = sqlite3.connect(migration_fixture.spain_copy)
    connection.row_factory = sqlite3.Row
    try:
        assert connection.execute("SELECT count(*) FROM users").fetchone()[0] == 6
        assert connection.execute("SELECT count(*) FROM plans").fetchone()[0] == 8
        assert connection.execute("SELECT count(*) FROM orders").fetchone()[0] == 8
        assert connection.execute("SELECT count(*) FROM devices").fetchone()[0] == 15
        assert connection.execute("SELECT count(*) FROM api_tokens").fetchone()[0] == 0
        assert connection.execute(
            "SELECT is_admin FROM users WHERE telegram_id=1000"
        ).fetchone()[0] == 1
        legacy_rows = connection.execute(
            """
            SELECT status, config_material_status,
                   peer_private_key_encrypted, preshared_key_encrypted,
                   config_fingerprint
            FROM devices WHERE id > 7 ORDER BY id
            """
        ).fetchall()
        assert len(legacy_rows) == 8
        assert {
            (row["status"], row["config_material_status"])
            for row in legacy_rows
        } == {("revoked", "external_only")}
        assert all(row["config_fingerprint"] is None for row in legacy_rows)
        serialized = repr([tuple(row) for row in legacy_rows])
        assert "synthetic-private" not in serialized
        assert "synthetic-psk" not in serialized
    finally:
        connection.close()


def test_apply_to_copy_replay_is_idempotent(
    migration_fixture: MigrationFixture,
) -> None:
    preview = migration_fixture.build_preview()

    first = migration_fixture.apply(preview)
    copy_after_first = file_sha256(migration_fixture.spain_copy)
    second = migration_fixture.apply(preview)

    assert first.created_rows > 0
    assert second.created_rows == 0
    assert second.result_sha256 == first.result_sha256
    assert file_sha256(migration_fixture.spain_copy) == copy_after_first


def test_apply_deletes_copy_when_source_changed_after_preview(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    preview = migration_fixture.build_preview()
    connection = migration_fixture._open(migration_fixture.usa_db)
    try:
        connection.execute(
            "UPDATE message_templates SET text='changed-after-preview' WHERE key='welcome'"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(bot_web.MigrationPreconditionError):
        migration_fixture.apply(preview)

    assert migration_fixture.usa_db.exists()
    assert migration_fixture.spain_db.exists()
    assert not migration_fixture.spain_copy.exists()


def test_apply_deletes_copy_when_target_row_changed_after_preview(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    preview = migration_fixture.build_preview()
    migration_fixture.change_target_copy_row_without_changing_counts()

    with pytest.raises(bot_web.MigrationPreconditionError):
        migration_fixture.apply(preview)

    assert migration_fixture.usa_db.exists()
    assert migration_fixture.spain_db.exists()
    assert not migration_fixture.spain_copy.exists()


def test_apply_rolls_back_and_deletes_copy_on_transaction_failure(
    migration_fixture: MigrationFixture,
) -> None:
    bot_web = migration_module()
    migration_fixture.add_rejecting_target_trigger()
    migration_fixture.refresh_spain_copy()
    preview = migration_fixture.build_preview()

    with pytest.raises(bot_web.MigrationApplyError):
        migration_fixture.apply(preview)

    assert migration_fixture.usa_db.exists()
    assert migration_fixture.spain_db.exists()
    assert not migration_fixture.spain_copy.exists()
