import sqlite3

import pytest

from app.db.schema import initialize_schema


def test_initialize_schema_creates_idempotent_legacy_migration_ledger() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        initialize_schema(connection)
        initialize_schema(connection)

        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(legacy_migration_records)"
            )
        ]
        assert columns == [
            "migration_id",
            "source_table",
            "source_row_sha256",
            "target_row_id",
            "created_at",
        ]
        values = ("migration-1", "users", "a" * 64, "target-1")
        connection.execute(
            """
            INSERT INTO legacy_migration_records(
                migration_id, source_table, source_row_sha256, target_row_id
            ) VALUES (?, ?, ?, ?)
            """,
            values,
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO legacy_migration_records(
                    migration_id, source_table, source_row_sha256, target_row_id
                ) VALUES (?, ?, ?, ?)
                """,
                values,
            )
    finally:
        connection.close()
