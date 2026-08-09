import sqlite3

import pytest

from app.db.schema import initialize_schema
from tests.db.test_phase13_protocol_schema import assert_phase13_protocol_schema


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def test_phase14_schema_keeps_protocol_and_migration_foundations(conn):
    initialize_schema(conn)
    initialize_schema(conn)
    names = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
        )
    }
    assert "legacy_migration_records" in names
    assert "idx_legacy_migration_records_migration" in names
    assert_phase13_protocol_schema(conn)
