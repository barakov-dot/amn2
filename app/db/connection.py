import sqlite3
from pathlib import Path


def connect(path: str | Path) -> sqlite3.Connection:
    database_path = Path(path)
    if str(database_path) != ":memory:":
        database_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def connect_read_only(path: str | Path) -> sqlite3.Connection:
    database_path = Path(path).resolve()
    conn = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA query_only = ON")
    return conn
