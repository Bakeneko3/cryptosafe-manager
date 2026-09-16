import sqlite3

from src.database.db import Database, SCHEMA_VERSION


def test_database_creates_schema(tmp_path):
    db_path = tmp_path / "test.db"

    db = Database(db_path)

    assert db_path.exists()

    version = db.fetch_one("PRAGMA user_version;")[0]
    assert version == SCHEMA_VERSION

    tables = db.fetch_all(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name;
        """
    )

    table_names = {row["name"] for row in tables}

    assert "vault_entries" in table_names
    assert "audit_log" in table_names
    assert "settings" in table_names
    assert "key_store" in table_names

    db.close()