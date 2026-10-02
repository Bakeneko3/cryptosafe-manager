import sqlite3
from pathlib import Path

import pytest

from src.database.db import Database, SCHEMA_VERSION


def _get_user_version(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("PRAGMA user_version;").fetchone()[0]
    finally:
        conn.close()


def _table_columns(db_path: Path, table: str) -> list[str]:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
        return [row[1] for row in rows]
    finally:
        conn.close()


def _table_names(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table';"
        ).fetchall()
        return {row[0] for row in rows}
    finally:
        conn.close()


# --------------------------------------------------------------------- #
# Fresh database
# --------------------------------------------------------------------- #


def test_fresh_database_has_current_version(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"
    db = Database(db_path)
    db.close()

    assert _get_user_version(db_path) == SCHEMA_VERSION


def test_fresh_database_has_all_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"
    db = Database(db_path)
    db.close()

    tables = _table_names(db_path)
    assert "vault_entries" in tables
    assert "audit_log" in tables
    assert "settings" in tables
    assert "key_store" in tables


def test_fresh_database_has_vault_entries_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"
    db = Database(db_path)
    db.close()

    columns = _table_columns(db_path, "vault_entries")
    for expected in (
        "id",
        "title",
        "username",
        "encrypted_password",
        "url",
        "notes",
        "created_at",
        "updated_at",
        "tags",
    ):
        assert expected in columns


# --------------------------------------------------------------------- #
# Migration from v1
# --------------------------------------------------------------------- #


def _create_v1_database(db_path: Path) -> None:
    """Create a bare-bones v1 database, mimicking Sprint 1 output."""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                url TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT
            );

            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                entry_id INTEGER,
                details TEXT,
                signature BLOB
            );

            CREATE TABLE settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT NOT NULL UNIQUE,
                setting_value BLOB,
                encrypted INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                salt BLOB,
                hash BLOB,
                params TEXT
            );

            PRAGMA user_version = 1;
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_migration_from_v1_updates_version(tmp_path: Path) -> None:
    db_path = tmp_path / "v1.db"
    _create_v1_database(db_path)

    assert _get_user_version(db_path) == 1

    db = Database(db_path)
    db.close()

    assert _get_user_version(db_path) == SCHEMA_VERSION


def test_migration_from_v1_preserves_data(tmp_path: Path) -> None:
    db_path = tmp_path / "v1.db"
    _create_v1_database(db_path)

    # Insert a row into the v1 database.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO vault_entries
                (title, username, encrypted_password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("Example", "user", b"\x00\x01\x02", "2024-01-01", "2024-01-01"),
        )
        conn.commit()
    finally:
        conn.close()

    # Run migrations.
    db = Database(db_path)
    rows = db.fetch_all("SELECT title, username FROM vault_entries;")
    db.close()

    assert len(rows) == 1
    assert rows[0]["title"] == "Example"
    assert rows[0]["username"] == "user"


# --------------------------------------------------------------------- #
# Version handling
# --------------------------------------------------------------------- #


def test_database_with_newer_version_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "future.db"
    _create_v1_database(db_path)

    # Bump version far into the future.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 5};")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(RuntimeError, match="newer than"):
        Database(db_path)


# --------------------------------------------------------------------- #
# key_store schema (v2)
# --------------------------------------------------------------------- #


def test_fresh_key_store_has_v2_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"
    db = Database(db_path)
    db.close()

    columns = _table_columns(db_path, "key_store")
    assert "key_type" in columns
    assert "key_data" in columns
    assert "version" in columns
    assert "created_at" in columns
    # v1 columns should be gone
    assert "salt" not in columns
    assert "hash" not in columns
    assert "params" not in columns


def test_migration_v1_to_v2_rebuilds_key_store(tmp_path: Path) -> None:
    db_path = tmp_path / "v1.db"
    _create_v1_database(db_path)

    db = Database(db_path)
    db.close()

    columns = _table_columns(db_path, "key_store")
    assert "key_type" in columns
    assert "key_data" in columns
    assert "version" in columns
    assert "created_at" in columns
    assert "salt" not in columns
    assert "hash" not in columns
    assert "params" not in columns


def test_migration_v1_to_v2_preserves_key_store_data(tmp_path: Path) -> None:
    db_path = tmp_path / "v1.db"
    _create_v1_database(db_path)

    # Insert a legacy row using the v1 shape.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO key_store (key_type, salt, hash, params)
            VALUES (?, ?, ?, ?)
            """,
            ("auth_hash", b"salt_bytes", b"hash_bytes", None),
        )
        conn.commit()
    finally:
        conn.close()

    db = Database(db_path)
    rows = db.fetch_all("SELECT key_type, key_data, version FROM key_store;")
    db.close()

    assert len(rows) == 1
    assert rows[0]["key_type"] == "auth_hash"
    # Migration maps hash -> key_data (hash takes priority).
    assert rows[0]["key_data"] == b"hash_bytes"
    assert rows[0]["version"] == 1


def test_migration_v1_to_v2_falls_back_to_salt(tmp_path: Path) -> None:
    db_path = tmp_path / "v1.db"
    _create_v1_database(db_path)

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO key_store (key_type, salt, hash, params)
            VALUES (?, ?, ?, ?)
            """,
            ("enc_salt", b"salt_only", None, None),
        )
        conn.commit()
    finally:
        conn.close()

    db = Database(db_path)
    rows = db.fetch_all("SELECT key_data FROM key_store;")
    db.close()

    assert rows[0]["key_data"] == b"salt_only"


def test_key_store_index_survives_migration(tmp_path: Path) -> None:
    db_path = tmp_path / "v1.db"
    _create_v1_database(db_path)

    db = Database(db_path)
    db.close()

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    finally:
        conn.close()

    names = {row[0] for row in rows}
    assert "idx_key_store_key_type" in names