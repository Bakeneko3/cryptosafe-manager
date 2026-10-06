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
    assert "deleted_entries" in tables
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
        "encrypted_data",
        "created_at",
        "updated_at",
        "tags",
    ):
        assert expected in columns

    # Sprint 3 replaced the plaintext layout with a single encrypted blob.
    assert "title" not in columns
    assert "username" not in columns
    assert "encrypted_password" not in columns
    assert "url" not in columns
    assert "notes" not in columns


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


# --------------------------------------------------------------------- #
# Version handling
# --------------------------------------------------------------------- #


def test_database_with_newer_version_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "future.db"
    _create_v1_database(db_path)

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


# --------------------------------------------------------------------- #
# v2 -> v3 migration
# --------------------------------------------------------------------- #


def _create_v2_database(db_path: Path) -> None:
    """Create a v2 database with the Sprint 2 schema."""
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
                key_data BLOB,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            PRAGMA user_version = 2;
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_migration_v2_to_v3_updates_version(tmp_path: Path) -> None:
    db_path = tmp_path / "v2.db"
    _create_v2_database(db_path)
    assert _get_user_version(db_path) == 2

    db = Database(db_path)
    db.close()
    assert _get_user_version(db_path) == SCHEMA_VERSION


def test_migration_v2_to_v3_vault_entries_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "v2.db"
    _create_v2_database(db_path)

    db = Database(db_path)
    db.close()

    columns = _table_columns(db_path, "vault_entries")
    assert "id" in columns
    assert "encrypted_data" in columns
    assert "created_at" in columns
    assert "updated_at" in columns
    assert "tags" in columns
    assert "title" not in columns
    assert "username" not in columns
    assert "encrypted_password" not in columns
    assert "url" not in columns
    assert "notes" not in columns


def test_migration_v2_to_v3_creates_deleted_entries(tmp_path: Path) -> None:
    db_path = tmp_path / "v2.db"
    _create_v2_database(db_path)

    db = Database(db_path)
    db.close()

    tables = _table_names(db_path)
    assert "deleted_entries" in tables

    columns = _table_columns(db_path, "deleted_entries")
    assert "id" in columns
    assert "encrypted_data" in columns
    assert "deleted_at" in columns
    assert "expires_at" in columns


def test_migration_v2_to_v3_audit_log_entry_id_is_text(tmp_path: Path) -> None:
    db_path = tmp_path / "v2.db"
    _create_v2_database(db_path)

    db = Database(db_path)
    db.close()

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("PRAGMA table_info(audit_log);").fetchall()
    finally:
        conn.close()

    entry_id_col = [row for row in rows if row[1] == "entry_id"][0]
    assert entry_id_col[2] == "TEXT"


# --------------------------------------------------------------------- #
# v3 -> v4 migration
# --------------------------------------------------------------------- #


def _create_v3_database(db_path: Path) -> None:
    """Create a v3 database with the Sprint 3 schema."""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT
            );

            CREATE TABLE deleted_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                deleted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                entry_id TEXT,
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
                key_data BLOB,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            PRAGMA user_version = 3;
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_migration_v3_to_v4_updates_version(tmp_path: Path) -> None:
    db_path = tmp_path / "v3.db"
    _create_v3_database(db_path)
    assert _get_user_version(db_path) == 3

    db = Database(db_path)
    db.close()
    assert _get_user_version(db_path) == SCHEMA_VERSION


def test_migration_v3_to_v4_audit_log_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "v3.db"
    _create_v3_database(db_path)

    db = Database(db_path)
    db.close()

    cols = _table_columns(db_path, "audit_log")
    for expected in (
        "sequence_number",
        "timestamp",
        "event_type",
        "severity",
        "source",
        "user_id",
        "entry_id",
        "previous_hash",
        "entry_data",
        "signature",
    ):
        assert expected in cols

    # Old columns must be gone.
    assert "action" not in cols
    assert "details" not in cols


def test_migration_v3_to_v4_creates_public_key_table(tmp_path: Path) -> None:
    db_path = tmp_path / "v3.db"
    _create_v3_database(db_path)

    db = Database(db_path)
    db.close()

    tables = _table_names(db_path)
    assert "audit_public_key" in tables

    cols = _table_columns(db_path, "audit_public_key")
    assert "id" in cols
    assert "public_key" in cols
    assert "created_at" in cols


def test_migration_v3_to_v4_drops_old_audit_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "v3.db"
    _create_v3_database(db_path)

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO audit_log (action, timestamp, entry_id, details)
            VALUES (?, ?, ?, ?)
            """,
            ("entry_created", "2024-01-01", "abc", None),
        )
        conn.commit()
    finally:
        conn.close()

    db = Database(db_path)
    rows = db.fetch_all("SELECT * FROM audit_log")
    db.close()

    # Old rows are dropped, not migrated.
    assert len(rows) == 0


def test_migration_v3_to_v4_indexes_present(tmp_path: Path) -> None:
    db_path = tmp_path / "v3.db"
    _create_v3_database(db_path)

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
    assert "idx_audit_log_timestamp" in names
    assert "idx_audit_log_event_type" in names
    assert "idx_audit_log_entry_id" in names