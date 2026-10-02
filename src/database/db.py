import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Callable, Iterator


SCHEMA_VERSION = 3


class Database:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._lock = Lock()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
        )

        self._connection.row_factory = sqlite3.Row

        self._initialize()

    # ------------------------------------------------------------------ #
    # Initialization & migrations
    # ------------------------------------------------------------------ #

    def _initialize(self) -> None:
        with self._lock:
            cursor = self._connection.cursor()

            cursor.execute("PRAGMA foreign_keys = ON;")

            cursor.execute("PRAGMA user_version;")
            version = cursor.fetchone()[0]

            if version == 0:
                self._create_schema()
                self._set_user_version(SCHEMA_VERSION)
                self._connection.commit()
                return

            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema version {version} is newer than "
                    f"supported version {SCHEMA_VERSION}. "
                    "Please upgrade the application."
                )

            while version < SCHEMA_VERSION:
                migration = self._MIGRATIONS.get(version)
                if migration is None:
                    raise RuntimeError(
                        f"No migration path from version {version} "
                        f"to {SCHEMA_VERSION}."
                    )
                migration(self._connection)
                version += 1
                self._set_user_version(version)

            self._connection.commit()

    def _set_user_version(self, version: int) -> None:
        self._connection.execute(f"PRAGMA user_version = {int(version)};")

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT
            );

            CREATE TABLE IF NOT EXISTS deleted_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                deleted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                entry_id TEXT,
                details TEXT,
                signature BLOB
            );

            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT NOT NULL UNIQUE,
                setting_value BLOB,
                encrypted INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_data BLOB,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at
                ON vault_entries(created_at);

            CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at
                ON vault_entries(updated_at);

            CREATE INDEX IF NOT EXISTS idx_vault_entries_tags
                ON vault_entries(tags);

            CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id
                ON audit_log(entry_id);

            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                ON audit_log(timestamp);

            CREATE INDEX IF NOT EXISTS idx_key_store_key_type
                ON key_store(key_type);
            """
        )

    # ------------------------------------------------------------------ #
    # Migration registry
    # ------------------------------------------------------------------ #

    @staticmethod
    def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
        cursor = connection.cursor()

        cursor.executescript(
            """
            CREATE TABLE key_store_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_data BLOB,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )

        cursor.execute(
            """
            INSERT INTO key_store_new (key_type, key_data, version)
            SELECT
                key_type,
                COALESCE(hash, salt, CAST(params AS BLOB)),
                1
            FROM key_store;
            """
        )

        cursor.execute("DROP TABLE key_store;")
        cursor.execute("ALTER TABLE key_store_new RENAME TO key_store;")

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_key_store_key_type
                ON key_store(key_type);
            """
        )

    @staticmethod
    def _migrate_v2_to_v3(connection: sqlite3.Connection) -> None:
        """
        Sprint 3 migration.

        Rebuilds vault_entries with the new per-entry AES-GCM layout
        (id: TEXT/UUID, encrypted_data: BLOB) and changes
        audit_log.entry_id to TEXT.

        Any existing rows in vault_entries are dropped: the Sprint 1/2
        placeholder format is not compatible with the new AES-GCM
        envelope, and no real user data exists yet (CRUD was not
        implemented before Sprint 3).
        """
        cursor = connection.cursor()

        # Drop and rebuild vault_entries.
        cursor.execute("DROP TABLE IF EXISTS vault_entries;")
        cursor.execute(
            """
            CREATE TABLE vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT
            );
            """
        )

        # Soft-delete table.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS deleted_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                deleted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            """
        )

        # audit_log.entry_id changes from INTEGER to TEXT. SQLite cannot
        # ALTER COLUMN TYPE, so rebuild it.
        cursor.execute("DROP INDEX IF EXISTS idx_audit_log_entry_id;")
        cursor.execute("DROP INDEX IF EXISTS idx_audit_log_timestamp;")
        cursor.execute("ALTER TABLE audit_log RENAME TO audit_log_old;")
        cursor.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                entry_id TEXT,
                details TEXT,
                signature BLOB
            );
            """
        )
        cursor.execute(
            """
            INSERT INTO audit_log (id, action, timestamp, entry_id, details, signature)
            SELECT id, action, timestamp, entry_id, details, signature
            FROM audit_log_old;
            """
        )
        cursor.execute("DROP TABLE audit_log_old;")

        # Recreate indexes for the new schema.
        cursor.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at
                ON vault_entries(created_at);
            CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at
                ON vault_entries(updated_at);
            CREATE INDEX IF NOT EXISTS idx_vault_entries_tags
                ON vault_entries(tags);
            CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id
                ON audit_log(entry_id);
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                ON audit_log(timestamp);
            """
        )

    _MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
        1: _migrate_v1_to_v2.__func__,
        2: _migrate_v2_to_v3.__func__,
    }

    # ------------------------------------------------------------------ #
    # Query helpers
    # ------------------------------------------------------------------ #

    def execute(self, query: str, parameters: tuple = ()):
        with self._lock:
            cursor = self._connection.execute(query, parameters)
            self._connection.commit()
            return cursor

    def fetch_all(self, query: str, parameters: tuple = ()):
        with self._lock:
            cursor = self._connection.execute(query, parameters)
            return cursor.fetchall()

    def fetch_one(self, query: str, parameters: tuple = ()):
        with self._lock:
            cursor = self._connection.execute(query, parameters)
            return cursor.fetchone()

    # ------------------------------------------------------------------ #
    # Transactions
    # ------------------------------------------------------------------ #

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            try:
                self._connection.execute("BEGIN;")
            except sqlite3.OperationalError:
                pass
            try:
                yield
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def execute_in_transaction(self, query: str, parameters: tuple = ()):
        return self._connection.execute(query, parameters)

    def close(self) -> None:
        with self._lock:
            self._connection.close()