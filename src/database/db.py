import sqlite3
from pathlib import Path
from threading import Lock
from typing import Callable


SCHEMA_VERSION = 2


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
                # Fresh database: create the current schema directly.
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

            # Existing database: apply pending migrations in order.
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

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                entry_id INTEGER,
                details TEXT,
                signature BLOB,
                FOREIGN KEY (entry_id)
                    REFERENCES vault_entries(id)
                    ON DELETE SET NULL
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

            CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id
                ON audit_log(entry_id);

            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                ON audit_log(timestamp);

            CREATE INDEX IF NOT EXISTS idx_vault_entries_title
                ON vault_entries(title);

            CREATE INDEX IF NOT EXISTS idx_vault_entries_tags
                ON vault_entries(tags);

            CREATE INDEX IF NOT EXISTS idx_key_store_key_type
                ON key_store(key_type);
            """
        )

    # ------------------------------------------------------------------ #
    # Migration registry
    # ------------------------------------------------------------------ #

    @staticmethod
    def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
        """
        Sprint 2 migration.

        Rebuilds key_store with the new schema required by Sprint 2:
          v1: id, key_type, salt, hash, params
          v2: id, key_type, key_data, version, created_at

        Existing rows (if any) are preserved by mapping:
          key_type  -> key_type
          hash/salt/params (first non-null) -> key_data
          version   -> 1
          created_at -> current timestamp

        SQLite does not support DROP COLUMN on older versions, so we
        rebuild the table following the standard 4-step pattern.
        """
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

    _MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
        1: _migrate_v1_to_v2.__func__,
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

    def close(self) -> None:
        with self._lock:
            self._connection.close()