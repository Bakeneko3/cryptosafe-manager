import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Callable, Iterator


SCHEMA_VERSION = 6


class Database:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._lock = RLock()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None,
        )

        self._connection.row_factory = sqlite3.Row
        self._tx_depth = 0

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
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                user_id TEXT NOT NULL,
                entry_id TEXT,
                previous_hash TEXT NOT NULL,
                entry_data BLOB NOT NULL,
                signature TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_public_key (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                public_key TEXT NOT NULL,
                created_at TEXT NOT NULL
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

            CREATE TABLE IF NOT EXISTS shared_entries (
                shared_id TEXT PRIMARY KEY,
                original_entry_id TEXT NOT NULL,
                encryption_method TEXT NOT NULL,
                recipient_info TEXT,
                permissions TEXT,
                shared_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (original_entry_id)
                    REFERENCES vault_entries(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS import_export_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                format TEXT NOT NULL,
                encryption TEXT,
                entry_count INTEGER NOT NULL,
                file_size INTEGER NOT NULL,
                checksum TEXT,
                verification_status TEXT,
                timestamp TEXT NOT NULL,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                identifier TEXT,
                public_key TEXT,
                fingerprint TEXT,
                key_type TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at
                ON vault_entries(created_at);

            CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at
                ON vault_entries(updated_at);

            CREATE INDEX IF NOT EXISTS idx_vault_entries_tags
                ON vault_entries(tags);

            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                ON audit_log(timestamp);

            CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
                ON audit_log(event_type);

            CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id
                ON audit_log(entry_id);

            CREATE INDEX IF NOT EXISTS idx_key_store_key_type
                ON key_store(key_type);

            CREATE INDEX IF NOT EXISTS idx_shared_entries_original
                ON shared_entries(original_entry_id);

            CREATE INDEX IF NOT EXISTS idx_import_export_history_ts
                ON import_export_history(timestamp);

            CREATE INDEX IF NOT EXISTS idx_contacts_fingerprint
                ON contacts(fingerprint);
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
        cursor = connection.cursor()

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

    @staticmethod
    def _migrate_v3_to_v4(connection: sqlite3.Connection) -> None:
        cursor = connection.cursor()

        cursor.execute("DROP INDEX IF EXISTS idx_audit_log_entry_id;")
        cursor.execute("DROP INDEX IF EXISTS idx_audit_log_timestamp;")
        cursor.execute("DROP TABLE IF EXISTS audit_log;")

        cursor.execute(
            """
            CREATE TABLE audit_log (
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                user_id TEXT NOT NULL,
                entry_id TEXT,
                previous_hash TEXT NOT NULL,
                entry_data BLOB NOT NULL,
                signature TEXT NOT NULL
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_public_key (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                public_key TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

        cursor.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
                ON audit_log(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id
                ON audit_log(entry_id);
            """
        )

    @staticmethod
    def _migrate_v4_to_v5(connection: sqlite3.Connection) -> None:
        cursor = connection.cursor()

        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS shared_entries (
                shared_id TEXT PRIMARY KEY,
                original_entry_id TEXT NOT NULL,
                encryption_method TEXT NOT NULL,
                recipient_info TEXT,
                permissions TEXT,
                shared_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (original_entry_id)
                    REFERENCES vault_entries(id)
                    ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS import_export_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                format TEXT NOT NULL,
                encryption TEXT,
                entry_count INTEGER NOT NULL,
                file_size INTEGER NOT NULL,
                checksum TEXT,
                verification_status TEXT,
                timestamp TEXT NOT NULL,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                identifier TEXT,
                public_key TEXT,
                fingerprint TEXT,
                key_type TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_shared_entries_original
                ON shared_entries(original_entry_id);
            CREATE INDEX IF NOT EXISTS idx_import_export_history_ts
                ON import_export_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_contacts_fingerprint
                ON contacts(fingerprint);
            """
        )

    @staticmethod
    def _migrate_v5_to_v6(connection: sqlite3.Connection) -> None:
        """
        Sprint 6 fix: change shared_entries.original_entry_id FK behavior
        from ON DELETE SET NULL to ON DELETE CASCADE. The column is
        NOT NULL, so SET NULL would violate the constraint.

        SQLite cannot ALTER a foreign key, so we rebuild the table.
        """
        cursor = connection.cursor()

        cursor.execute("DROP INDEX IF EXISTS idx_shared_entries_original;")
        cursor.execute("ALTER TABLE shared_entries RENAME TO shared_entries_old;")
        cursor.execute(
            """
            CREATE TABLE shared_entries (
                shared_id TEXT PRIMARY KEY,
                original_entry_id TEXT NOT NULL,
                encryption_method TEXT NOT NULL,
                recipient_info TEXT,
                permissions TEXT,
                shared_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (original_entry_id)
                    REFERENCES vault_entries(id)
                    ON DELETE CASCADE
            );
            """
        )
        cursor.execute(
            """
            INSERT INTO shared_entries
            SELECT * FROM shared_entries_old;
            """
        )
        cursor.execute("DROP TABLE shared_entries_old;")
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_shared_entries_original
                ON shared_entries(original_entry_id);
            """
        )

    _MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
        1: _migrate_v1_to_v2.__func__,
        2: _migrate_v2_to_v3.__func__,
        3: _migrate_v3_to_v4.__func__,
        4: _migrate_v4_to_v5.__func__,
        5: _migrate_v5_to_v6.__func__,
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
    # Transactions (supports nesting via SAVEPOINTs)
    # ------------------------------------------------------------------ #

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            depth = self._tx_depth
            savepoint_name = f"sp_{depth}"

            if depth == 0:
                self._connection.execute("BEGIN;")
            else:
                self._connection.execute(f"SAVEPOINT {savepoint_name};")

            self._tx_depth = depth + 1
            try:
                yield
            except Exception:
                self._tx_depth = depth
                if depth == 0:
                    self._connection.execute("ROLLBACK;")
                else:
                    self._connection.execute(
                        f"ROLLBACK TO SAVEPOINT {savepoint_name};"
                    )
                    self._connection.execute(
                        f"RELEASE SAVEPOINT {savepoint_name};"
                    )
                raise
            else:
                self._tx_depth = depth
                if depth == 0:
                    self._connection.execute("COMMIT;")
                else:
                    self._connection.execute(
                        f"RELEASE SAVEPOINT {savepoint_name};"
                    )

    def execute_in_transaction(self, query: str, parameters: tuple = ()):
        return self._connection.execute(query, parameters)

    def close(self) -> None:
        with self._lock:
            self._connection.close()