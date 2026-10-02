import sqlite3
from pathlib import Path
from threading import Lock


SCHEMA_VERSION = 1


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

    def _initialize(self) -> None:
        with self._lock:
            cursor = self._connection.cursor()

            cursor.execute("PRAGMA foreign_keys = ON;")

            cursor.execute("PRAGMA user_version;")
            version = cursor.fetchone()[0]

            if version == 0:
                self._create_schema()
                cursor.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")

            self._connection.commit()

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
                salt BLOB,
                hash BLOB,
                params TEXT
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