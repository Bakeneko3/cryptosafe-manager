import json

from src.database.db import Database


class SettingsManager:
    def __init__(self, database: Database):
        self.database = database

    def set(self, key: str, value, encrypted: bool = False) -> None:
        serialized = json.dumps(value)

        self.database.execute(
            """
            INSERT INTO settings (setting_key, setting_value, encrypted)
            VALUES (?, ?, ?)
            ON CONFLICT(setting_key)
            DO UPDATE SET
                setting_value = excluded.setting_value,
                encrypted = excluded.encrypted
            """,
            (key, serialized.encode("utf-8"), int(encrypted)),
        )

    def get(self, key: str, default=None):
        row = self.database.fetch_one(
            """
            SELECT setting_value, encrypted
            FROM settings
            WHERE setting_key = ?
            """,
            (key,),
        )

        if row is None:
            return default

        try:
            return json.loads(row["setting_value"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return default

    def get_all(self) -> dict:
        rows = self.database.fetch_all(
            """
            SELECT setting_key, setting_value
            FROM settings
            """
        )

        result = {}

        for row in rows:
            try:
                result[row["setting_key"]] = json.loads(
                    row["setting_value"].decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue

        return result