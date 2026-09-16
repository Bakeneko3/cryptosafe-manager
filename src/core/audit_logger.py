from datetime import datetime, timezone

from src.core.events import (
    ClipboardCleared,
    ClipboardCopied,
    EntryAdded,
    EntryDeleted,
    EntryUpdated,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
)
from src.database.db import Database


class AuditLogger:
    """Writes application events to the audit_log table."""

    def __init__(self, database: Database, event_bus: EventBus):
        self.database = database
        self.event_bus = event_bus

        self._subscribe()

    def _subscribe(self) -> None:
        self.event_bus.subscribe(EntryAdded, self._handle_entry_added)
        self.event_bus.subscribe(EntryUpdated, self._handle_entry_updated)
        self.event_bus.subscribe(EntryDeleted, self._handle_entry_deleted)

        self.event_bus.subscribe(UserLoggedIn, self._handle_user_logged_in)
        self.event_bus.subscribe(UserLoggedOut, self._handle_user_logged_out)

        self.event_bus.subscribe(ClipboardCopied, self._handle_clipboard_copied)
        self.event_bus.subscribe(ClipboardCleared, self._handle_clipboard_cleared)

    def _write(
        self,
        action: str,
        entry_id: int | None = None,
        details: str | None = None,
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()

        self.database.execute(
            """
            INSERT INTO audit_log (
                action,
                timestamp,
                entry_id,
                details
            )
            VALUES (?, ?, ?, ?)
            """,
            (action, timestamp, entry_id, details),
        )

    def _handle_entry_added(self, event: EntryAdded) -> None:
        self._write("entry_added")

    def _handle_entry_updated(self, event: EntryUpdated) -> None:
        self._write("entry_updated")

    def _handle_entry_deleted(self, event: EntryDeleted) -> None:
        self._write("entry_deleted")

    def _handle_user_logged_in(self, event: UserLoggedIn) -> None:
        self._write("user_logged_in")

    def _handle_user_logged_out(self, event: UserLoggedOut) -> None:
        self._write("user_logged_out")

    def _handle_clipboard_copied(self, event: ClipboardCopied) -> None:
        self._write("clipboard_copied")

    def _handle_clipboard_cleared(self, event: ClipboardCleared) -> None:
        self._write("clipboard_cleared")