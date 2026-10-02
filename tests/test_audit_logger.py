"""Tests for src/core/audit_logger.py."""

from src.core.audit_logger import AuditLogger
from src.core.events import (
    ClipboardCleared,
    ClipboardCopied,
    EntryCreated,
    EntryDeleted,
    EntryUpdated,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
)
from src.database.db import Database


def test_audit_logger_writes_user_and_entry_events(tmp_path):
    db = Database(tmp_path / "test.db")
    event_bus = EventBus()

    AuditLogger(db, event_bus)

    event_bus.publish(UserLoggedIn())
    event_bus.publish(EntryCreated(entry_id="abc"))

    rows = db.fetch_all(
        """
        SELECT action, entry_id
        FROM audit_log
        ORDER BY id
        """
    )

    assert [row["action"] for row in rows] == [
        "user_logged_in",
        "entry_created",
    ]
    assert rows[1]["entry_id"] == "abc"

    db.close()


def test_audit_logger_entry_updated(tmp_path):
    db = Database(tmp_path / "test.db")
    bus = EventBus()
    AuditLogger(db, bus)

    bus.publish(EntryUpdated(entry_id="xyz"))

    rows = db.fetch_all("SELECT action, entry_id FROM audit_log")
    assert len(rows) == 1
    assert rows[0]["action"] == "entry_updated"
    assert rows[0]["entry_id"] == "xyz"

    db.close()


def test_audit_logger_entry_deleted_soft(tmp_path):
    db = Database(tmp_path / "test.db")
    bus = EventBus()
    AuditLogger(db, bus)

    bus.publish(EntryDeleted(entry_id="abc", soft=True))

    rows = db.fetch_all("SELECT action, entry_id, details FROM audit_log")
    assert rows[0]["action"] == "entry_deleted"
    assert rows[0]["entry_id"] == "abc"
    assert "soft=True" in rows[0]["details"]

    db.close()


def test_audit_logger_user_logged_out_reason(tmp_path):
    db = Database(tmp_path / "test.db")
    bus = EventBus()
    AuditLogger(db, bus)

    bus.publish(UserLoggedOut(reason="auto-lock"))

    rows = db.fetch_all("SELECT action, details FROM audit_log")
    assert rows[0]["action"] == "user_logged_out"
    assert "reason=auto-lock" in rows[0]["details"]

    db.close()


def test_audit_logger_clipboard_events(tmp_path):
    db = Database(tmp_path / "test.db")
    bus = EventBus()
    AuditLogger(db, bus)

    bus.publish(ClipboardCopied())
    bus.publish(ClipboardCleared())

    rows = db.fetch_all("SELECT action FROM audit_log ORDER BY id")
    assert [row["action"] for row in rows] == [
        "clipboard_copied",
        "clipboard_cleared",
    ]

    db.close()


def test_audit_logger_unsubscribes_safely(tmp_path):
    """Multiple AuditLogger instances must not corrupt each other."""
    db = Database(tmp_path / "test.db")
    bus = EventBus()
    AuditLogger(db, bus)
    AuditLogger(db, bus)  # second logger

    bus.publish(UserLoggedIn())

    rows = db.fetch_all("SELECT action FROM audit_log")
    # Two loggers subscribed → two rows.
    assert len(rows) == 2
    assert all(r["action"] == "user_logged_in" for r in rows)

    db.close()