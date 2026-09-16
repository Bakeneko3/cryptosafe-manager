from src.core.audit_logger import AuditLogger
from src.core.events import EntryAdded, UserLoggedIn, EventBus
from src.database.db import Database


def test_audit_logger_writes_events(tmp_path):
    db = Database(tmp_path / "test.db")
    event_bus = EventBus()

    AuditLogger(db, event_bus)

    event_bus.publish(UserLoggedIn())
    event_bus.publish(EntryAdded())

    rows = db.fetch_all(
        """
        SELECT action
        FROM audit_log
        ORDER BY id
        """
    )

    assert [row["action"] for row in rows] == [
        "user_logged_in",
        "entry_added",
    ]

    db.close()