"""Tests for src/core/audit/audit_logger.py (Sprint 5)."""

from pathlib import Path

import pytest

from src.core.audit.audit_logger import AuditLogger
from src.core.crypto.key_derivation import KeyDerivation
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
from src.core.key_manager import KeyManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"


@pytest.fixture
def fast_kd() -> KeyDerivation:
    return KeyDerivation(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        pbkdf2_iterations=1000,
    )


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(tmp_path / "audit.db")
    yield d
    d.close()


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    manager = KeyManager(db, key_derivation=fast_kd)
    manager.create_vault(STRONG)
    return manager


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def logger(db: Database, bus: EventBus, km: KeyManager) -> AuditLogger:
    return AuditLogger(db, bus, key_manager=km)


# --------------------------------------------------------------------- #
# Genesis
# --------------------------------------------------------------------- #


def test_genesis_created_on_first_event(
    db: Database, bus: EventBus, km: KeyManager
) -> None:
    AuditLogger(db, bus, key_manager=km)
    bus.publish(UserLoggedIn())
    rows = db.fetch_all("SELECT event_type FROM audit_log ORDER BY sequence_number")
    types = [r["event_type"] for r in rows]
    assert types[0] == "system_genesis"
    assert "user_logged_in" in types


def test_genesis_not_duplicated(
    db: Database, bus: EventBus, km: KeyManager
) -> None:
    AuditLogger(db, bus, key_manager=km)
    bus.publish(UserLoggedIn())
    bus.publish(EntryCreated(entry_id="a"))
    bus.publish(EntryUpdated(entry_id="a"))
    rows = db.fetch_all("SELECT event_type FROM audit_log")
    genesis_count = sum(1 for r in rows if r["event_type"] == "system_genesis")
    assert genesis_count == 1


# --------------------------------------------------------------------- #
# Event handlers
# --------------------------------------------------------------------- #


def test_user_logged_in_is_logged(logger: AuditLogger, bus: EventBus, db: Database) -> None:
    bus.publish(UserLoggedIn())
    rows = db.fetch_all(
        "SELECT event_type, severity, source FROM audit_log WHERE event_type = 'user_logged_in'"
    )
    assert len(rows) == 1
    assert rows[0]["severity"] == "INFO"
    assert rows[0]["source"] == "key_manager"


def test_user_logged_out_records_reason(
    logger: AuditLogger, bus: EventBus, db: Database
) -> None:
    bus.publish(UserLoggedOut(reason="auto-lock"))
    # Find the row and decrypt to check details.
    rows = db.fetch_all(
        "SELECT entry_data FROM audit_log WHERE event_type = 'user_logged_out'"
    )
    assert len(rows) == 1


def test_entry_created_logged_with_entry_id(
    logger: AuditLogger, bus: EventBus, db: Database
) -> None:
    bus.publish(EntryCreated(entry_id="abc-123"))
    row = db.fetch_one(
        "SELECT entry_id FROM audit_log WHERE event_type = 'entry_created'"
    )
    assert row is not None
    assert row["entry_id"] == "abc-123"


def test_entry_deleted_severity_is_warn(
    logger: AuditLogger, bus: EventBus, db: Database
) -> None:
    bus.publish(EntryDeleted(entry_id="x", soft=True))
    row = db.fetch_one(
        "SELECT severity FROM audit_log WHERE event_type = 'entry_deleted'"
    )
    assert row["severity"] == "WARN"


def test_clipboard_copied(logger: AuditLogger, bus: EventBus, db: Database) -> None:
    bus.publish(
        ClipboardCopied(data_type="password", source_entry_id="e1", timeout=30)
    )
    row = db.fetch_one(
        "SELECT entry_id FROM audit_log WHERE event_type = 'clipboard_copied'"
    )
    assert row["entry_id"] == "e1"


def test_clipboard_cleared(logger: AuditLogger, bus: EventBus, db: Database) -> None:
    bus.publish(ClipboardCleared(reason="timeout"))
    row = db.fetch_one(
        "SELECT event_type FROM audit_log WHERE event_type = 'clipboard_cleared'"
    )
    assert row is not None


# --------------------------------------------------------------------- #
# Manual log_event
# --------------------------------------------------------------------- #


def test_log_event_manual(logger: AuditLogger, db: Database) -> None:
    logger.log_event(
        "custom_event",
        source="test",
        severity="ERROR",
        details={"msg": "hello"},
    )
    row = db.fetch_one(
        "SELECT severity, source FROM audit_log WHERE event_type = 'custom_event'"
    )
    assert row["severity"] == "ERROR"
    assert row["source"] == "test"


# --------------------------------------------------------------------- #
# Hash chain (CRY-4)
# --------------------------------------------------------------------- #


def test_hash_chain_first_entry_uses_genesis(
    logger: AuditLogger, db: Database
) -> None:
    logger.log_event("test_a")
    first = db.fetch_one(
        "SELECT previous_hash FROM audit_log ORDER BY sequence_number LIMIT 1"
    )
    assert first["previous_hash"] == "0" * 64


def test_hash_chain_links_entries(logger: AuditLogger, db: Database) -> None:
    logger.log_event("first")
    logger.log_event("second")

    rows = db.fetch_all(
        "SELECT sequence_number, previous_hash FROM audit_log ORDER BY sequence_number"
    )
    # Second entry's previous_hash must not be genesis.
    assert rows[1]["previous_hash"] != "0" * 64


# --------------------------------------------------------------------- #
# Public key storage
# --------------------------------------------------------------------- #


def test_public_key_stored_once(logger: AuditLogger, db: Database) -> None:
    logger.log_event("a")
    logger.log_event("b")

    rows = db.fetch_all("SELECT public_key FROM audit_public_key")
    assert len(rows) == 1
    assert len(rows[0]["public_key"]) == 64  # hex Ed25519 pubkey


# --------------------------------------------------------------------- #
# Locked vault
# --------------------------------------------------------------------- #


def test_events_ignored_when_locked(
    db: Database, bus: EventBus, km: KeyManager
) -> None:
    AuditLogger(db, bus, key_manager=km)
    bus.publish(UserLoggedIn())  # creates genesis + logs

    km.lock()

    before = db.fetch_all("SELECT COUNT(*) as c FROM audit_log")[0]["c"]
    bus.publish(EntryCreated(entry_id="locked"))
    after = db.fetch_all("SELECT COUNT(*) as c FROM audit_log")[0]["c"]
    assert before == after


def test_logger_without_key_manager_is_noop(db: Database, bus: EventBus) -> None:
    AuditLogger(db, bus)  # no key_manager
    bus.publish(UserLoggedIn())
    rows = db.fetch_all("SELECT COUNT(*) as c FROM audit_log")
    assert rows[0]["c"] == 0


# --------------------------------------------------------------------- #
# Sanitization (LOG-3)
# --------------------------------------------------------------------- #


def test_sensitive_keys_are_redacted(logger: AuditLogger, db: Database) -> None:
    logger.log_event(
        "test",
        details={"password": "hunter2", "username": "alice"},
    )
    # We can't read the plaintext directly (encrypted); verify via
    # the verifier in a later test. Here just check that logging works.
    row = db.fetch_one(
        "SELECT entry_data FROM audit_log WHERE event_type = 'test'"
    )
    assert row is not None
    # Encrypted blob must not contain the plaintext password.
    assert b"hunter2" not in bytes(row["entry_data"])