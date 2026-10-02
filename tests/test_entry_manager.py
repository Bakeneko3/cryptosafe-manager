"""Tests for src/core/vault/entry_manager.py (step 5a: create_entry)."""

from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.events import EntryCreated, EntryDeleted, EntryUpdated, EventBus
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import (
    VaultOperationError,
    VaultValidationError,
    EntryManager,
)
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
    d = Database(tmp_path / "vault.db")
    yield d
    d.close()


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    manager = KeyManager(db, key_derivation=fast_kd)
    manager.create_vault(STRONG)
    return manager


@pytest.fixture
def em(db: Database, km: KeyManager) -> EntryManager:
    return EntryManager(db, km)


SAMPLE = {
    "title": "Example",
    "username": "user@example.com",
    "password": "s3cr3t-p@ss",
    "url": "https://example.com",
    "notes": "some notes",
    "category": "Work",
}


# --------------------------------------------------------------------- #
# create_entry — happy path
# --------------------------------------------------------------------- #


def test_create_entry_returns_uuid(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    assert isinstance(entry_id, str)
    # UUID v4 string
    assert len(entry_id) == 36
    assert entry_id.count("-") == 4


def test_create_entry_persists_row(em: EntryManager, db: Database) -> None:
    entry_id = em.create_entry(SAMPLE)
    row = db.fetch_one(
        "SELECT id, encrypted_data, tags FROM vault_entries WHERE id = ?",
        (entry_id,),
    )
    assert row is not None
    assert row["id"] == entry_id
    assert isinstance(row["encrypted_data"], (bytes, bytearray))
    assert len(row["encrypted_data"]) > 28  # nonce(12) + tag(16) + something


def test_create_entry_blob_is_not_plaintext(em: EntryManager, db: Database) -> None:
    em.create_entry(SAMPLE)
    row = db.fetch_one("SELECT encrypted_data FROM vault_entries LIMIT 1")
    blob = bytes(row["encrypted_data"])
    # The plaintext password must not appear in the ciphertext.
    assert b"s3cr3t-p@ss" not in blob
    assert b"Example" not in blob


def test_create_entry_publishes_event(db: Database, km: KeyManager) -> None:
    bus = EventBus()
    received = []
    bus.subscribe(EntryCreated, lambda e: received.append(e))

    em = EntryManager(db, km, event_bus=bus)
    entry_id = em.create_entry(SAMPLE)

    assert len(received) == 1
    assert received[0].entry_id == entry_id


def test_create_entry_without_event_bus_is_ok(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    assert isinstance(entry_id, str)


def test_create_entry_tags_string(em: EntryManager, db: Database) -> None:
    em.create_entry({**SAMPLE, "tags": "work,important"})
    row = db.fetch_one("SELECT tags FROM vault_entries LIMIT 1")
    assert row["tags"] == "work,important"


def test_create_entry_tags_list_is_joined(em: EntryManager, db: Database) -> None:
    em.create_entry({**SAMPLE, "tags": ["work", "important"]})
    row = db.fetch_one("SELECT tags FROM vault_entries LIMIT 1")
    assert row["tags"] == "work,important"


def test_create_entry_unicode(em: EntryManager) -> None:
    entry_id = em.create_entry({**SAMPLE, "title": "Привет 🎉", "notes": "你好"})
    assert entry_id


# --------------------------------------------------------------------- #
# create_entry — validation
# --------------------------------------------------------------------- #


def test_create_entry_missing_title(em: EntryManager) -> None:
    with pytest.raises(VaultValidationError):
        em.create_entry({**SAMPLE, "title": ""})


def test_create_entry_missing_password(em: EntryManager) -> None:
    with pytest.raises(VaultValidationError):
        em.create_entry({**SAMPLE, "password": ""})


def test_create_entry_non_dict_raises(em: EntryManager) -> None:
    with pytest.raises(VaultValidationError):
        em.create_entry("not a dict")  # type: ignore[arg-type]


def test_create_entry_whitespace_title(em: EntryManager) -> None:
    with pytest.raises(VaultValidationError):
        em.create_entry({**SAMPLE, "title": "   "})


# --------------------------------------------------------------------- #
# create_entry — locked vault
# --------------------------------------------------------------------- #


def test_create_entry_fails_when_locked(em: EntryManager, km: KeyManager) -> None:
    km.lock()
    with pytest.raises(VaultOperationError):
        em.create_entry(SAMPLE)


# --------------------------------------------------------------------- #
# get_entry
# --------------------------------------------------------------------- #


def test_get_entry_roundtrip(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    loaded = em.get_entry(entry_id)

    assert loaded["id"] == entry_id
    assert loaded["title"] == SAMPLE["title"]
    assert loaded["username"] == SAMPLE["username"]
    assert loaded["password"] == SAMPLE["password"]
    assert loaded["url"] == SAMPLE["url"]
    assert loaded["notes"] == SAMPLE["notes"]
    assert loaded["category"] == SAMPLE["category"]
    assert loaded["version"] == 1
    assert "created_at" in loaded
    assert "updated_at" in loaded


def test_get_entry_with_tags(em: EntryManager) -> None:
    entry_id = em.create_entry({**SAMPLE, "tags": "work,important"})
    loaded = em.get_entry(entry_id)
    assert loaded["tags"] == "work,important"


def test_get_entry_unknown_id_raises(em: EntryManager) -> None:
    with pytest.raises(VaultOperationError):
        em.get_entry("no-such-id")


def test_get_entry_error_does_not_leak_existence(em: EntryManager) -> None:
    """SEC-4: unknown id and locked vault must produce the same error type."""
    with pytest.raises(VaultOperationError):
        em.get_entry("no-such-id")


def test_get_entry_fails_when_locked(em: EntryManager, km: KeyManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    km.lock()
    with pytest.raises(VaultOperationError):
        em.get_entry(entry_id)


# --------------------------------------------------------------------- #
# get_all_entries
# --------------------------------------------------------------------- #


def test_get_all_entries_empty(em: EntryManager) -> None:
    assert em.get_all_entries() == []


def test_get_all_entries_returns_all(em: EntryManager) -> None:
    ids = [em.create_entry({**SAMPLE, "title": f"E{i}"}) for i in range(5)]
    loaded = em.get_all_entries()

    assert len(loaded) == 5
    assert {e["id"] for e in loaded} == set(ids)


def test_get_all_entries_ordered_by_updated_desc(em: EntryManager) -> None:
    import time
    first = em.create_entry({**SAMPLE, "title": "first"})
    time.sleep(0.01)
    second = em.create_entry({**SAMPLE, "title": "second"})

    loaded = em.get_all_entries()
    assert [e["id"] for e in loaded][0] == second


def test_get_all_entries_skips_corrupted(db: Database, em: EntryManager, km: KeyManager) -> None:
    """One corrupted row must not break the whole list."""
    good = em.create_entry(SAMPLE)

    # Insert a bogus row directly.
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at, tags)
        VALUES (?, ?, ?, ?, ?)
        """,
        ("bogus-id", b"\x00" * 40, now, now, ""),
    )

    loaded = em.get_all_entries()
    assert len(loaded) == 1
    assert loaded[0]["id"] == good


def test_get_all_entries_fails_when_locked(em: EntryManager, km: KeyManager) -> None:
    em.create_entry(SAMPLE)
    km.lock()
    # When locked, every row fails to decrypt, so the list is empty
    # rather than raising.
    assert em.get_all_entries() == []


# --------------------------------------------------------------------- #
# update_entry
# --------------------------------------------------------------------- #


def test_update_entry_changes_fields(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    updated = em.update_entry(entry_id, {"title": "New Title", "username": "new@x.com"})

    assert updated["title"] == "New Title"
    assert updated["username"] == "new@x.com"
    # Untouched fields preserved.
    assert updated["password"] == SAMPLE["password"]
    assert updated["url"] == SAMPLE["url"]


def test_update_entry_persists_changes(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    em.update_entry(entry_id, {"notes": "changed"})

    loaded = em.get_entry(entry_id)
    assert loaded["notes"] == "changed"


def test_update_entry_bumps_updated_at(em: EntryManager) -> None:
    import time
    entry_id = em.create_entry(SAMPLE)
    original = em.get_entry(entry_id)["updated_at"]
    time.sleep(0.01)
    updated = em.update_entry(entry_id, {"title": "X"})
    assert updated["updated_at"] > original


def test_update_entry_preserves_created_at(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    created = em.get_entry(entry_id)["created_at"]
    em.update_entry(entry_id, {"title": "Changed"})
    assert em.get_entry(entry_id)["created_at"] == created


def test_update_entry_tags(em: EntryManager) -> None:
    entry_id = em.create_entry({**SAMPLE, "tags": "old"})
    em.update_entry(entry_id, {"tags": "new,tag"})
    assert em.get_entry(entry_id)["tags"] == "new,tag"


def test_update_entry_rejects_empty_title(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    with pytest.raises(VaultValidationError):
        em.update_entry(entry_id, {"title": "   "})


def test_update_entry_rejects_empty_password(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    with pytest.raises(VaultValidationError):
        em.update_entry(entry_id, {"password": ""})


def test_update_entry_unknown_id(em: EntryManager) -> None:
    with pytest.raises(VaultOperationError):
        em.update_entry("no-such-id", {"title": "X"})


def test_update_entry_publishes_event(db: Database, km: KeyManager) -> None:
    bus = EventBus()
    received = []
    bus.subscribe(EntryUpdated, lambda e: received.append(e))

    em = EntryManager(db, km, event_bus=bus)
    entry_id = em.create_entry(SAMPLE)
    em.update_entry(entry_id, {"title": "X"})

    assert len(received) == 1
    assert received[0].entry_id == entry_id


def test_update_entry_fails_when_locked(em: EntryManager, km: KeyManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    km.lock()
    with pytest.raises(VaultOperationError):
        em.update_entry(entry_id, {"title": "X"})


# --------------------------------------------------------------------- #
# delete_entry
# --------------------------------------------------------------------- #


def test_delete_entry_soft_removes_from_vault(em: EntryManager) -> None:
    entry_id = em.create_entry(SAMPLE)
    em.delete_entry(entry_id, soft_delete=True)
    assert em.get_all_entries() == []


def test_delete_entry_soft_moves_to_deleted_table(em: EntryManager, db: Database) -> None:
    entry_id = em.create_entry(SAMPLE)
    em.delete_entry(entry_id, soft_delete=True)

    row = db.fetch_one(
        "SELECT id, deleted_at, expires_at FROM deleted_entries WHERE id = ?",
        (entry_id,),
    )
    assert row is not None
    assert row["deleted_at"] is not None
    assert row["expires_at"] is not None


def test_delete_entry_hard(em: EntryManager, db: Database) -> None:
    entry_id = em.create_entry(SAMPLE)
    em.delete_entry(entry_id, soft_delete=False)

    assert db.fetch_one(
        "SELECT 1 FROM vault_entries WHERE id = ?", (entry_id,)
    ) is None
    assert db.fetch_one(
        "SELECT 1 FROM deleted_entries WHERE id = ?", (entry_id,)
    ) is None


def test_delete_entry_unknown_id(em: EntryManager) -> None:
    with pytest.raises(VaultOperationError):
        em.delete_entry("no-such-id")


def test_delete_entry_publishes_event_soft(db: Database, km: KeyManager) -> None:
    bus = EventBus()
    received = []
    bus.subscribe(EntryDeleted, lambda e: received.append(e))

    em = EntryManager(db, km, event_bus=bus)
    entry_id = em.create_entry(SAMPLE)
    em.delete_entry(entry_id, soft_delete=True)

    assert len(received) == 1
    assert received[0].entry_id == entry_id
    assert received[0].soft is True


def test_delete_entry_publishes_event_hard(db: Database, km: KeyManager) -> None:
    bus = EventBus()
    received = []
    bus.subscribe(EntryDeleted, lambda e: received.append(e))

    em = EntryManager(db, km, event_bus=bus)
    entry_id = em.create_entry(SAMPLE)
    em.delete_entry(entry_id, soft_delete=False)

    assert received[0].soft is False


def test_soft_delete_expiration_is_in_future(em: EntryManager, db: Database) -> None:
    from datetime import datetime, timezone
    entry_id = em.create_entry(SAMPLE)
    em.delete_entry(entry_id, soft_delete=True)

    row = db.fetch_one(
        "SELECT expires_at FROM deleted_entries WHERE id = ?", (entry_id,)
    )
    expires = datetime.fromisoformat(row["expires_at"])
    assert expires > datetime.now(timezone.utc)