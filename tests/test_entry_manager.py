"""Tests for src/core/vault/entry_manager.py (step 5a: create_entry)."""

from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.events import EntryCreated, EventBus
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