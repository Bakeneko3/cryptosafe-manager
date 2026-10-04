"""Tests for src/core/key_manager.py (Sprint 2/3)."""

from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.key_manager import (
    KEY_TYPE_AUTH_HASH,
    KEY_TYPE_ENC_SALT,
    KEY_TYPE_PARAMS,
    KeyManager,
    UnlockResult,
)
from src.core.vault.encryption_service import AESGCMService
from src.database.db import Database


# --------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------- #


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(tmp_path / "test.db")
    yield d
    d.close()


@pytest.fixture
def fast_kd() -> KeyDerivation:
    """Lightweight KDF for fast tests."""
    return KeyDerivation(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        pbkdf2_iterations=1000,
    )


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    return KeyManager(db, key_derivation=fast_kd)


STRONG = "Correct-Horse-Battery-42!"
NEW_STRONG = "Another-Strong-Pass-99$"


# --------------------------------------------------------------------- #
# Initialization state
# --------------------------------------------------------------------- #


def test_fresh_manager_is_not_initialized(km: KeyManager) -> None:
    assert km.is_initialized() is False
    assert km.status().initialized is False
    assert km.status().unlocked is False


def test_create_vault_initializes_and_unlocks(km: KeyManager) -> None:
    km.create_vault(STRONG)
    assert km.is_initialized() is True
    assert km.status().unlocked is True
    assert km.get_encryption_key() is not None


def test_create_vault_rejects_weak_password(km: KeyManager) -> None:
    with pytest.raises(ValueError, match="policy"):
        km.create_vault("weak")


def test_create_vault_twice_raises(km: KeyManager) -> None:
    km.create_vault(STRONG)
    with pytest.raises(ValueError, match="already initialized"):
        km.create_vault(STRONG)


# --------------------------------------------------------------------- #
# key_store records (KEY-3, DB-1, SEC-1)
# --------------------------------------------------------------------- #


def test_create_vault_writes_three_records(km: KeyManager, db: Database) -> None:
    km.create_vault(STRONG)
    rows = db.fetch_all("SELECT key_type FROM key_store ORDER BY key_type")
    types = {r["key_type"] for r in rows}
    assert types == {KEY_TYPE_AUTH_HASH, KEY_TYPE_ENC_SALT, KEY_TYPE_PARAMS}


def test_master_password_is_never_stored(km: KeyManager, db: Database) -> None:
    km.create_vault(STRONG)
    rows = db.fetch_all("SELECT key_data FROM key_store")
    for r in rows:
        data = r["key_data"]
        assert STRONG.encode("utf-8") not in bytes(data)


def test_auth_hash_is_argon2id(km: KeyManager, db: Database) -> None:
    km.create_vault(STRONG)
    row = db.fetch_one(
        "SELECT key_data FROM key_store WHERE key_type = ?",
        (KEY_TYPE_AUTH_HASH,),
    )
    assert row is not None
    assert row["key_data"].decode("utf-8").startswith("$argon2id$")


def test_enc_salt_is_16_bytes(km: KeyManager, db: Database) -> None:
    km.create_vault(STRONG)
    row = db.fetch_one(
        "SELECT key_data FROM key_store WHERE key_type = ?",
        (KEY_TYPE_ENC_SALT,),
    )
    assert row is not None
    assert len(bytes(row["key_data"])) == 16


def test_params_record_contains_expected_keys(km: KeyManager, db: Database) -> None:
    import json
    km.create_vault(STRONG)
    row = db.fetch_one(
        "SELECT key_data FROM key_store WHERE key_type = ?",
        (KEY_TYPE_PARAMS,),
    )
    assert row is not None
    params = json.loads(row["key_data"].decode("utf-8"))
    assert "version" in params
    assert "argon2" in params
    assert "pbkdf2" in params
    assert params["argon2"]["time_cost"] == 1
    assert params["pbkdf2"]["iterations"] == 1000


# --------------------------------------------------------------------- #
# Unlock
# --------------------------------------------------------------------- #


def test_unlock_with_correct_password(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.lock()
    result = km.unlock(STRONG)
    assert isinstance(result, UnlockResult)
    assert result.success is True
    assert result.backoff_delay == 0
    assert km.get_encryption_key() is not None


def test_unlock_with_wrong_password(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.lock()
    result = km.unlock("Wrong-Password-99!")
    assert result.success is False
    assert result.backoff_delay == 1
    assert km.get_encryption_key() is None


def test_unlock_backoff_grows(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.lock()
    delays = []
    for _ in range(5):
        r = km.unlock("Wrong-Password-99!")
        delays.append(r.backoff_delay)
    assert delays == [1, 1, 5, 5, 30]


def test_unlock_resets_failures_on_success(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.lock()
    km.unlock("Wrong-Password-99!")
    km.unlock("Wrong-Password-99!")
    assert km.session.failed_attempts == 2
    km.unlock(STRONG)
    assert km.session.failed_attempts == 0


def test_unlock_on_uninitialized_raises(km: KeyManager) -> None:
    with pytest.raises(ValueError, match="not initialized"):
        km.unlock(STRONG)


# --------------------------------------------------------------------- #
# Lock
# --------------------------------------------------------------------- #


def test_lock_hides_key(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.lock()
    assert km.get_encryption_key() is None
    assert km.cache.has_key is True
    assert km.cache.unlocked is False


def test_lock_ends_session(km: KeyManager) -> None:
    km.create_vault(STRONG)
    assert km.session.is_active is True
    km.lock()
    assert km.session.is_active is False


# --------------------------------------------------------------------- #
# Encryption key consistency
# --------------------------------------------------------------------- #


def test_derived_key_is_deterministic_across_unlocks(km: KeyManager) -> None:
    km.create_vault(STRONG)
    key1 = bytes(km.get_encryption_key())

    km.lock()
    km.unlock(STRONG)
    key2 = bytes(km.get_encryption_key())

    assert key1 == key2


def test_different_vaults_produce_different_keys(
    tmp_path: Path, fast_kd: KeyDerivation
) -> None:
    db1 = Database(tmp_path / "a.db")
    db2 = Database(tmp_path / "b.db")
    try:
        km1 = KeyManager(db1, key_derivation=fast_kd)
        km2 = KeyManager(db2, key_derivation=fast_kd)

        km1.create_vault(STRONG)
        km2.create_vault(STRONG)

        assert bytes(km1.get_encryption_key()) != bytes(km2.get_encryption_key())
    finally:
        db1.close()
        db2.close()


# --------------------------------------------------------------------- #
# Event publishing (AUTH-2 step 4)
# --------------------------------------------------------------------- #


def test_create_vault_publishes_user_logged_in(
    db: Database, fast_kd: KeyDerivation
) -> None:
    from src.core.events import EventBus, UserLoggedIn

    bus = EventBus()
    received = []
    bus.subscribe(UserLoggedIn, lambda e: received.append(e))

    km = KeyManager(db, key_derivation=fast_kd, event_bus=bus)
    km.create_vault(STRONG)

    assert len(received) == 1
    assert isinstance(received[0], UserLoggedIn)


def test_unlock_publishes_user_logged_in(
    db: Database, fast_kd: KeyDerivation
) -> None:
    from src.core.events import EventBus, UserLoggedIn

    bus = EventBus()
    received = []
    bus.subscribe(UserLoggedIn, lambda e: received.append(e))

    km = KeyManager(db, key_derivation=fast_kd, event_bus=bus)
    km.create_vault(STRONG)
    km.lock()
    received.clear()

    km.unlock(STRONG)
    assert len(received) == 1


def test_failed_unlock_does_not_publish(
    db: Database, fast_kd: KeyDerivation
) -> None:
    from src.core.events import EventBus, UserLoggedIn

    bus = EventBus()
    received = []
    bus.subscribe(UserLoggedIn, lambda e: received.append(e))

    km = KeyManager(db, key_derivation=fast_kd, event_bus=bus)
    km.create_vault(STRONG)
    km.lock()
    received.clear()

    km.unlock("Wrong-Password-99!")
    assert received == []


def test_lock_publishes_user_logged_out(
    db: Database, fast_kd: KeyDerivation
) -> None:
    from src.core.events import EventBus, UserLoggedOut

    bus = EventBus()
    received = []
    bus.subscribe(UserLoggedOut, lambda e: received.append(e))

    km = KeyManager(db, key_derivation=fast_kd, event_bus=bus)
    km.create_vault(STRONG)

    km.lock()
    assert len(received) == 1
    assert received[0].reason == "manual"


def test_lock_with_reason(
    db: Database, fast_kd: KeyDerivation
) -> None:
    from src.core.events import EventBus, UserLoggedOut

    bus = EventBus()
    received = []
    bus.subscribe(UserLoggedOut, lambda e: received.append(e))

    km = KeyManager(db, key_derivation=fast_kd, event_bus=bus)
    km.create_vault(STRONG)

    km.lock(reason="auto-lock")
    assert received[0].reason == "auto-lock"


def test_manager_works_without_event_bus(
    db: Database, fast_kd: KeyDerivation
) -> None:
    km = KeyManager(db, key_derivation=fast_kd)
    km.create_vault(STRONG)
    km.lock()
    km.unlock(STRONG)


# --------------------------------------------------------------------- #
# Password change & key rotation (CHANGE-1..4, TEST-5)
# --------------------------------------------------------------------- #


def _insert_dummy_entry(db: Database, title: str, ciphertext: bytes) -> str:
    """
    Insert a raw entry using the Sprint 3 schema (UUID + encrypted_data).
    `title` is unused in the new schema; kept for signature compatibility.
    """
    import uuid
    from datetime import datetime, timezone
    entry_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO vault_entries
            (id, encrypted_data, created_at, updated_at, tags)
        VALUES (?, ?, ?, ?, ?)
        """,
        (entry_id, ciphertext, now, now, ""),
    )
    return entry_id


def test_change_password_requires_unlocked(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.lock()
    with pytest.raises(RuntimeError, match="unlocked"):
        km.change_password(STRONG, NEW_STRONG)


def test_change_password_requires_correct_current(km: KeyManager) -> None:
    km.create_vault(STRONG)
    with pytest.raises(ValueError, match="Current password"):
        km.change_password("Wrong-Password-99!", NEW_STRONG)


def test_change_password_rejects_weak_new(km: KeyManager) -> None:
    km.create_vault(STRONG)
    with pytest.raises(ValueError, match="policy"):
        km.change_password(STRONG, "weak")


def test_change_password_rejects_same_password(km: KeyManager) -> None:
    km.create_vault(STRONG)
    with pytest.raises(ValueError, match="differ"):
        km.change_password(STRONG, STRONG)


def test_change_password_updates_key_store(km: KeyManager, db: Database) -> None:
    km.create_vault(STRONG)
    old_hash = db.fetch_one(
        "SELECT key_data FROM key_store WHERE key_type = ?",
        (KEY_TYPE_AUTH_HASH,),
    )["key_data"]
    old_salt = db.fetch_one(
        "SELECT key_data FROM key_store WHERE key_type = ?",
        (KEY_TYPE_ENC_SALT,),
    )["key_data"]

    km.change_password(STRONG, NEW_STRONG)

    new_hash = db.fetch_one(
        "SELECT key_data FROM key_store WHERE key_type = ?",
        (KEY_TYPE_AUTH_HASH,),
    )["key_data"]
    new_salt = db.fetch_one(
        "SELECT key_data FROM key_store WHERE key_type = ?",
        (KEY_TYPE_ENC_SALT,),
    )["key_data"]

    assert new_hash != old_hash
    assert bytes(new_salt) != bytes(old_salt)


def test_change_password_allows_unlock_with_new(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.change_password(STRONG, NEW_STRONG)
    km.lock()
    result = km.unlock(NEW_STRONG)
    assert result.success is True


def test_change_password_blocks_old_password(km: KeyManager) -> None:
    km.create_vault(STRONG)
    km.change_password(STRONG, NEW_STRONG)
    km.lock()
    result = km.unlock(STRONG)
    assert result.success is False


def test_change_password_re_encrypts_entries(km: KeyManager, db: Database) -> None:
    """TEST-5 (reduced): entries survive a password change."""
    km.create_vault(STRONG)

    service = AESGCMService(km)
    plaintexts = [f"secret-{i}".encode("utf-8") for i in range(10)]
    for i, pt in enumerate(plaintexts):
        _insert_dummy_entry(db, f"entry-{i}", service.encrypt(pt))

    km.change_password(STRONG, NEW_STRONG)

    service_after = AESGCMService(km)
    rows = db.fetch_all(
        "SELECT id, encrypted_data FROM vault_entries"
    )
    assert len(rows) == 10

    decrypted = {
        service_after.decrypt(bytes(row["encrypted_data"]))
        for row in rows
    }
    assert decrypted == set(plaintexts)


def test_change_password_atomic_rollback_on_failure(
    db: Database, km: KeyManager
) -> None:
    """
    If re-encryption fails midway, the DB must roll back and the old
    password must remain valid (CHANGE-4).
    """
    km.create_vault(STRONG)

    # Insert one valid entry.
    service = AESGCMService(km)
    _insert_dummy_entry(db, "entry", service.encrypt(b"data"))

    # Insert one bogus entry that will fail to decrypt during re-encryption.
    _insert_dummy_entry(db, "bogus", b"\xff" * 40)

    with pytest.raises(RuntimeError):
        km.change_password(STRONG, NEW_STRONG)

    # Old password must still unlock.
    km.lock()
    assert km.unlock(STRONG).success is True
    assert km.unlock(NEW_STRONG).success is False


# --------------------------------------------------------------------- #
# TEST-5: full password change integration
# --------------------------------------------------------------------- #


def test_test5_password_change_integration(
    tmp_path: Path, fast_kd: KeyDerivation
) -> None:
    """
    TEST-5 (full):
        1. Create vault with password A.
        2. Add 10 entries (encrypted with A's key).
        3. Lock, unlock with A: all entries readable.
        4. Change password A -> B.
        5. Lock, unlock with B: all entries readable.
        6. Old password A no longer unlocks.
    """
    PASSWORD_A = "Original-Strong-Pass-11!"
    PASSWORD_B = "Rotated-Strong-Pass-22@"

    db = Database(tmp_path / "test5.db")
    try:
        km = KeyManager(db, key_derivation=fast_kd)
        km.create_vault(PASSWORD_A)

        # Step 2: add 10 entries, encrypting each with the current key.
        service = AESGCMService(km)
        plaintexts = [f"secret-number-{i}".encode("utf-8") for i in range(10)]
        for i, pt in enumerate(plaintexts):
            _insert_dummy_entry(db, f"entry-{i}", service.encrypt(pt))

        # Step 3: lock / unlock with A, verify all entries readable.
        km.lock()
        assert km.unlock(PASSWORD_A).success is True
        service_a = AESGCMService(km)
        rows = db.fetch_all("SELECT encrypted_data FROM vault_entries")
        assert len(rows) == 10
        decrypted_a = {
            service_a.decrypt(bytes(row["encrypted_data"])) for row in rows
        }
        assert decrypted_a == set(plaintexts)

        # Step 4: rotate to password B.
        km.change_password(PASSWORD_A, PASSWORD_B)

        # Step 5: lock, unlock with B, verify all entries readable.
        km.lock()
        assert km.unlock(PASSWORD_B).success is True
        service_b = AESGCMService(km)
        rows = db.fetch_all("SELECT encrypted_data FROM vault_entries")
        assert len(rows) == 10
        decrypted_b = {
            service_b.decrypt(bytes(row["encrypted_data"])) for row in rows
        }
        assert decrypted_b == set(plaintexts)

        # Step 6: old password A must no longer unlock.
        km.lock()
        assert km.unlock(PASSWORD_A).success is False
    finally:
        db.close()