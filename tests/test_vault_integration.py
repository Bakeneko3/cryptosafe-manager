"""
Integration tests for vault CRUD + performance (TEST-2, TEST-3, PERF-1/2).
"""

import threading
import time
from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager, VaultOperationError
from src.core.vault.search import search_entries
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
    d = Database(tmp_path / "integration.db")
    yield d
    d.close()


@pytest.fixture
def em(db: Database, fast_kd: KeyDerivation) -> EntryManager:
    km = KeyManager(db, key_derivation=fast_kd)
    km.create_vault(STRONG)
    return EntryManager(db, km)


def _make_entry(i: int) -> dict:
    return {
        "title": f"Entry {i:04d}",
        "username": f"user{i}@example.com",
        "password": f"pw-{i}-Strong!Pass",
        "url": f"https://example.com/{i}",
        "notes": f"note for {i}",
        "category": "Bulk" if i % 2 == 0 else "Other",
        "tags": "bulk,test" if i % 3 == 0 else "test",
    }


# --------------------------------------------------------------------- #
# TEST-2: CRUD integration
# --------------------------------------------------------------------- #


def test_create_100_entries_and_count(em: EntryManager) -> None:
    ids = [em.create_entry(_make_entry(i)) for i in range(100)]
    assert len(ids) == 100
    assert len(set(ids)) == 100  # all UUIDs unique

    entries = em.get_all_entries()
    assert len(entries) == 100


def test_read_back_each_entry(em: EntryManager) -> None:
    ids = [em.create_entry(_make_entry(i)) for i in range(100)]
    for i, entry_id in enumerate(ids):
        loaded = em.get_entry(entry_id)
        assert loaded["title"] == f"Entry {i:04d}"
        assert loaded["username"] == f"user{i}@example.com"
        assert loaded["password"] == f"pw-{i}-Strong!Pass"


def test_update_all_entries(em: EntryManager) -> None:
    ids = [em.create_entry(_make_entry(i)) for i in range(100)]

    for i, entry_id in enumerate(ids):
        em.update_entry(entry_id, {"notes": f"updated note {i}"})

    for i, entry_id in enumerate(ids):
        loaded = em.get_entry(entry_id)
        assert loaded["notes"] == f"updated note {i}"
        # Other fields untouched.
        assert loaded["title"] == f"Entry {i:04d}"


def test_delete_half_soft_half_hard(em: EntryManager) -> None:
    ids = [em.create_entry(_make_entry(i)) for i in range(100)]

    for i, entry_id in enumerate(ids):
        em.delete_entry(entry_id, soft_delete=(i % 2 == 0))

    remaining = em.get_all_entries()
    assert len(remaining) == 0  # soft + hard both remove from vault_entries


def test_update_after_delete_fails(em: EntryManager) -> None:
    entry_id = em.create_entry(_make_entry(1))
    em.delete_entry(entry_id, soft_delete=True)
    with pytest.raises(VaultOperationError):
        em.update_entry(entry_id, {"title": "ghost"})


def test_data_consistency_after_mixed_operations(em: EntryManager) -> None:
    ids = [em.create_entry(_make_entry(i)) for i in range(50)]

    # Update 10.
    for entry_id in ids[:10]:
        em.update_entry(entry_id, {"title": "updated"})

    # Delete 10.
    for entry_id in ids[10:20]:
        em.delete_entry(entry_id, soft_delete=True)

    remaining = em.get_all_entries()
    assert len(remaining) == 40

    titles = [e["title"] for e in remaining]
    assert titles.count("updated") == 10


# --------------------------------------------------------------------- #
# PERF-1: 1000 entries load < 2 seconds
# --------------------------------------------------------------------- #


@pytest.mark.slow
@pytest.mark.perf
def test_perf_load_1000_entries(em: EntryManager) -> None:
    for i in range(1000):
        em.create_entry(_make_entry(i))

    start = time.perf_counter()
    entries = em.get_all_entries()
    elapsed = time.perf_counter() - start

    assert len(entries) == 1000
    assert elapsed < 2.0, f"Loading 1000 entries took {elapsed:.3f}s"


# --------------------------------------------------------------------- #
# PERF-2: search across 1000 entries < 200 ms
# --------------------------------------------------------------------- #


@pytest.mark.slow
@pytest.mark.perf
def test_perf_search_1000_entries(em: EntryManager) -> None:
    for i in range(1000):
        em.create_entry(_make_entry(i))

    entries = em.get_all_entries()

    start = time.perf_counter()
    result = search_entries(entries, "Entry 0500")
    elapsed = time.perf_counter() - start

    assert len(result) >= 1
    assert elapsed < 0.2, f"Search took {elapsed:.3f}s"


@pytest.mark.slow
@pytest.mark.perf
def test_perf_field_filter_1000_entries(em: EntryManager) -> None:
    for i in range(1000):
        em.create_entry(_make_entry(i))

    entries = em.get_all_entries()

    start = time.perf_counter()
    result = search_entries(entries, "category:Bulk")
    elapsed = time.perf_counter() - start

    assert len(result) == 500
    assert elapsed < 0.2, f"Field-filter search took {elapsed:.3f}s"


# --------------------------------------------------------------------- #
# TEST-3: concurrency
# --------------------------------------------------------------------- #


def test_concurrent_reads_do_not_corrupt(em: EntryManager) -> None:
    """
    Multiple threads reading entries simultaneously must not raise and
    must return consistent data. Writes are serialized by Database._lock.
    """
    ids = [em.create_entry(_make_entry(i)) for i in range(50)]
    errors: list[Exception] = []

    def worker() -> None:
        try:
            for _ in range(20):
                entries = em.get_all_entries()
                assert len(entries) == 50
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []


def test_concurrent_writes_serialized(em: EntryManager) -> None:
    """
    Multiple threads creating entries simultaneously must not corrupt
    the database. Each write is serialized via the Database lock.
    """
    errors: list[Exception] = []

    def worker(offset: int) -> None:
        try:
            for i in range(25):
                em.create_entry(_make_entry(offset + i))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i * 100,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(em.get_all_entries()) == 100