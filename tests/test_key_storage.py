"""Tests for src/core/crypto/key_storage.py (CACHE-1, CACHE-2, CACHE-4)."""

import time

import pytest

from src.core.crypto.key_storage import KeyCache, wipe_bytes


# --------------------------------------------------------------------- #
# wipe_bytes
# --------------------------------------------------------------------- #


def test_wipe_bytes_zeroes_buffer() -> None:
    buf = bytearray(b"secret-key-material")
    wipe_bytes(buf)
    assert all(b == 0 for b in buf)


def test_wipe_bytes_accepts_empty_buffer() -> None:
    wipe_bytes(bytearray())


def test_wipe_bytes_rejects_bytes() -> None:
    with pytest.raises(TypeError):
        wipe_bytes(b"immutable")  # type: ignore[arg-type]


# --------------------------------------------------------------------- #
# KeyCache: basic lifecycle
# --------------------------------------------------------------------- #


def test_cache_starts_empty() -> None:
    c = KeyCache()
    assert c.has_key is False
    assert c.unlocked is False
    assert c.get() is None


def test_store_marks_unlocked_and_exposes_key() -> None:
    c = KeyCache()
    c.store(b"\x01" * 32)
    assert c.has_key is True
    assert c.unlocked is True
    got = c.get()
    assert got is not None
    assert bytes(got) == b"\x01" * 32


def test_store_rejects_empty_key() -> None:
    c = KeyCache()
    with pytest.raises(ValueError):
        c.store(b"")


def test_store_rejects_wrong_type() -> None:
    c = KeyCache()
    with pytest.raises(TypeError):
        c.store("not-bytes")  # type: ignore[arg-type]


def test_store_replaces_existing_key_and_wipes_old() -> None:
    c = KeyCache()
    c.store(b"\xaa" * 32)
    old = c.get()
    assert old is not None

    c.store(b"\xbb" * 32)
    new = c.get()
    assert new is not None
    assert bytes(new) == b"\xbb" * 32
    # Old buffer was zeroed before being dropped.
    assert all(b == 0 for b in old)


# --------------------------------------------------------------------- #
# KeyCache: lock / unlock
# --------------------------------------------------------------------- #


def test_lock_hides_key_but_keeps_it() -> None:
    c = KeyCache()
    c.store(b"\x01" * 32)
    c.lock()
    assert c.has_key is True
    assert c.unlocked is False
    assert c.get() is None


def test_unlock_restores_access() -> None:
    c = KeyCache()
    c.store(b"\x02" * 32)
    c.lock()
    assert c.unlock() is True
    got = c.get()
    assert got is not None
    assert bytes(got) == b"\x02" * 32


def test_unlock_returns_false_when_no_key() -> None:
    c = KeyCache()
    assert c.unlock() is False


# --------------------------------------------------------------------- #
# KeyCache: wipe (CACHE-4)
# --------------------------------------------------------------------- #


def test_wipe_zeroes_and_forgets_key() -> None:
    c = KeyCache()
    c.store(b"\xcc" * 32)
    buf = c.get()
    assert buf is not None

    c.wipe()
    assert c.has_key is False
    assert c.unlocked is False
    assert c.get() is None
    # The buffer we held earlier was zeroed in place.
    assert all(b == 0 for b in buf)


def test_wipe_is_idempotent() -> None:
    c = KeyCache()
    c.wipe()
    c.wipe()
    assert c.has_key is False


# --------------------------------------------------------------------- #
# KeyCache: expiration (CACHE-2)
# --------------------------------------------------------------------- #


def test_not_expired_within_timeout() -> None:
    c = KeyCache(inactivity_timeout=3600)
    c.store(b"\x01" * 32)
    assert c.is_expired() is False
    assert c.get() is not None


def test_expired_after_timeout() -> None:
    c = KeyCache(inactivity_timeout=10)
    c.store(b"\x01" * 32)
    future = time.monotonic() + 11
    assert c.is_expired(now=future) is True


def test_get_returns_none_when_cache_is_expired() -> None:
    """get() must respect expiration using the real clock."""
    c = KeyCache(inactivity_timeout=0)
    c.store(b"\x01" * 32)
    # With timeout=0, anything past the current monotonic instant counts
    # as expired. Sleep a tiny amount to make sure time advances.
    time.sleep(0.01)
    assert c.is_expired() is True
    assert c.get() is None


def test_get_refreshes_last_used_timestamp() -> None:
    c = KeyCache(inactivity_timeout=10)
    c.store(b"\x01" * 32)
    # Simulate "just about to expire".
    c._last_used_at = time.monotonic() - 9  # type: ignore[attr-defined]
    assert c.is_expired() is False
    # Touching via get() should push the deadline further away.
    assert c.get() is not None
    assert c.is_expired() is False


def test_status_reflects_state() -> None:
    c = KeyCache(inactivity_timeout=5)
    s = c.status()
    assert s.has_key is False
    assert s.unlocked is False
    assert s.expired is False

    c.store(b"\x01" * 32)
    s = c.status()
    assert s.has_key is True
    assert s.unlocked is True
    assert s.expired is False

    c.lock()
    s = c.status()
    assert s.unlocked is False


def test_focus_loss_flag_is_stored() -> None:
    c = KeyCache(drop_on_focus_loss=True)
    assert c.drop_on_focus_loss is True
    c2 = KeyCache(drop_on_focus_loss=False)
    assert c2.drop_on_focus_loss is False