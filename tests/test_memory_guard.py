"""Tests for src/core/security/memory_guard.py (MEM-1, MEM-2, MEM-4)."""

import ctypes
import warnings

import pytest

from src.core.security.memory_guard import (
    SecureMemory,
    SecretHolder,
    wipe_bytes_inplace,
)


# --------------------------------------------------------------------- #
# SecureMemory
# --------------------------------------------------------------------- #


def test_allocate_returns_buffer() -> None:
    mem = SecureMemory()
    buf = mem.allocate(32)
    assert ctypes.sizeof(buf) == 32
    mem.free(buf)


def test_allocate_zeroes_by_default() -> None:
    mem = SecureMemory()
    buf = mem.allocate(16)
    assert bytes(buf) == b"\x00" * 16
    mem.free(buf)


def test_allocate_rejects_zero_size() -> None:
    mem = SecureMemory()
    with pytest.raises(ValueError):
        mem.allocate(0)


def test_zero_clears_data() -> None:
    mem = SecureMemory()
    buf = mem.allocate(8)
    ctypes.memmove(buf, b"secret!!", 8)
    assert bytes(buf) == b"secret!!"
    mem.zero(buf)
    assert bytes(buf) == b"\x00" * 8
    mem.free(buf)


def test_free_clears_and_unlocks() -> None:
    mem = SecureMemory()
    buf = mem.allocate(16)
    ctypes.memmove(buf, b"data" * 4, 16)
    mem.free(buf)
    assert bytes(buf) == b"\x00" * 16


def test_allocate_warns_when_lock_unavailable() -> None:
    """
    On most systems without privileges, mlock/VirtualLock either works
    or issues a warning. Either behaviour is acceptable.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        mem = SecureMemory()
        buf = mem.allocate(32)
        mem.free(buf)


# --------------------------------------------------------------------- #
# SecretHolder
# --------------------------------------------------------------------- #


def test_secret_holder_get_roundtrip() -> None:
    secret = b"my secret bytes"
    holder = SecretHolder(secret)
    assert holder.get() == secret
    holder.wipe()
    assert holder.wiped is True


def test_secret_holder_wipes_bytearray_input() -> None:
    data = bytearray(b"to be wiped")
    holder = SecretHolder(data)
    assert all(b == 0 for b in data)
    assert holder.get() == b"to be wiped"
    holder.wipe()


def test_secret_holder_double_wipe_is_safe() -> None:
    holder = SecretHolder(b"data")
    holder.wipe()
    holder.wipe()


def test_secret_holder_get_after_wipe_raises() -> None:
    holder = SecretHolder(b"data")
    holder.wipe()
    with pytest.raises(RuntimeError):
        holder.get()


def test_secret_holder_rejects_wrong_type() -> None:
    with pytest.raises(TypeError):
        SecretHolder("string")  # type: ignore[arg-type]


def test_secret_holder_rejects_empty() -> None:
    with pytest.raises(ValueError):
        SecretHolder(b"")


def test_secret_holder_size() -> None:
    holder = SecretHolder(b"12345")
    assert holder.size == 5
    holder.wipe()


# --------------------------------------------------------------------- #
# wipe_bytes_inplace
# --------------------------------------------------------------------- #


def test_wipe_bytes_inplace() -> None:
    buf = bytearray(b"erase me")
    wipe_bytes_inplace(buf)
    assert all(b == 0 for b in buf)


def test_wipe_bytes_inplace_empty() -> None:
    wipe_bytes_inplace(bytearray())


def test_wipe_bytes_inplace_rejects_bytes() -> None:
    with pytest.raises(TypeError):
        wipe_bytes_inplace(b"immutable")  # type: ignore[arg-type]