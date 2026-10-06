"""
Secure memory handling.

Best-effort memory locking (mlock / VirtualLock) so that sensitive
buffers are not swapped to disk, plus explicit zeroing on free.

If locking is not available (insufficient privileges, unsupported
platform), the operation degrades to a warning and continues. The
memory is still zeroed on free.
"""

from __future__ import annotations

import ctypes
import platform
import sys
import warnings
from typing import Optional


# --------------------------------------------------------------------- #
# Platform detection
# --------------------------------------------------------------------- #


_IS_WINDOWS = sys.platform == "win32"
_IS_UNIX = platform.system() in ("Linux", "Darwin")


class MemoryLockError(Exception):
    """Raised when memory locking fails and strict mode is enabled."""


# --------------------------------------------------------------------- #
# Native bindings (best-effort)
# --------------------------------------------------------------------- #


class _Native:
    def __init__(self) -> None:
        self.libc = None
        self.kernel32 = None
        if _IS_WINDOWS:
            try:
                self.kernel32 = ctypes.windll.kernel32
            except Exception:
                self.kernel32 = None
        elif _IS_UNIX:
            try:
                self.libc = ctypes.CDLL(None, use_errno=True)
            except Exception:
                self.libc = None

    def lock(self, address: int, size: int) -> bool:
        if self.kernel32 is not None:
            try:
                return bool(self.kernel32.VirtualLock(ctypes.c_void_p(address), size))
            except Exception:
                return False
        if self.libc is not None:
            try:
                return self.libc.mlock(ctypes.c_void_p(address), size) == 0
            except Exception:
                return False
        return False

    def unlock(self, address: int, size: int) -> bool:
        if self.kernel32 is not None:
            try:
                return bool(self.kernel32.VirtualUnlock(ctypes.c_void_p(address), size))
            except Exception:
                return False
        if self.libc is not None:
            try:
                return self.libc.munlock(ctypes.c_void_p(address), size) == 0
            except Exception:
                return False
        return False


_NATIVE = _Native()


# --------------------------------------------------------------------- #
# SecureMemory
# --------------------------------------------------------------------- #


class SecureMemory:
    """
    Allocate, lock, zero, and free sensitive memory buffers.

    The buffer is a `ctypes.c_char * size` array. Locking is best-effort:
    if the OS refuses, a warning is issued and the buffer is still used.
    """

    def __init__(self, *, strict: bool = False) -> None:
        self._strict = strict
        self._locks: dict[int, int] = {}  # address -> size

    # ------------------------------------------------------------------ #
    # Allocation
    # ------------------------------------------------------------------ #

    def allocate(self, size: int) -> ctypes.Array:
        if size <= 0:
            raise ValueError("size must be > 0")

        buffer = (ctypes.c_char * size)()
        address = ctypes.addressof(buffer)

        if _NATIVE.lock(address, size):
            self._locks[address] = size
        else:
            if self._strict:
                raise MemoryLockError(
                    "Unable to lock memory (mlock/VirtualLock failed)."
                )
            warnings.warn(
                "memory locking is unavailable; buffer will not be pinned",
                RuntimeWarning,
                stacklevel=2,
            )

        return buffer

    # ------------------------------------------------------------------ #
    # Zeroing
    # ------------------------------------------------------------------ #

    def zero(self, buffer: ctypes.Array) -> None:
        size = ctypes.sizeof(buffer)
        if size <= 0:
            return
        ctypes.memset(buffer, 0, size)

    # ------------------------------------------------------------------ #
    # Freeing
    # ------------------------------------------------------------------ #

    def free(self, buffer: ctypes.Array) -> None:
        try:
            self.zero(buffer)
        finally:
            address = ctypes.addressof(buffer)
            size = self._locks.pop(address, None)
            if size is not None:
                _NATIVE.unlock(address, size)

    # ------------------------------------------------------------------ #
    # Context manager
    # ------------------------------------------------------------------ #

    def __enter__(self) -> "SecureMemory":
        return self

    def __exit__(self, *exc) -> None:
        # Individual buffers are freed by the caller via `free(buffer)`.
        pass


# --------------------------------------------------------------------- #
# SecretHolder
# --------------------------------------------------------------------- #


class SecretHolder:
    """
    Holds a bytes-like secret in a locked buffer.

    The original `data` (if it's a bytearray) is zeroed after copying.
    Call `wipe()` to clear; `__del__` also attempts a wipe.
    """

    def __init__(self, data: bytes | bytearray, *, strict: bool = False) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes or bytearray")

        self._mem = SecureMemory(strict=strict)
        self._size = len(data)
        if self._size == 0:
            raise ValueError("data must not be empty")

        self._buffer = self._mem.allocate(self._size)
        ctypes.memmove(self._buffer, bytes(data), self._size)

        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0

        self._wiped = False

    # ------------------------------------------------------------------ #

    @property
    def size(self) -> int:
        return self._size

    @property
    def wiped(self) -> bool:
        return self._wiped

    def get(self) -> bytes:
        if self._wiped:
            raise RuntimeError("secret has been wiped")
        return bytes(self._buffer)

    def wipe(self) -> None:
        if self._wiped:
            return
        self._mem.free(self._buffer)
        self._buffer = None
        self._wiped = True

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass


# --------------------------------------------------------------------- #
# Helper: wipe a bytearray in place
# --------------------------------------------------------------------- #


def wipe_bytes_inplace(buf: bytearray) -> None:
    """Zero a bytearray in place using ctypes.memset when possible."""
    if not isinstance(buf, bytearray):
        raise TypeError("expected bytearray")
    length = len(buf)
    if length == 0:
        return
    try:
        ctypes.memset(
            (ctypes.c_char * length).from_buffer(buf),
            0,
            length,
        )
    except (TypeError, ValueError):
        for i in range(length):
            buf[i] = 0