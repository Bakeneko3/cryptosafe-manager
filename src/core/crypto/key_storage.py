"""
Secure in-memory storage for derived encryption keys.

The encryption key is only ever held here, in RAM, while the vault is
unlocked. It is never written to disk (SEC-2).

Responsibilities:
  * hold the key as a mutable bytearray so it can be zeroed in place;
  * expose access only while the vault is considered unlocked;
  * track inactivity and report expiration (CACHE-2);
  * wipe the key explicitly on demand (CACHE-4).

OS keychain integration is intentionally stubbed for Sprint 7
(KEYCHAIN-1..3). File-based fallback is out of scope for Sprint 2.
"""

from __future__ import annotations

import ctypes
import time
from dataclasses import dataclass, field

from src.core import config


# --------------------------------------------------------------------- #
# Low-level memory wiping
# --------------------------------------------------------------------- #


def wipe_bytes(buf: bytearray) -> None:
    """
    Overwrite the contents of a bytearray with zeros.

    Uses ctypes.memset when available for a best-effort guaranteed wipe;
    falls back to a pure-Python loop otherwise.
    """
    if not isinstance(buf, bytearray):
        raise TypeError("wipe_bytes expects a bytearray")
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


# --------------------------------------------------------------------- #
# Key cache
# --------------------------------------------------------------------- #


@dataclass
class CacheStatus:
    """Snapshot of the cache state, useful for tests and diagnostics."""

    has_key: bool
    unlocked: bool
    last_used_at: float | None
    expired: bool


class KeyCache:
    """
    Holds a single encryption key in memory.

    Lifecycle:
        * `store(key)`    -- cache a freshly derived key, mark unlocked
        * `get()`         -- retrieve the key, refreshing last-used time
        * `lock()`        -- mark locked; key is retained but not readable
                             (Sprint 7 will decide whether to also wipe)
        * `wipe()`        -- zero the key and forget it (logout, close)
        * `is_expired()`  -- check inactivity timeout

    `get()` returns the internal bytearray. Callers must treat it as
    read-only. The intent is to avoid unnecessary copies of key material.
    """

    def __init__(
        self,
        *,
        inactivity_timeout: int = config.KEY_CACHE_INACTIVITY_TIMEOUT,
        drop_on_focus_loss: bool = config.KEY_CACHE_DROP_ON_FOCUS_LOSS,
    ) -> None:
        self._key: bytearray | None = None
        self._unlocked: bool = False
        self._last_used_at: float | None = None
        self._inactivity_timeout = inactivity_timeout
        self._drop_on_focus_loss = drop_on_focus_loss

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def has_key(self) -> bool:
        return self._key is not None

    @property
    def unlocked(self) -> bool:
        return self._unlocked

    @property
    def inactivity_timeout(self) -> int:
        return self._inactivity_timeout

    @property
    def drop_on_focus_loss(self) -> bool:
        return self._drop_on_focus_loss

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def store(self, key: bytes) -> None:
        """Cache a derived key and mark the vault as unlocked."""
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")
        if len(key) == 0:
            raise ValueError("key must not be empty")
        self.wipe()
        self._key = bytearray(key)
        self._unlocked = True
        self._last_used_at = time.monotonic()

    def get(self) -> bytearray | None:
        """
        Return the cached key and refresh the last-used timestamp.

        Returns None if the vault is locked, the key is absent, or the
        cache has expired.
        """
        if self._key is None or not self._unlocked:
            return None
        if self.is_expired():
            # Do not wipe here: policy is "report, do not act".
            return None
        self._last_used_at = time.monotonic()
        return self._key

    def lock(self) -> None:
        """
        Mark the cache as locked.

        By default the key material is retained so that a fast unlock can
        reuse it. Explicit `wipe()` is required to clear memory. This
        matches CACHE-1: key is only *accessible* while unlocked.
        """
        self._unlocked = False

    def unlock(self) -> bool:
        """Re-enable access if a key is still present. Returns success."""
        if self._key is None:
            return False
        self._unlocked = True
        self._last_used_at = time.monotonic()
        return True

    def wipe(self) -> None:
        """Zero the key in memory and forget it (CACHE-4)."""
        if self._key is not None:
            wipe_bytes(self._key)
            self._key = None
        self._unlocked = False
        self._last_used_at = None

    # ------------------------------------------------------------------ #
    # Expiration (CACHE-2)
    # ------------------------------------------------------------------ #

    def is_expired(self, *, now: float | None = None) -> bool:
        if self._last_used_at is None or self._key is None:
            return False
        current = time.monotonic() if now is None else now
        return (current - self._last_used_at) > self._inactivity_timeout

    def status(self, *, now: float | None = None) -> CacheStatus:
        return CacheStatus(
            has_key=self._key is not None,
            unlocked=self._unlocked,
            last_used_at=self._last_used_at,
            expired=self.is_expired(now=now),
        )