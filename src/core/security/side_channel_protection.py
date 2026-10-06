"""
Side-channel protection primitives.

Python cannot guarantee true constant-time execution at the CPU level
(the interpreter's own logic dominates). This module provides:

  * a single, well-named entry point for constant-time byte comparison
    built on `secrets.compare_digest`, which the C implementation
    performs without short-circuiting;
  * a small integer comparison helper that avoids data-dependent
    branches when the operands are within a known small range;
  * secure random helpers;
  * an optional random-delay helper used only in tests, NOT in the
    production paths (see the Sprint 7 planning notes: power-analysis
    mitigation is deliberately out of scope).
"""

from __future__ import annotations

import hmac
import secrets
import time


# --------------------------------------------------------------------- #
# Constant-time comparison
# --------------------------------------------------------------------- #


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.

    Backed by hmac.compare_digest / secrets.compare_digest.
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        raise TypeError("arguments must be bytes or bytearray")
    return secrets.compare_digest(bytes(a), bytes(b))


def constant_time_equals_str(a: str, b: str) -> bool:
    """Compare two strings in constant time using their UTF-8 bytes."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("arguments must be str")
    return constant_time_compare(a.encode("utf-8"), b.encode("utf-8"))


def constant_time_equals_int(a: int, b: int) -> bool:
    """
    Compare two integers in constant time without an early return.

    Suitable for values in [0, 2^53) where exact equality is required.
    """
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("arguments must be int")
    diff = a ^ b
    return diff == 0


# --------------------------------------------------------------------- #
# Constant-time selection (no data-dependent branch)
# --------------------------------------------------------------------- #


def constant_time_select(flag: int, a: bytes, b: bytes) -> bytes:
    """
    Return `a` if flag == 1, else `b`, without branching on `flag`.

    `a` and `b` must have the same length. Used for very small
    security-critical choices; not a general-purpose primitive.
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        raise TypeError("a and b must be bytes")
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    if flag not in (0, 1):
        raise ValueError("flag must be 0 or 1")

    mask = -flag  # 0 -> 0x00000000, 1 -> 0xFFFFFFFF
    out = bytearray(len(a))
    for i in range(len(a)):
        out[i] = (a[i] & mask) | (b[i] & ~mask & 0xFF)
    return bytes(out)


# --------------------------------------------------------------------- #
# Secure randomness
# --------------------------------------------------------------------- #


def secure_random_bytes(n: int) -> bytes:
    if n <= 0:
        raise ValueError("n must be > 0")
    return secrets.token_bytes(n)


def secure_random_int(low: int, high: int) -> int:
    if low >= high:
        raise ValueError("low must be < high")
    return secrets.randbelow(high - low) + low


# --------------------------------------------------------------------- #
# Optional randomized delay (testing/UX only)
# --------------------------------------------------------------------- #


def random_delay(min_ms: int = 0, max_ms: int = 50) -> None:
    """
    Sleep for a random duration in [min_ms, max_ms] milliseconds.

    NOT a security mechanism. Provided only for experiments and for
    deliberately slowing down brute-force attempts in some callers.
    """
    if min_ms < 0 or max_ms < min_ms:
        raise ValueError("invalid delay range")
    if max_ms == 0:
        return
    delta = max_ms - min_ms
    delay = (min_ms + secrets.randbelow(delta + 1)) / 1000.0
    time.sleep(delay)