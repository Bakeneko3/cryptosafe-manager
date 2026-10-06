"""Tests for src/core/security/side_channel_protection.py (SC-1, TEST-1)."""

import time

import pytest

from src.core.security.side_channel_protection import (
    constant_time_compare,
    constant_time_equals_int,
    constant_time_equals_str,
    constant_time_select,
    random_delay,
    secure_random_bytes,
    secure_random_int,
)


# --------------------------------------------------------------------- #
# constant_time_compare
# --------------------------------------------------------------------- #


def test_compare_equal() -> None:
    assert constant_time_compare(b"abc", b"abc") is True


def test_compare_different() -> None:
    assert constant_time_compare(b"abc", b"abd") is False


def test_compare_length_mismatch() -> None:
    assert constant_time_compare(b"abc", b"ab") is False


def test_compare_empty() -> None:
    assert constant_time_compare(b"", b"") is True


def test_compare_rejects_str() -> None:
    with pytest.raises(TypeError):
        constant_time_compare("abc", b"abc")  # type: ignore[arg-type]


def test_compare_bytearray_accepted() -> None:
    assert constant_time_compare(bytearray(b"x"), bytearray(b"x")) is True


# --------------------------------------------------------------------- #
# String/int versions
# --------------------------------------------------------------------- #


def test_equals_str_equal() -> None:
    assert constant_time_equals_str("hello", "hello") is True


def test_equals_str_different() -> None:
    assert constant_time_equals_str("hello", "hellp") is False


def test_equals_str_unicode() -> None:
    assert constant_time_equals_str("Привет", "Привет") is True


def test_equals_int_equal() -> None:
    assert constant_time_equals_int(12345, 12345) is True


def test_equals_int_different() -> None:
    assert constant_time_equals_int(12345, 12346) is False


# --------------------------------------------------------------------- #
# constant_time_select
# --------------------------------------------------------------------- #


def test_select_flag_1_returns_a() -> None:
    assert constant_time_select(1, b"A" * 4, b"B" * 4) == b"A" * 4


def test_select_flag_0_returns_b() -> None:
    assert constant_time_select(0, b"A" * 4, b"B" * 4) == b"B" * 4


def test_select_length_mismatch() -> None:
    with pytest.raises(ValueError):
        constant_time_select(1, b"A", b"BB")


def test_select_bad_flag() -> None:
    with pytest.raises(ValueError):
        constant_time_select(2, b"A", b"B")


# --------------------------------------------------------------------- #
# Secure randomness
# --------------------------------------------------------------------- #


def test_secure_random_bytes_length() -> None:
    assert len(secure_random_bytes(16)) == 16


def test_secure_random_bytes_unique() -> None:
    seen = {secure_random_bytes(16) for _ in range(50)}
    assert len(seen) == 50


def test_secure_random_bytes_rejects_zero() -> None:
    with pytest.raises(ValueError):
        secure_random_bytes(0)


def test_secure_random_int_range() -> None:
    for _ in range(100):
        v = secure_random_int(10, 20)
        assert 10 <= v < 20


def test_secure_random_int_bad_range() -> None:
    with pytest.raises(ValueError):
        secure_random_int(20, 10)


# --------------------------------------------------------------------- #
# random_delay
# --------------------------------------------------------------------- #


def test_random_delay_zero() -> None:
    start = time.monotonic()
    random_delay(0, 0)
    assert time.monotonic() - start < 0.01


def test_random_delay_positive() -> None:
    start = time.monotonic()
    random_delay(5, 15)
    elapsed = time.monotonic() - start
    assert elapsed >= 0.004
    assert elapsed < 0.2


# --------------------------------------------------------------------- #
# TEST-1: constant-time behavior (relative comparison)
# --------------------------------------------------------------------- #


def test_compare_time_roughly_constant() -> None:
    """
    Rough sanity check that comparison time does not depend on the
    position of the first differing byte. Very loose thresholds; the
    interpreter dominates the actual measurement.
    """
    a = b"A" * 32 + b"X" * 32
    b_same_prefix = b"A" * 64
    b_diff_early = b"Z" + b"A" * 63

    iterations = 2000

    def measure(other: bytes) -> float:
        start = time.perf_counter()
        for _ in range(iterations):
            constant_time_compare(a, other)
        return time.perf_counter() - start

    t_early = measure(b_diff_early)
    t_late = measure(b_same_prefix)

    # Allow very generous slack; both should be within ~5x of each other.
    ratio = max(t_early, t_late) / max(min(t_early, t_late), 1e-9)
    assert ratio < 5.0