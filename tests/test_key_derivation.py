"""
Tests for src/core/crypto/key_derivation.py.

Covers:
  * TEST-1: Argon2 parameter validation.
  * TEST-2: Key derivation consistency.
  * TEST-3: Password verification behaviour (constant-time is provided
            by argon2-cffi; we test that failures do not raise and that
            tampering is detected).
"""

import pytest

from src.core import config
from src.core.crypto.key_derivation import (
    Argon2Params,
    InvalidParameterError,
    KeyDerivation,
)


# --------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------- #


@pytest.fixture
def kd() -> KeyDerivation:
    """Default KeyDerivation with production-like parameters."""
    # Use small parameters to keep tests fast (see TEST-1 for real ones).
    return KeyDerivation(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        pbkdf2_iterations=1000,
    )


# --------------------------------------------------------------------- #
# TEST-1: Argon2 parameter validation
# --------------------------------------------------------------------- #


def test_default_parameters_match_config() -> None:
    kd = KeyDerivation()
    p = kd.params
    assert p.time_cost == config.ARGON2_TIME_COST
    assert p.memory_cost == config.ARGON2_MEMORY_COST
    assert p.parallelism == config.ARGON2_PARALLELISM
    assert p.hash_len == config.ARGON2_HASH_LEN
    assert p.salt_len == config.ARGON2_SALT_LEN
    assert kd.pbkdf2_iterations == config.PBKDF2_ITERATIONS


def test_create_auth_hash_produces_valid_argon2id_string() -> None:
    kd = KeyDerivation(time_cost=1, memory_cost=8192, parallelism=1)
    h = kd.create_auth_hash("correct horse battery staple")
    assert h.startswith("$argon2id$")


def test_different_parameter_combinations_produce_valid_hashes() -> None:
    """TEST-1: several parameter sets must all produce verifiable hashes."""
    combos = [
        dict(time_cost=1, memory_cost=8192, parallelism=1),
        dict(time_cost=2, memory_cost=16384, parallelism=2),
        dict(time_cost=3, memory_cost=32768, parallelism=4),
    ]
    for params in combos:
        kd = KeyDerivation(**params)
        h = kd.create_auth_hash("hunter2-very-strong")
        assert kd.verify_password("hunter2-very-strong", h)


@pytest.mark.parametrize(
    "kwargs, match",
    [
        (dict(time_cost=0), "time_cost"),
        (dict(time_cost=config.ARGON2_MAX_TIME_COST + 1), "time_cost"),
        (dict(memory_cost=1), "memory_cost"),
        (dict(memory_cost=config.ARGON2_MAX_MEMORY_COST + 1), "memory_cost"),
        (dict(parallelism=0), "parallelism"),
        (dict(parallelism=config.ARGON2_MAX_PARALLELISM + 1), "parallelism"),
        (dict(hash_len=4), "hash_len"),
        (dict(hash_len=1024), "hash_len"),
        (dict(salt_len=2), "salt_len"),
        (dict(salt_len=1024), "salt_len"),
        (dict(pbkdf2_iterations=0), "iterations"),
        (
            dict(pbkdf2_iterations=config.PBKDF2_MAX_ITERATIONS + 1),
            "iterations",
        ),
    ],
)
def test_invalid_parameters_are_rejected(kwargs, match) -> None:
    with pytest.raises(InvalidParameterError, match=match):
        KeyDerivation(**kwargs)


# --------------------------------------------------------------------- #
# HASH-1 / HASH-2: correct variant and defaults
# --------------------------------------------------------------------- #


def test_auth_hash_uses_argon2id_variant() -> None:
    kd = KeyDerivation(time_cost=1, memory_cost=8192, parallelism=1)
    h = kd.create_auth_hash("some-password-123!")
    assert "$argon2id$" in h


# --------------------------------------------------------------------- #
# HASH-3: verification behaviour
# --------------------------------------------------------------------- #


def test_verify_password_accepts_correct_password(kd: KeyDerivation) -> None:
    h = kd.create_auth_hash("s3cr3t-password")
    assert kd.verify_password("s3cr3t-password", h) is True


def test_verify_password_rejects_wrong_password(kd: KeyDerivation) -> None:
    h = kd.create_auth_hash("s3cr3t-password")
    assert kd.verify_password("wrong-password", h) is False


def test_verify_password_rejects_tampered_hash(kd: KeyDerivation) -> None:
    h = kd.create_auth_hash("s3cr3t-password")
    tampered = h[:-1] + ("A" if h[-1] != "A" else "B")
    assert kd.verify_password("s3cr3t-password", tampered) is False


def test_verify_password_with_empty_inputs_returns_false(kd: KeyDerivation) -> None:
    assert kd.verify_password("", "whatever") is False
    assert kd.verify_password("password", "") is False


def test_create_auth_hash_rejects_empty_password(kd: KeyDerivation) -> None:
    with pytest.raises(ValueError):
        kd.create_auth_hash("")


# --------------------------------------------------------------------- #
# KEY-1 / KEY-2: encryption key derivation
# --------------------------------------------------------------------- #


def test_derive_encryption_key_returns_32_bytes(kd: KeyDerivation) -> None:
    salt = kd.generate_salt()
    key = kd.derive_encryption_key("master-password", salt)
    assert isinstance(key, bytes)
    assert len(key) == config.PBKDF2_KEY_LEN == 32


def test_derive_encryption_key_requires_password_and_salt(kd: KeyDerivation) -> None:
    salt = kd.generate_salt()
    with pytest.raises(ValueError):
        kd.derive_encryption_key("", salt)
    with pytest.raises(ValueError):
        kd.derive_encryption_key("password", b"")


def test_derive_encryption_key_requires_min_salt_length(kd: KeyDerivation) -> None:
    # generate_salt enforces [8, 64]
    with pytest.raises(InvalidParameterError):
        kd.generate_salt(length=2)
    with pytest.raises(InvalidParameterError):
        kd.generate_salt(length=128)


# --------------------------------------------------------------------- #
# TEST-2: key derivation consistency
# --------------------------------------------------------------------- #


def test_derive_encryption_key_is_deterministic(kd: KeyDerivation) -> None:
    """TEST-2: 100 derivations with the same inputs must match."""
    salt = kd.generate_salt()
    password = "deterministic-password"
    first = kd.derive_encryption_key(password, salt)
    for _ in range(100):
        assert kd.derive_encryption_key(password, salt) == first


def test_derive_encryption_key_differs_with_different_salt(kd: KeyDerivation) -> None:
    password = "same-password"
    salt_a = kd.generate_salt()
    salt_b = kd.generate_salt()
    assert kd.derive_encryption_key(password, salt_a) != kd.derive_encryption_key(
        password, salt_b
    )


def test_derive_encryption_key_differs_with_different_password(kd: KeyDerivation) -> None:
    salt = kd.generate_salt()
    assert kd.derive_encryption_key("password-a", salt) != kd.derive_encryption_key(
        "password-b", salt
    )


# --------------------------------------------------------------------- #
# Salt generation
# --------------------------------------------------------------------- #


def test_generate_salt_returns_requested_length(kd: KeyDerivation) -> None:
    salt = kd.generate_salt(16)
    assert isinstance(salt, bytes)
    assert len(salt) == 16


def test_generate_salt_is_unique(kd: KeyDerivation) -> None:
    salts = {kd.generate_salt() for _ in range(50)}
    assert len(salts) == 50


# --------------------------------------------------------------------- #
# needs_rehash (introspection helper)
# --------------------------------------------------------------------- #


def test_needs_rehash_returns_bool(kd: KeyDerivation) -> None:
    h = kd.create_auth_hash("password-123")
    assert isinstance(kd.needs_rehash(h), bool)
    assert kd.needs_rehash("") is True


# --------------------------------------------------------------------- #
# HKDF subkey derivation (CRY-2)
# --------------------------------------------------------------------- #


def test_derive_subkey_returns_requested_length(kd: KeyDerivation) -> None:
    master = b"\x01" * 32
    key = kd.derive_subkey(master, b"context", length=32)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_derive_subkey_different_contexts_differ(kd: KeyDerivation) -> None:
    master = b"\x02" * 32
    a = kd.derive_subkey(master, b"ctx-a")
    b = kd.derive_subkey(master, b"ctx-b")
    assert a != b


def test_derive_subkey_is_deterministic(kd: KeyDerivation) -> None:
    master = b"\x03" * 32
    first = kd.derive_subkey(master, b"stable")
    for _ in range(20):
        assert kd.derive_subkey(master, b"stable") == first


def test_derive_subkey_different_master_differs(kd: KeyDerivation) -> None:
    ctx = b"same"
    a = kd.derive_subkey(b"\x01" * 32, ctx)
    b = kd.derive_subkey(b"\x02" * 32, ctx)
    assert a != b


def test_derive_subkey_rejects_empty_master(kd: KeyDerivation) -> None:
    with pytest.raises(ValueError):
        kd.derive_subkey(b"", b"ctx")


def test_derive_subkey_rejects_empty_context(kd: KeyDerivation) -> None:
    with pytest.raises(ValueError):
        kd.derive_subkey(b"\x01" * 32, b"")


def test_derive_subkey_rejects_short_length(kd: KeyDerivation) -> None:
    with pytest.raises(InvalidParameterError):
        kd.derive_subkey(b"\x01" * 32, b"ctx", length=8)


def test_derive_signing_key_length(kd: KeyDerivation) -> None:
    master = b"\x04" * 32
    seed = kd.derive_signing_key(master)
    assert len(seed) == 32


def test_derive_signing_key_differs_from_log_key(kd: KeyDerivation) -> None:
    master = b"\x05" * 32
    signing = kd.derive_signing_key(master)
    log_enc = kd.derive_log_encryption_key(master)
    assert signing != log_enc


def test_derive_log_encryption_key_length(kd: KeyDerivation) -> None:
    master = b"\x06" * 32
    key = kd.derive_log_encryption_key(master)
    assert len(key) == 32