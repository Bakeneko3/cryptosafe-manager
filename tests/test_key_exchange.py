"""Tests for src/core/import_export/key_exchange.py (CRY-2, QR-3)."""

import pytest

from src.core.import_export.key_exchange import (
    DecryptionError,
    KeyExchangeError,
    decrypt_with_private_key,
    encrypt_with_public_key,
    fingerprint_public_key,
    generate_keypair,
)


# --------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------- #


def test_generate_rsa_keypair() -> None:
    kp = generate_keypair("rsa")
    assert kp.key_type == "rsa"
    assert b"BEGIN PUBLIC KEY" in kp.public_pem
    assert b"BEGIN PRIVATE KEY" in kp.private_pem
    assert kp.fingerprint


def test_generate_ec_keypair() -> None:
    kp = generate_keypair("ec")
    assert kp.key_type == "ec"
    assert b"BEGIN PUBLIC KEY" in kp.public_pem


def test_generate_invalid_type() -> None:
    with pytest.raises(KeyExchangeError):
        generate_keypair("dsa")  # type: ignore[arg-type]


def test_two_keypairs_differ() -> None:
    a = generate_keypair("rsa")
    b = generate_keypair("rsa")
    assert a.public_pem != b.public_pem
    assert a.fingerprint != b.fingerprint


# --------------------------------------------------------------------- #
# Fingerprint
# --------------------------------------------------------------------- #


def test_fingerprint_format() -> None:
    kp = generate_keypair("rsa")
    fp = kp.fingerprint
    # Format: XXXX:XXXX:... 16 groups of 4 hex chars
    parts = fp.split(":")
    assert len(parts) == 16
    for p in parts:
        assert len(p) == 4
        int(p, 16)


def test_fingerprint_deterministic() -> None:
    kp = generate_keypair("rsa")
    assert fingerprint_public_key(kp.public_pem) == kp.fingerprint


def test_fingerprint_invalid_key() -> None:
    with pytest.raises(KeyExchangeError):
        fingerprint_public_key(b"not a key")


# --------------------------------------------------------------------- #
# RSA round-trip
# --------------------------------------------------------------------- #


def test_rsa_roundtrip_simple() -> None:
    kp = generate_keypair("rsa")
    data = b"secret data"
    ct = encrypt_with_public_key(data, kp.public_pem)
    assert ct != data
    assert decrypt_with_private_key(ct, kp.private_pem) == data


def test_rsa_roundtrip_empty() -> None:
    kp = generate_keypair("rsa")
    assert decrypt_with_private_key(
        encrypt_with_public_key(b"", kp.public_pem), kp.private_pem
    ) == b""


def test_rsa_roundtrip_binary() -> None:
    kp = generate_keypair("rsa")
    payload = bytes(range(256)) * 4
    assert decrypt_with_private_key(
        encrypt_with_public_key(payload, kp.public_pem), kp.private_pem
    ) == payload


def test_rsa_roundtrip_large() -> None:
    kp = generate_keypair("rsa")
    payload = b"x" * 10_000
    assert decrypt_with_private_key(
        encrypt_with_public_key(payload, kp.public_pem), kp.private_pem
    ) == payload


# --------------------------------------------------------------------- #
# ECC round-trip
# --------------------------------------------------------------------- #


def test_ec_roundtrip_simple() -> None:
    kp = generate_keypair("ec")
    data = b"secret via ecc"
    ct = encrypt_with_public_key(data, kp.public_pem)
    assert ct != data
    assert decrypt_with_private_key(ct, kp.private_pem) == data


def test_ec_roundtrip_large() -> None:
    kp = generate_keypair("ec")
    payload = b"y" * 10_000
    assert decrypt_with_private_key(
        encrypt_with_public_key(payload, kp.public_pem), kp.private_pem
    ) == payload


def test_ec_ephemeral_keys_are_fresh() -> None:
    """Each encryption must use a fresh ephemeral key."""
    kp = generate_keypair("ec")
    ct1 = encrypt_with_public_key(b"data", kp.public_pem)
    ct2 = encrypt_with_public_key(b"data", kp.public_pem)
    assert ct1 != ct2


# --------------------------------------------------------------------- #
# Decryption failures
# --------------------------------------------------------------------- #


def test_rsa_wrong_private_key() -> None:
    kp1 = generate_keypair("rsa")
    kp2 = generate_keypair("rsa")
    ct = encrypt_with_public_key(b"data", kp1.public_pem)
    with pytest.raises(DecryptionError):
        decrypt_with_private_key(ct, kp2.private_pem)


def test_rsa_tampered_ciphertext() -> None:
    kp = generate_keypair("rsa")
    ct = bytearray(encrypt_with_public_key(b"data", kp.public_pem))
    ct[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt_with_private_key(bytes(ct), kp.private_pem)


def test_rsa_truncated_ciphertext() -> None:
    kp = generate_keypair("rsa")
    with pytest.raises(DecryptionError):
        decrypt_with_private_key(b"\x00\x00", kp.private_pem)


def test_ec_wrong_private_key() -> None:
    kp1 = generate_keypair("ec")
    kp2 = generate_keypair("ec")
    ct = encrypt_with_public_key(b"data", kp1.public_pem)
    with pytest.raises(DecryptionError):
        decrypt_with_private_key(ct, kp2.private_pem)


# --------------------------------------------------------------------- #
# Cross-type
# --------------------------------------------------------------------- #


def test_rsa_and_ec_are_incompatible() -> None:
    rsa_kp = generate_keypair("rsa")
    ec_kp = generate_keypair("ec")
    ct_rsa = encrypt_with_public_key(b"data", rsa_kp.public_pem)
    with pytest.raises(DecryptionError):
        decrypt_with_private_key(ct_rsa, ec_kp.private_pem)