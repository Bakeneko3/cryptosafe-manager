"""Tests for src/core/vault/encryption_service.py (ENC-1..5, TEST-1)."""

import os
from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.key_manager import KeyManager
from src.core.vault.encryption_service import (
    MIN_CIPHERTEXT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    AESGCMService,
    DecryptionError,
)
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
def km(tmp_path: Path, fast_kd: KeyDerivation) -> KeyManager:
    db = Database(tmp_path / "gcm.db")
    manager = KeyManager(db, key_derivation=fast_kd)
    manager.create_vault(STRONG)
    yield manager
    db.close()


@pytest.fixture
def service(km: KeyManager) -> AESGCMService:
    return AESGCMService(km)


# --------------------------------------------------------------------- #
# TEST-1: round-trip encryption (ENC-1)
# --------------------------------------------------------------------- #


def test_roundtrip_simple(service: AESGCMService) -> None:
    plaintext = b"hello world"
    ct = service.encrypt(plaintext)
    assert ct != plaintext
    assert service.decrypt(ct) == plaintext


def test_roundtrip_empty(service: AESGCMService) -> None:
    ct = service.encrypt(b"")
    assert service.decrypt(ct) == b""


def test_roundtrip_binary(service: AESGCMService) -> None:
    payload = bytes(range(256))
    assert service.decrypt(service.encrypt(payload)) == payload


def test_roundtrip_long(service: AESGCMService) -> None:
    payload = os.urandom(100_000)
    assert service.decrypt(service.encrypt(payload)) == payload


def test_roundtrip_unicode_bytes(service: AESGCMService) -> None:
    payload = "Привет, мир! 你好 🎉".encode("utf-8")
    assert service.decrypt(service.encrypt(payload)) == payload


# --------------------------------------------------------------------- #
# ENC-2: unique nonce per operation
# --------------------------------------------------------------------- #


def test_unique_nonce_per_encryption(service: AESGCMService) -> None:
    plaintext = b"same plaintext"
    ct1 = service.encrypt(plaintext)
    ct2 = service.encrypt(plaintext)

    assert ct1 != ct2

    nonce1 = ct1[:NONCE_SIZE]
    nonce2 = ct2[:NONCE_SIZE]
    assert nonce1 != nonce2


def test_many_encryptions_have_unique_nonces(service: AESGCMService) -> None:
    nonces = set()
    for _ in range(100):
        ct = service.encrypt(b"x")
        nonces.add(ct[:NONCE_SIZE])
    assert len(nonces) == 100


# --------------------------------------------------------------------- #
# ENC-4: wire format
# --------------------------------------------------------------------- #


def test_ciphertext_length_matches_format(service: AESGCMService) -> None:
    plaintext = b"a" * 50
    ct = service.encrypt(plaintext)
    # nonce (12) + plaintext (50) + tag (16)
    assert len(ct) == NONCE_SIZE + len(plaintext) + TAG_SIZE


def test_min_ciphertext_size_for_empty_plaintext(service: AESGCMService) -> None:
    ct = service.encrypt(b"")
    assert len(ct) == MIN_CIPHERTEXT_SIZE


# --------------------------------------------------------------------- #
# ENC-5: tampering detection
# --------------------------------------------------------------------- #


def test_tampered_ciphertext_raises(service: AESGCMService) -> None:
    ct = bytearray(service.encrypt(b"secret data"))
    # Flip a byte in the ciphertext body (not in the nonce).
    ct[NONCE_SIZE + 1] ^= 0xFF
    with pytest.raises(DecryptionError):
        service.decrypt(bytes(ct))


def test_tampered_nonce_raises(service: AESGCMService) -> None:
    ct = bytearray(service.encrypt(b"secret data"))
    ct[0] ^= 0xFF
    with pytest.raises(DecryptionError):
        service.decrypt(bytes(ct))


def test_truncated_ciphertext_raises(service: AESGCMService) -> None:
    ct = service.encrypt(b"secret data")
    with pytest.raises(DecryptionError):
        service.decrypt(ct[:10])


def test_empty_ciphertext_raises(service: AESGCMService) -> None:
    with pytest.raises(DecryptionError):
        service.decrypt(b"")


# --------------------------------------------------------------------- #
# ARC-3: service bound to KeyManager
# --------------------------------------------------------------------- #


def test_service_fails_when_locked(service: AESGCMService, km: KeyManager) -> None:
    ct = service.encrypt(b"data")
    km.lock()
    with pytest.raises(RuntimeError, match="locked"):
        service.encrypt(b"more data")
    with pytest.raises(RuntimeError, match="locked"):
        service.decrypt(ct)


def test_service_works_after_unlock(
    service: AESGCMService, km: KeyManager
) -> None:
    ct = service.encrypt(b"data")
    km.lock()
    km.unlock(STRONG)
    assert service.decrypt(ct) == b"data"


def test_different_vaults_are_incompatible(
    tmp_path: Path, fast_kd: KeyDerivation
) -> None:
    db_a = Database(tmp_path / "a.db")
    db_b = Database(tmp_path / "b.db")
    try:
        km_a = KeyManager(db_a, key_derivation=fast_kd)
        km_b = KeyManager(db_b, key_derivation=fast_kd)
        km_a.create_vault(STRONG)
        km_b.create_vault(STRONG)

        svc_a = AESGCMService(km_a)
        svc_b = AESGCMService(km_b)

        ct = svc_a.encrypt(b"secret")
        with pytest.raises(DecryptionError):
            svc_b.decrypt(ct)
    finally:
        db_a.close()
        db_b.close()


# --------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------- #


def test_encrypt_rejects_str(service: AESGCMService) -> None:
    with pytest.raises(TypeError):
        service.encrypt("string")  # type: ignore[arg-type]


def test_decrypt_rejects_str(service: AESGCMService) -> None:
    with pytest.raises(TypeError):
        service.decrypt("string")  # type: ignore[arg-type]