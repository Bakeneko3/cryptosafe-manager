"""Tests for src/core/crypto/abstract.py and placeholder.py (ARC-2)."""

from pathlib import Path

import pytest

from src.core.crypto.abstract import EncryptionService
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"


# --------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------- #


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
    db = Database(tmp_path / "crypto.db")
    manager = KeyManager(db, key_derivation=fast_kd)
    manager.create_vault(STRONG)
    yield manager
    db.close()


@pytest.fixture
def service(km: KeyManager) -> AES256Placeholder:
    return AES256Placeholder(km)


# --------------------------------------------------------------------- #
# EncryptionService interface
# --------------------------------------------------------------------- #


def test_encryption_service_is_abstract() -> None:
    with pytest.raises(TypeError):
        EncryptionService(None)  # type: ignore[abstract]


def test_placeholder_is_a_subclass() -> None:
    assert issubclass(AES256Placeholder, EncryptionService)


def test_service_exposes_key_manager(service: AES256Placeholder, km: KeyManager) -> None:
    assert service.key_manager is km


# --------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------- #


def test_encrypt_decrypt_roundtrip(service: AES256Placeholder) -> None:
    plaintext = b"hello world"
    ciphertext = service.encrypt(plaintext)
    assert ciphertext != plaintext
    assert service.decrypt(ciphertext) == plaintext


def test_roundtrip_with_empty_data(service: AES256Placeholder) -> None:
    assert service.decrypt(service.encrypt(b"")) == b""


def test_roundtrip_with_binary_data(service: AES256Placeholder) -> None:
    payload = bytes(range(256))
    assert service.decrypt(service.encrypt(payload)) == payload


def test_roundtrip_with_long_data(service: AES256Placeholder) -> None:
    payload = b"a" * 10_000
    assert service.decrypt(service.encrypt(payload)) == payload


# --------------------------------------------------------------------- #
# Key from KeyManager (ARC-2)
# --------------------------------------------------------------------- #


def test_encrypt_uses_key_from_key_manager(km: KeyManager) -> None:
    """
    Two services bound to the same KeyManager must produce compatible
    ciphertexts (same key).
    """
    a = AES256Placeholder(km)
    b = AES256Placeholder(km)

    ct = a.encrypt(b"shared secret")
    assert b.decrypt(ct) == b"shared secret"


def test_service_fails_when_vault_locked(service: AES256Placeholder) -> None:
    service.key_manager.lock()
    with pytest.raises(RuntimeError, match="locked"):
        service.encrypt(b"data")
    with pytest.raises(RuntimeError, match="locked"):
        service.decrypt(b"data")


def test_service_works_again_after_unlock(service: AES256Placeholder) -> None:
    ct = service.encrypt(b"secret")
    service.key_manager.lock()
    service.key_manager.unlock(STRONG)
    assert service.decrypt(ct) == b"secret"


# --------------------------------------------------------------------- #
# Different vaults => different keys
# --------------------------------------------------------------------- #


def test_different_vaults_produce_incompatible_ciphertexts(
    tmp_path: Path, fast_kd: KeyDerivation
) -> None:
    db_a = Database(tmp_path / "a.db")
    db_b = Database(tmp_path / "b.db")
    try:
        km_a = KeyManager(db_a, key_derivation=fast_kd)
        km_b = KeyManager(db_b, key_derivation=fast_kd)

        km_a.create_vault(STRONG)
        km_b.create_vault(STRONG)

        svc_a = AES256Placeholder(km_a)
        svc_b = AES256Placeholder(km_b)

        ct = svc_a.encrypt(b"secret")
        # b's key is different, so decrypting with b gives garbage,
        # not the original plaintext.
        assert svc_b.decrypt(ct) != b"secret"
    finally:
        db_a.close()
        db_b.close()