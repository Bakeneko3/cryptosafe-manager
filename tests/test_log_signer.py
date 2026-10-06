"""Tests for src/core/audit/log_signer.py (CRY-1, CRY-2)."""

from pathlib import Path

import pytest

from src.core.audit.log_signer import LogSigner, SigningKeyUnavailableError
from src.core.crypto.key_derivation import KeyDerivation
from src.core.key_manager import KeyManager
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
    db = Database(tmp_path / "signer.db")
    manager = KeyManager(db, key_derivation=fast_kd)
    manager.create_vault(STRONG)
    yield manager
    db.close()


# --------------------------------------------------------------------- #
# Key availability
# --------------------------------------------------------------------- #


def test_signer_requires_unlocked_vault(km: KeyManager) -> None:
    km.lock()
    with pytest.raises(SigningKeyUnavailableError):
        LogSigner(km)


def test_signer_constructs_when_unlocked(km: KeyManager) -> None:
    signer = LogSigner(km)
    assert signer.public_key_bytes()


# --------------------------------------------------------------------- #
# Sign / verify
# --------------------------------------------------------------------- #


def test_sign_and_verify(km: KeyManager) -> None:
    signer = LogSigner(km)
    data = b"hello audit log"
    sig = signer.sign(data)
    assert isinstance(sig, bytes)
    assert len(sig) == 64
    assert signer.verify(data, sig) is True


def test_verify_rejects_tampered_data(km: KeyManager) -> None:
    signer = LogSigner(km)
    sig = signer.sign(b"original")
    assert signer.verify(b"modified", sig) is False


def test_verify_rejects_tampered_signature(km: KeyManager) -> None:
    signer = LogSigner(km)
    sig = bytearray(signer.sign(b"data"))
    sig[0] ^= 0xFF
    assert signer.verify(b"data", bytes(sig)) is False


def test_verify_rejects_garbage_signature(km: KeyManager) -> None:
    signer = LogSigner(km)
    assert signer.verify(b"data", b"\x00" * 64) is False


def test_sign_is_deterministic_ed25519(km: KeyManager) -> None:
    """Ed25519 signatures are deterministic."""
    signer = LogSigner(km)
    s1 = signer.sign(b"same")
    s2 = signer.sign(b"same")
    assert s1 == s2


# --------------------------------------------------------------------- #
# Public key
# --------------------------------------------------------------------- #


def test_public_key_is_32_bytes(km: KeyManager) -> None:
    signer = LogSigner(km)
    assert len(signer.public_key_bytes()) == 32


def test_public_key_hex(km: KeyManager) -> None:
    signer = LogSigner(km)
    assert signer.public_key_hex() == signer.public_key_bytes().hex()
    assert len(signer.public_key_hex()) == 64


def test_public_key_is_deterministic(km: KeyManager) -> None:
    signer1 = LogSigner(km)
    signer2 = LogSigner(km)
    assert signer1.public_key_bytes() == signer2.public_key_bytes()


def test_public_key_changes_on_password_change(km: KeyManager) -> None:
    signer1 = LogSigner(km)
    pub1 = signer1.public_key_bytes()

    km.change_password(STRONG, "Another-Strong-Pass-99$")

    signer2 = LogSigner(km)
    pub2 = signer2.public_key_bytes()
    assert pub1 != pub2


# --------------------------------------------------------------------- #
# Static verification
# --------------------------------------------------------------------- #


def test_verify_with_public_key(km: KeyManager) -> None:
    signer = LogSigner(km)
    data = b"verify me"
    sig = signer.sign(data)
    pub = signer.public_key_bytes()

    assert LogSigner.verify_with_public_key(data, sig, pub) is True


def test_verify_with_wrong_public_key(km: KeyManager) -> None:
    signer = LogSigner(km)
    data = b"verify me"
    sig = signer.sign(data)
    wrong_pub = b"\x00" * 32

    assert LogSigner.verify_with_public_key(data, sig, wrong_pub) is False


def test_verify_with_malformed_public_key(km: KeyManager) -> None:
    signer = LogSigner(km)
    data = b"x"
    sig = signer.sign(data)
    assert LogSigner.verify_with_public_key(data, sig, b"\x00" * 16) is False