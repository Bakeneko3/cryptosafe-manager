"""Tests for src/core/audit/log_verifier.py (VER-1, VER-3, TEST-1)."""

from pathlib import Path

import pytest

from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_verifier import LogVerifier, VerificationReport
from src.core.crypto.key_derivation import KeyDerivation
from src.core.events import EventBus, UserLoggedIn
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
def db(tmp_path: Path) -> Database:
    d = Database(tmp_path / "verify.db")
    yield d
    d.close()


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    m = KeyManager(db, key_derivation=fast_kd)
    m.create_vault(STRONG)
    return m


@pytest.fixture
def populated(db: Database, km: KeyManager) -> Database:
    bus = EventBus()
    logger = AuditLogger(db, bus, key_manager=km)
    # Create genesis + several entries via manual log_event.
    logger.log_event("test_a", details={"i": 1})
    logger.log_event("test_b", details={"i": 2})
    logger.log_event("test_c", details={"i": 3})
    return db


# --------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------- #


def test_verify_empty_log(populated: Database, km: KeyManager) -> None:
    """After three log_event calls, the log has 4 entries (genesis + 3)."""
    verifier = LogVerifier(km)
    report = verifier.verify_all()
    assert isinstance(report, VerificationReport)
    assert report.verified is True
    assert report.total_entries == 4
    assert report.valid_entries == 4


def test_verify_returns_ok_summary(populated: Database, km: KeyManager) -> None:
    report = LogVerifier(km).verify_all()
    assert "OK" in report.summary()


def test_verify_requires_unlocked_vault(populated: Database, km: KeyManager) -> None:
    km.lock()
    with pytest.raises(RuntimeError, match="unlocked"):
        LogVerifier(km).verify_all()


# --------------------------------------------------------------------- #
# TEST-1: tampering detection
# --------------------------------------------------------------------- #


def test_detects_tampered_signature(populated: Database, km: KeyManager) -> None:
    # Corrupt the signature of the second entry.
    populated.execute(
        """
        UPDATE audit_log
        SET signature = '00' || substr(signature, 3)
        WHERE sequence_number = 2
        """
    )
    report = LogVerifier(km).verify_all()
    assert report.verified is False
    assert any(
        "invalid signature" in e.reason for e in report.errors
    )


def test_detects_tampered_ciphertext(populated: Database, km: KeyManager) -> None:
    # Flip a byte in the encrypted blob of the last entry.
    row = populated.fetch_one(
        "SELECT sequence_number, entry_data FROM audit_log ORDER BY sequence_number DESC LIMIT 1"
    )
    blob = bytearray(row["entry_data"])
    blob[-1] ^= 0xFF
    populated.execute(
        "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
        (bytes(blob), row["sequence_number"]),
    )

    report = LogVerifier(km).verify_all()
    assert report.verified is False
    assert any("decryption failed" in e.reason for e in report.errors)


def test_detects_broken_chain(populated: Database, km: KeyManager) -> None:
    """Modify previous_hash of an entry to break the chain."""
    populated.execute(
        """
        UPDATE audit_log
        SET previous_hash = 'deadbeef' || substr(previous_hash, 9)
        WHERE sequence_number = 3
        """
    )
    report = LogVerifier(km).verify_all()
    assert report.verified is False
    assert any("hash chain broken" in e.reason for e in report.errors)


# --------------------------------------------------------------------- #
# Range verification (VER-2 helper)
# --------------------------------------------------------------------- #


def test_verify_range(populated: Database, km: KeyManager) -> None:
    report = LogVerifier(km).verify_range(1, 3)
    assert report.total_entries == 3
    assert report.valid_entries == 3


def test_verify_range_detects_bad_signature(populated: Database, km: KeyManager) -> None:
    populated.execute(
        """
        UPDATE audit_log
        SET signature = '00' || substr(signature, 3)
        WHERE sequence_number = 2
        """
    )
    report = LogVerifier(km).verify_range(1, 4)
    assert report.verified is False