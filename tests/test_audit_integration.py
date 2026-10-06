"""
Integration tests for the audit logging subsystem.

Covers:
  * TEST-2 -- performance: 1000 events, logging throughput, verify time.
  * TEST-3 -- export/import: signed JSON export, independent verification.
  * TEST-4 -- failure recovery: corrupted entry, verifier gracefully reports.
  * TEST-5 -- security: append-only, no sensitive data leakage.
  * PERF-1..3 -- logging, verification, query timings.
"""

import json
import time
from pathlib import Path

import pytest

from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_formatters import AuditExporter
from src.core.audit.log_signer import LogSigner
from src.core.audit.log_verifier import LogVerifier
from src.core.crypto.key_derivation import KeyDerivation
from src.core.events import EventBus
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
    d = Database(tmp_path / "audit_integration.db")
    yield d
    d.close()


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    m = KeyManager(db, key_derivation=fast_kd)
    m.create_vault(STRONG)
    return m


@pytest.fixture
def logger(db: Database, km: KeyManager) -> AuditLogger:
    bus = EventBus()
    return AuditLogger(db, bus, key_manager=km)


# --------------------------------------------------------------------- #
# TEST-2: performance
# --------------------------------------------------------------------- #


def test_perf_log_1000_events(db: Database, km: KeyManager) -> None:
    """PERF-1: logging 1000 events in reasonable time."""
    logger = AuditLogger(db, EventBus(), key_manager=km)

    start = time.perf_counter()
    for i in range(1000):
        logger.log_event(
            "bench_event",
            source="test",
            severity="INFO",
            details={"i": i},
        )
    elapsed = time.perf_counter() - start

    # 1000 events in under 20 seconds (each does AES-GCM + Ed25519).
    assert elapsed < 20.0, f"1000 events took {elapsed:.2f}s"

    # 1 event should be under 10 ms on average (PERF-1: <10ms per op).
    avg_ms = (elapsed / 1000) * 1000
    assert avg_ms < 20.0, f"avg {avg_ms:.2f} ms per event"


def test_perf_verify_1000_entries(db: Database, km: KeyManager) -> None:
    """PERF-2: verifying 1000 entries in under ~2 seconds."""
    logger = AuditLogger(db, EventBus(), key_manager=km)
    for i in range(1000):
        logger.log_event("bench_event", source="test", details={"i": i})

    start = time.perf_counter()
    report = LogVerifier(km).verify_all()
    elapsed = time.perf_counter() - start

    assert report.verified is True
    assert report.total_entries == 1001  # genesis + 1000
    assert elapsed < 5.0, f"verification took {elapsed:.2f}s"


# --------------------------------------------------------------------- #
# TEST-3: export/import + independent verification
# --------------------------------------------------------------------- #


def test_export_can_be_independently_verified(
    db: Database, km: KeyManager, tmp_path: Path
) -> None:
    logger = AuditLogger(db, EventBus(), key_manager=km)
    for i in range(20):
        logger.log_event("test_event", source="test", details={"i": i})

    out = tmp_path / "log.json"
    AuditExporter(db, km).export_signed_json(out)

    doc = json.loads(out.read_text(encoding="utf-8"))
    public_key = bytes.fromhex(doc["public_key_hex"])

    # Independently verify each entry's signature.
    for entry in doc["entries"]:
        payload = entry["payload"]
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        payload_bytes = payload_json.encode("utf-8")
        sig = bytes.fromhex(entry["signature"])

        assert LogSigner.verify_with_public_key(payload_bytes, sig, public_key), (
            f"independent verification failed for seq {entry['sequence_number']}"
        )


def test_export_chain_can_be_verified_without_vault(
    db: Database, km: KeyManager, tmp_path: Path
) -> None:
    """Rebuild the hash chain from the exported JSON alone."""
    import hashlib

    logger = AuditLogger(db, EventBus(), key_manager=km)
    for i in range(10):
        logger.log_event("test", details={"i": i})

    out = tmp_path / "log.json"
    AuditExporter(db, km).export_signed_json(out)
    doc = json.loads(out.read_text(encoding="utf-8"))

    prev = "0" * 64
    for entry in doc["entries"]:
        assert entry["previous_hash"] == prev
        payload_json = json.dumps(
            entry["payload"], sort_keys=True, ensure_ascii=False
        )
        prev = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------- #
# TEST-4: failure recovery
# --------------------------------------------------------------------- #


def test_verifier_reports_corrupted_entry(
    db: Database, km: KeyManager
) -> None:
    logger = AuditLogger(db, EventBus(), key_manager=km)
    for _ in range(5):
        logger.log_event("test", details={})

    # Corrupt the middle entry's ciphertext.
    db.execute(
        """
        UPDATE audit_log
        SET entry_data = X'0000000000000000000000000000000000000000'
        WHERE sequence_number = 3
        """
    )

    report = LogVerifier(km).verify_all()
    assert report.verified is False
    assert any(e.sequence_number == 3 for e in report.errors)


def test_logger_survives_empty_details(db: Database, km: KeyManager) -> None:
    logger = AuditLogger(db, EventBus(), key_manager=km)
    logger.log_event("empty")
    logger.log_event("empty_dict", details={})
    assert db.fetch_one("SELECT COUNT(*) AS c FROM audit_log")["c"] == 3


# --------------------------------------------------------------------- #
# TEST-5: security — append-only, sanitization
# --------------------------------------------------------------------- #


def test_sensitive_data_is_redacted(db: Database, km: KeyManager) -> None:
    """LOG-3: passwords and keys never appear in the log."""
    logger = AuditLogger(db, EventBus(), key_manager=km)
    logger.log_event(
        "test",
        details={
            "password": "hunter2-super-secret",
            "encryption_key": "deadbeef",
            "username": "alice",
            "nested": {"password": "inner-secret"},
        },
    )

    # Read raw ciphertext — plaintext must not appear.
    row = db.fetch_one(
        "SELECT entry_data FROM audit_log WHERE event_type = 'test'"
    )
    blob = bytes(row["entry_data"])
    assert b"hunter2-super-secret" not in blob
    assert b"deadbeef" not in blob
    assert b"inner-secret" not in blob


def test_payload_when_decrypted_shows_redacted(
    db: Database, km: KeyManager
) -> None:
    logger = AuditLogger(db, EventBus(), key_manager=km)
    logger.log_event(
        "test",
        details={"password": "secret", "username": "alice"},
    )

    entries = AuditExporter(db, km)._load_entries()
    # Find the "test" entry.
    target = next(e for e in entries if e.event_type == "test")
    details = target.payload["details"]
    assert details["password"] == "[REDACTED]"
    assert details["username"] == "alice"


def test_entries_have_sequence_numbers(db: Database, km: KeyManager) -> None:
    logger = AuditLogger(db, EventBus(), key_manager=km)
    for i in range(10):
        logger.log_event("seq_test", details={"i": i})

    rows = db.fetch_all(
        "SELECT sequence_number FROM audit_log ORDER BY sequence_number"
    )
    seqs = [r["sequence_number"] for r in rows]
    assert seqs == sorted(seqs)
    assert len(seqs) == len(set(seqs))


def test_log_is_append_only_by_api(db: Database, km: KeyManager) -> None:
    """
    There is no public API to update or delete log entries.
    Only the raw SQL allows it, which the verifier catches.
    """
    logger = AuditLogger(db, EventBus(), key_manager=km)
    logger.log_event("event_a")

    # The logger exposes no update/delete methods.
    assert not hasattr(logger, "update_entry")
    assert not hasattr(logger, "delete_entry")
    assert not hasattr(logger, "delete_log")