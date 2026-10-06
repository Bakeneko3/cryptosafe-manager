"""Tests for src/core/audit/log_formatters.py (EXP-1, EXP-2, EXP-3)."""

import csv
import json
from pathlib import Path

import pytest

from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_formatters import AuditExporter
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
    d = Database(tmp_path / "export.db")
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
    logger.log_event("test_alpha", source="test", severity="INFO", details={"a": 1})
    logger.log_event("test_beta", source="test", severity="WARN", details={"b": 2})
    logger.log_event("test_gamma", source="test", severity="ERROR", details={"c": 3})
    return db


@pytest.fixture
def exporter(populated: Database, km: KeyManager) -> AuditExporter:
    return AuditExporter(populated, km)


# --------------------------------------------------------------------- #
# Signed JSON (EXP-2)
# --------------------------------------------------------------------- #


def test_export_signed_json_creates_file(exporter: AuditExporter, tmp_path: Path) -> None:
    out = tmp_path / "log.json"
    exporter.export_signed_json(out)
    assert out.exists()
    assert out.stat().st_size > 0


def test_export_signed_json_structure(exporter: AuditExporter, tmp_path: Path) -> None:
    out = tmp_path / "log.json"
    exporter.export_signed_json(out)
    doc = json.loads(out.read_text(encoding="utf-8"))

    assert doc["format"] == "cryptosafe-audit-log"
    assert doc["format_version"] == 1
    assert "exported_at" in doc
    assert doc["entry_count"] == 4  # genesis + 3
    assert "public_key_hex" in doc
    assert len(doc["public_key_hex"]) == 64
    assert len(doc["entries"]) == 4


def test_export_signed_json_entries_have_signatures(
    exporter: AuditExporter, tmp_path: Path
) -> None:
    out = tmp_path / "log.json"
    exporter.export_signed_json(out)
    doc = json.loads(out.read_text(encoding="utf-8"))

    for entry in doc["entries"]:
        assert "signature" in entry
        assert len(entry["signature"]) == 128  # 64 bytes hex
        assert "payload" in entry
        assert "previous_hash" in entry


def test_export_signed_json_contains_genesis(
    exporter: AuditExporter, tmp_path: Path
) -> None:
    out = tmp_path / "log.json"
    exporter.export_signed_json(out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    types = [e["event_type"] for e in doc["entries"]]
    assert "system_genesis" in types


# --------------------------------------------------------------------- #
# CSV (EXP-1)
# --------------------------------------------------------------------- #


def test_export_csv_creates_file(exporter: AuditExporter, tmp_path: Path) -> None:
    out = tmp_path / "log.csv"
    exporter.export_csv(out)
    assert out.exists()


def test_export_csv_has_header_and_rows(
    exporter: AuditExporter, tmp_path: Path
) -> None:
    out = tmp_path / "log.csv"
    exporter.export_csv(out)

    with out.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        rows = list(reader)

    assert rows[0][0] == "sequence_number"
    assert len(rows) == 5  # header + 4 entries


def test_export_csv_entries_match(exporter: AuditExporter, tmp_path: Path) -> None:
    out = tmp_path / "log.csv"
    exporter.export_csv(out)

    with out.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    types = [r["event_type"] for r in rows]
    assert "system_genesis" in types
    assert "test_alpha" in types
    assert "test_beta" in types
    assert "test_gamma" in types


# --------------------------------------------------------------------- #
# PDF (EXP-1)
# --------------------------------------------------------------------- #


def test_export_pdf_creates_file(exporter: AuditExporter, tmp_path: Path) -> None:
    out = tmp_path / "log.pdf"
    exporter.export_pdf(out)
    assert out.exists()
    assert out.stat().st_size > 0
    # Basic PDF magic check.
    assert out.read_bytes()[:5] == b"%PDF-"


# --------------------------------------------------------------------- #
# Locked vault
# --------------------------------------------------------------------- #


def test_export_fails_when_locked(populated: Database, km: KeyManager, tmp_path: Path) -> None:
    km.lock()
    exp = AuditExporter(populated, km)
    with pytest.raises(RuntimeError, match="unlocked"):
        exp.export_signed_json(tmp_path / "x.json")