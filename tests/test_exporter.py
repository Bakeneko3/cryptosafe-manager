"""Tests for src/core/import_export/exporter.py (EXP-1..4)."""

import base64
import json
from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.import_export.exporter import (
    ExportEncryptionError,
    ExportFormatError,
    VaultExporter,
)
from src.core.import_export.key_exchange import (
    decrypt_with_private_key,
    generate_keypair,
)
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"
EXPORT_PW = "Export-P@ss-2026!"
SAMPLE = {
    "title": "GitHub",
    "username": "alice",
    "password": "hunter2",
    "url": "https://github.com",
    "notes": "2FA",
    "category": "Work",
    "tags": "code",
}


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
    d = Database(tmp_path / "exporter.db")
    yield d
    d.close()


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    m = KeyManager(db, key_derivation=fast_kd)
    m.create_vault(STRONG)
    return m


@pytest.fixture
def em(db: Database, km: KeyManager) -> EntryManager:
    em = EntryManager(db, km)
    em.create_entry(SAMPLE)
    em.create_entry({**SAMPLE, "title": "Gmail"})
    return em


@pytest.fixture
def exporter(em: EntryManager, km: KeyManager) -> VaultExporter:
    return VaultExporter(em, km)


# --------------------------------------------------------------------- #
# Password encryption round-trip
# --------------------------------------------------------------------- #


def test_export_password_json_roundtrip(exporter: VaultExporter, tmp_path: Path) -> None:
    out = tmp_path / "vault.json"
    result = exporter.export(out, format="json", encryption="password", password=EXPORT_PW)

    assert out.exists()
    assert result.entry_count == 2
    assert result.file_size > 0

    # Decrypt manually to verify.
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["cryptosafe_export"] is True
    assert doc["format"] == "json"
    assert doc["encryption"]["algorithm"] == "AES-256-GCM"

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    salt = base64.b64decode(doc["encryption"]["salt"])
    nonce = base64.b64decode(doc["encryption"]["nonce"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=doc["encryption"]["iterations"],
    )
    key = kdf.derive(EXPORT_PW.encode("utf-8"))
    ct = base64.b64decode(doc["data"])
    plaintext = AESGCM(key).decrypt(nonce, ct, None)

    from src.core.import_export.formats import json_format
    entries = json_format.parse(plaintext)
    assert len(entries) == 2


def test_export_password_requires_password(exporter: VaultExporter, tmp_path: Path) -> None:
    with pytest.raises(ExportEncryptionError):
        exporter.export(
            tmp_path / "x.json", format="json", encryption="password"
        )


def test_export_unique_nonce_per_export(exporter: VaultExporter, tmp_path: Path) -> None:
    a = exporter.export(
        tmp_path / "a.json", format="json", encryption="password", password=EXPORT_PW
    )
    b = exporter.export(
        tmp_path / "b.json", format="json", encryption="password", password=EXPORT_PW
    )
    doc_a = json.loads(a.path.read_text(encoding="utf-8"))
    doc_b = json.loads(b.path.read_text(encoding="utf-8"))
    assert doc_a["encryption"]["nonce"] != doc_b["encryption"]["nonce"]
    assert doc_a["encryption"]["salt"] != doc_b["encryption"]["salt"]


# --------------------------------------------------------------------- #
# Public key encryption
# --------------------------------------------------------------------- #


def test_export_public_key_rsa(exporter: VaultExporter, tmp_path: Path) -> None:
    kp = generate_keypair("rsa")
    out = tmp_path / "vault.pk.json"
    exporter.export(
        out, format="json", encryption="public_key", public_key_pem=kp.public_pem
    )

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["encryption"]["algorithm"] == "hybrid"

    payload = base64.b64decode(doc["data"])
    plaintext = decrypt_with_private_key(payload, kp.private_pem)

    from src.core.import_export.formats import json_format
    entries = json_format.parse(plaintext)
    assert len(entries) == 2


def test_export_public_key_ec(exporter: VaultExporter, tmp_path: Path) -> None:
    kp = generate_keypair("ec")
    out = tmp_path / "vault.pk.ec.json"
    exporter.export(
        out, format="json", encryption="public_key", public_key_pem=kp.public_pem
    )

    doc = json.loads(out.read_text(encoding="utf-8"))
    payload = base64.b64decode(doc["data"])
    plaintext = decrypt_with_private_key(payload, kp.private_pem)
    assert b"GitHub" in plaintext


def test_export_public_key_requires_key(exporter: VaultExporter, tmp_path: Path) -> None:
    with pytest.raises(ExportEncryptionError):
        exporter.export(tmp_path / "x.json", format="json", encryption="public_key")


# --------------------------------------------------------------------- #
# Plaintext (migration only)
# --------------------------------------------------------------------- #


def test_export_plaintext_csv(exporter: VaultExporter, tmp_path: Path) -> None:
    out = tmp_path / "vault.csv"
    result = exporter.export(out, format="csv", encryption="none")
    assert result.encryption == "none"

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["encryption"]["algorithm"] == "none"

    plaintext = base64.b64decode(doc["data"])
    from src.core.import_export.formats import csv_format
    entries = csv_format.parse(plaintext)
    assert len(entries) == 2


# --------------------------------------------------------------------- #
# Formats
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("fmt", ["json", "csv", "bitwarden", "lastpass"])
def test_export_all_formats(exporter: VaultExporter, tmp_path: Path, fmt: str) -> None:
    out = tmp_path / f"vault.{fmt}"
    result = exporter.export(
        out, format=fmt, encryption="password", password=EXPORT_PW
    )
    assert result.entry_count == 2


def test_export_unsupported_format(exporter: VaultExporter, tmp_path: Path) -> None:
    with pytest.raises(ExportFormatError):
        exporter.export(tmp_path / "x", format="yaml", encryption="none")


def test_export_unsupported_encryption(exporter: VaultExporter, tmp_path: Path) -> None:
    with pytest.raises(ExportEncryptionError):
        exporter.export(tmp_path / "x", format="json", encryption="bogus")


# --------------------------------------------------------------------- #
# Selection & field filtering
# --------------------------------------------------------------------- #


def test_export_selected_entries(exporter: VaultExporter, em: EntryManager, tmp_path: Path) -> None:
    ids = [e["id"] for e in em.get_all_entries()]
    result = exporter.export(
        tmp_path / "one.json", format="json", encryption="password",
        password=EXPORT_PW, entry_ids=[ids[0]],
    )
    assert result.entry_count == 1


def test_export_exclude_fields(exporter: VaultExporter, tmp_path: Path) -> None:
    out = tmp_path / "no-notes.json"
    exporter.export(
        out, format="json", encryption="none", exclude_fields=["notes"],
    )

    doc = json.loads(out.read_text(encoding="utf-8"))
    plaintext = base64.b64decode(doc["data"])
    from src.core.import_export.formats import json_format
    entries = json_format.parse(plaintext)
    assert all("notes" not in e or not e["notes"] for e in entries)


def test_export_include_fields(exporter: VaultExporter, tmp_path: Path) -> None:
    out = tmp_path / "only-title.json"
    exporter.export(
        out, format="json", encryption="none", include_fields=["title"],
    )

    doc = json.loads(out.read_text(encoding="utf-8"))
    plaintext = base64.b64decode(doc["data"])
    from src.core.import_export.formats import json_format
    entries = json_format.parse(plaintext)
    assert all(e["title"] for e in entries)


# --------------------------------------------------------------------- #
# Integrity & signature
# --------------------------------------------------------------------- #


def test_export_produces_integrity_hash(exporter: VaultExporter, tmp_path: Path) -> None:
    out = tmp_path / "integrity.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert "integrity" in doc
    assert len(doc["integrity"]["hash"]) == 64


def test_export_produces_signature(exporter: VaultExporter, tmp_path: Path) -> None:
    out = tmp_path / "signed.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["integrity"]["signature"] is not None
    assert len(doc["integrity"]["signature"]) == 128  # 64 bytes hex


# --------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------- #


def test_export_records_history(exporter: VaultExporter, db: Database, tmp_path: Path) -> None:
    exporter.export(tmp_path / "x.json", format="json", encryption="password", password=EXPORT_PW)
    rows = db.fetch_all("SELECT * FROM import_export_history")
    assert len(rows) == 1
    assert rows[0]["operation_type"] == "export"
    assert rows[0]["format"] == "json"
    assert rows[0]["entry_count"] == 2
    assert rows[0]["verification_status"] == "ok"


# --------------------------------------------------------------------- #
# Compression
# --------------------------------------------------------------------- #


def test_export_with_compression(exporter: VaultExporter, tmp_path: Path) -> None:
    out = tmp_path / "compressed.json.gz"
    result = exporter.export(
        out, format="json", encryption="password", password=EXPORT_PW, compress=True
    )
    data = out.read_bytes()
    assert data[:2] == b"\x1f\x8b"  # gzip magic
    assert result.file_size > 0