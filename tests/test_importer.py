"""Tests for src/core/import_export/importer.py (IMP-1..4, SEC-1..5)."""

import json
from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.importer import (
    ImportDecryptionError,
    ImportFormatError,
    ImportSecurityError,
    VaultImporter,
)
from src.core.import_export.key_exchange import generate_keypair
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
    "notes": "",
    "category": "Work",
    "tags": "",
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
    d = Database(tmp_path / "importer.db")
    yield d
    d.close()


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    m = KeyManager(db, key_derivation=fast_kd)
    m.create_vault(STRONG)
    return m


@pytest.fixture
def em(db: Database, km: KeyManager) -> EntryManager:
    return EntryManager(db, km)


@pytest.fixture
def exporter(em: EntryManager, km: KeyManager) -> VaultExporter:
    em.create_entry(SAMPLE)
    em.create_entry({**SAMPLE, "title": "Gmail"})
    return VaultExporter(em, km)


@pytest.fixture
def importer(em: EntryManager, km: KeyManager) -> VaultImporter:
    return VaultImporter(em, km)


# --------------------------------------------------------------------- #
# Round-trip: password JSON
# --------------------------------------------------------------------- #


def test_import_password_json_merge(
    exporter: VaultExporter, importer: VaultImporter,
    em: EntryManager, tmp_path: Path
) -> None:
    out = tmp_path / "vault.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)

    # Clear vault to test merge cleanly.
    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)

    summary = importer.import_file(out, mode="merge", password=EXPORT_PW)
    assert summary.ok
    assert summary.added == 2
    assert len(em.get_all_entries()) == 2


def test_import_wrong_password(
    exporter: VaultExporter, importer: VaultImporter, tmp_path: Path
) -> None:
    out = tmp_path / "vault.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)
    with pytest.raises(ImportDecryptionError):
        importer.import_file(out, password="Wrong-P@ss-000!")


# --------------------------------------------------------------------- #
# Public-key round-trip
# --------------------------------------------------------------------- #


def test_import_public_key_rsa(
    exporter: VaultExporter, importer: VaultImporter, em: EntryManager, tmp_path: Path
) -> None:
    kp = generate_keypair("rsa")
    out = tmp_path / "vault.pk.json"
    exporter.export(
        out, format="json", encryption="public_key", public_key_pem=kp.public_pem
    )

    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)

    summary = importer.import_file(out, private_key_pem=kp.private_pem)
    assert summary.ok
    assert summary.added == 2


def test_import_public_key_requires_private_key(
    exporter: VaultExporter, importer: VaultImporter, tmp_path: Path
) -> None:
    kp = generate_keypair("rsa")
    out = tmp_path / "vault.pk.json"
    exporter.export(
        out, format="json", encryption="public_key", public_key_pem=kp.public_pem
    )
    with pytest.raises(ImportDecryptionError):
        importer.import_file(out)


# --------------------------------------------------------------------- #
# Plaintext CSV (migration)
# --------------------------------------------------------------------- #


def test_import_plaintext_csv(
    exporter: VaultExporter, importer: VaultImporter, em: EntryManager, tmp_path: Path
) -> None:
    out = tmp_path / "vault.csv"
    exporter.export(out, format="csv", encryption="none")

    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)

    summary = importer.import_file(out)
    assert summary.ok
    assert summary.added == 2


# --------------------------------------------------------------------- #
# Dry-run
# --------------------------------------------------------------------- #


def test_dry_run_does_not_write(
    exporter: VaultExporter, importer: VaultImporter, em: EntryManager, tmp_path: Path
) -> None:
    out = tmp_path / "vault.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)

    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)

    summary = importer.import_file(
        out, mode="dry-run", password=EXPORT_PW
    )
    assert summary.dry_run is True
    assert summary.added == 2
    # Nothing written.
    assert len(em.get_all_entries()) == 0


# --------------------------------------------------------------------- #
# Replace mode
# --------------------------------------------------------------------- #


def test_replace_mode_clears_existing(
    exporter: VaultExporter, importer: VaultImporter, em: EntryManager, tmp_path: Path
) -> None:
    out = tmp_path / "vault.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)

    # Add an extra entry that should NOT be in the result.
    em.create_entry({**SAMPLE, "title": "Should-Go-Away"})

    importer.import_file(out, mode="replace", password=EXPORT_PW)

    titles = {e["title"] for e in em.get_all_entries()}
    assert "Should-Go-Away" not in titles
    assert titles == {"GitHub", "Gmail"}


# --------------------------------------------------------------------- #
# Duplicates in merge mode
# --------------------------------------------------------------------- #


def test_merge_skips_duplicates(
    exporter: VaultExporter, importer: VaultImporter, em: EntryManager, tmp_path: Path
) -> None:
    out = tmp_path / "vault.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)

    # The vault still has GitHub & Gmail from the fixture; importing the same file again
    # should skip both as duplicates.
    summary = importer.import_file(out, mode="merge", password=EXPORT_PW)
    assert summary.skipped_duplicates == 2
    assert summary.added == 0


# --------------------------------------------------------------------- #
# Format detection from raw files
# --------------------------------------------------------------------- #


def test_detect_lastpass_csv(importer: VaultImporter, em: EntryManager, tmp_path: Path) -> None:
    csv = (
        "url,username,password,extra,name,grouping,fav\n"
        "https://github.com,alice,hunter2,,GitHub,Work,0\n"
    )
    p = tmp_path / "lp.csv"
    p.write_text(csv, encoding="utf-8")
    summary = importer.import_file(p)
    assert summary.format == "lastpass"
    assert summary.added == 1


def test_detect_bitwarden_json(importer: VaultImporter, tmp_path: Path) -> None:
    doc = {
        "folders": [],
        "items": [
            {
                "type": 1,
                "name": "GitHub",
                "login": {"username": "alice", "password": "hunter2", "uris": []},
            }
        ],
    }
    p = tmp_path / "bw.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    summary = importer.import_file(p)
    assert summary.format == "bitwarden"
    assert summary.added == 1


# --------------------------------------------------------------------- #
# Security
# --------------------------------------------------------------------- #


def test_rejects_oversized_file(importer: VaultImporter, tmp_path: Path) -> None:
    p = tmp_path / "big.json"
    p.write_bytes(b"x" * (11 * 1024 * 1024))
    with pytest.raises(ImportSecurityError):
        importer.import_file(p)


def test_rejects_script_payload(importer: VaultImporter, tmp_path: Path) -> None:
    doc = {
        "version": "1.0",
        "cryptosafe_export": True,
        "format": "json",
        "encryption": {"algorithm": "none"},
        "data": None,
    }
    # Build a plaintext JSON export with a script in notes.
    from src.core.import_export.formats import json_format
    import base64
    plaintext = json_format.render(
        [
            {
                "title": "Suspicious",
                "password": "<script>alert(1)</script>",
            }
        ]
    )
    doc["data"] = base64.b64encode(plaintext).decode("ascii")

    p = tmp_path / "malicious.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    summary = importer.import_file(p)
    assert summary.skipped_malicious == 1
    assert summary.added == 0


def test_rejects_integrity_mismatch(
    exporter: VaultExporter, importer: VaultImporter, tmp_path: Path
) -> None:
    out = tmp_path / "vault.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)

    # Tamper with the integrity hash.
    doc = json.loads(out.read_text(encoding="utf-8"))
    doc["integrity"]["hash"] = "0" * 64
    out.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(ImportSecurityError):
        importer.import_file(out, password=EXPORT_PW)


def test_rejects_unknown_format(importer: VaultImporter, tmp_path: Path) -> None:
    p = tmp_path / "unknown.xyz"
    p.write_text("just some text without structure", encoding="utf-8")
    with pytest.raises(ImportFormatError):
        importer.import_file(p)


# --------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------- #


def test_import_records_history(
    exporter: VaultExporter, importer: VaultImporter,
    em: EntryManager, db: Database, tmp_path: Path
) -> None:
    out = tmp_path / "vault.json"
    exporter.export(out, format="json", encryption="password", password=EXPORT_PW)

    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)

    importer.import_file(out, password=EXPORT_PW)

    rows = db.fetch_all(
        "SELECT * FROM import_export_history WHERE operation_type = 'import'"
    )
    assert len(rows) == 1
    assert rows[0]["format"] == "json"
    assert rows[0]["entry_count"] == 2