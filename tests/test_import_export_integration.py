"""
Integration tests for Sprint 6: import/export, sharing, QR.

Covers:
  * TEST-1 -- round-trip export/import across formats.
  * TEST-2 -- Bitwarden/LastPass interoperability.
  * TEST-3 -- sharing tamper detection (end-to-end).
  * TEST-4 -- QR round-trip with 1 KB payload.
  * TEST-5 -- performance: export/import 100 entries.
"""

import json
import os
import time
from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.importer import VaultImporter
from src.core.import_export.key_exchange import generate_keypair
from src.core.import_export.qr_service import QRService
from src.core.import_export.sharing_service import (
    Permissions,
    SharingEncryptionError,
    SharingService,
)
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"
EXPORT_PW = "Export-P@ss-2026!"
SHARE_PW = "Sh@re-P@ssword-2026!"


def _sample(i: int) -> dict:
    return {
        "title": f"Entry-{i:03d}",
        "username": f"user{i}@example.com",
        "password": f"pw-{i}-Strong!Pass",
        "url": f"https://example.com/{i}",
        "notes": f"note {i}",
        "category": "Bulk",
        "tags": "bulk,test",
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
    d = Database(tmp_path / "integration.db")
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


def _wipe(em: EntryManager) -> None:
    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)


# --------------------------------------------------------------------- #
# TEST-1: round-trip across formats
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("fmt", ["json", "csv", "bitwarden", "lastpass"])
def test_roundtrip_format(
    em: EntryManager, km: KeyManager, tmp_path: Path, fmt: str
) -> None:
    for i in range(5):
        em.create_entry(_sample(i))

    exporter = VaultExporter(em, km)
    out = tmp_path / f"vault.{fmt}"
    exporter.export(
        out, format=fmt, encryption="password", password=EXPORT_PW
    )

    _wipe(em)

    importer = VaultImporter(em, km)
    summary = importer.import_file(out, password=EXPORT_PW)

    assert summary.ok
    assert summary.added == 5

    titles = {e["title"] for e in em.get_all_entries()}
    assert titles == {f"Entry-{i:03d}" for i in range(5)}


# --------------------------------------------------------------------- #
# TEST-2: Bitwarden / LastPass interoperability
# --------------------------------------------------------------------- #


def test_import_real_bitwarden_json(em: EntryManager, km: KeyManager, tmp_path: Path) -> None:
    """Import a realistic Bitwarden export (documented schema)."""
    doc = {
        "encrypted": False,
        "folders": [{"id": "f-1", "name": "Work"}],
        "items": [
            {
                "id": "it-1",
                "folderId": "f-1",
                "type": 1,
                "name": "GitHub",
                "notes": "2FA enabled",
                "login": {
                    "uris": [{"match": None, "uri": "https://github.com"}],
                    "username": "alice",
                    "password": "hunter2",
                    "totp": None,
                },
            },
            {
                "id": "it-2",
                "type": 1,
                "name": "Gmail",
                "login": {
                    "uris": [{"uri": "https://mail.google.com"}],
                    "username": "alice@gmail.com",
                    "password": "hunter3",
                },
            },
        ],
    }
    path = tmp_path / "bitwarden.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    importer = VaultImporter(em, km)
    summary = importer.import_file(path)

    assert summary.ok
    assert summary.added == 2
    titles = {e["title"] for e in em.get_all_entries()}
    assert titles == {"GitHub", "Gmail"}


def test_import_real_lastpass_csv(em: EntryManager, km: KeyManager, tmp_path: Path) -> None:
    csv = (
        "url,username,password,extra,name,grouping,fav\n"
        "https://github.com,alice,hunter2,2FA,GitHub,Work,0\n"
        "https://mail.google.com,alice@gmail.com,hunter3,,Gmail,Personal,0\n"
    )
    path = tmp_path / "lastpass.csv"
    path.write_text(csv, encoding="utf-8")

    importer = VaultImporter(em, km)
    summary = importer.import_file(path)

    assert summary.ok
    assert summary.added == 2


def test_export_to_bitwarden_can_be_parsed_back(
    em: EntryManager, km: KeyManager, tmp_path: Path
) -> None:
    """Export to Bitwarden format (plaintext), re-parse with Bitwarden parser."""
    em.create_entry(_sample(0))
    em.create_entry(_sample(1))

    exporter = VaultExporter(em, km)
    out = tmp_path / "bw.json"
    exporter.export(out, format="bitwarden", encryption="none")

    import base64
    doc = json.loads(out.read_text(encoding="utf-8"))
    plaintext = base64.b64decode(doc["data"])

    from src.core.import_export.formats import bitwarden_format
    entries = bitwarden_format.parse(plaintext)
    assert len(entries) == 2
    titles = {e["title"] for e in entries}
    assert titles == {"Entry-000", "Entry-001"}


# --------------------------------------------------------------------- #
# TEST-3: sharing tamper (end-to-end)
# --------------------------------------------------------------------- #


def test_share_tamper_detection_end_to_end(
    em: EntryManager, km: KeyManager, tmp_path: Path
) -> None:
    em.create_entry(_sample(0))
    entry_id = em.get_all_entries()[0]["id"]

    sharer = SharingService(em, km)
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")

    # Tamper: flip a byte in the encrypted data.
    doc = json.loads(p.read_text(encoding="utf-8"))
    import base64
    blob = bytearray(base64.b64decode(doc["data"]))
    blob[-1] ^= 0xFF
    doc["data"] = base64.b64encode(bytes(blob)).decode("ascii")
    p.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(SharingEncryptionError):
        sharer.open_share(p, password=SHARE_PW)


def test_share_with_public_key_end_to_end(
    em: EntryManager, km: KeyManager, tmp_path: Path
) -> None:
    em.create_entry(_sample(0))
    entry_id = em.get_all_entries()[0]["id"]

    kp = generate_keypair("rsa")
    sharer = SharingService(em, km)
    pkg = sharer.create_share(entry_id, public_key_pem=kp.public_pem)
    p = pkg.write(tmp_path / "share.pk.json")

    opened = sharer.open_share(p, private_key_pem=kp.private_pem)
    assert opened["entry"]["title"] == "Entry-000"


# --------------------------------------------------------------------- #
# TEST-4: QR round-trip with ~1 KB payload
# --------------------------------------------------------------------- #


def test_qr_roundtrip_1kb() -> None:
    service = QRService(validity_seconds=300, chunk_size=800)
    payload = os.urandom(1024)

    chunks = service.generate(payload)
    assert len(chunks) >= 1

    # Save each chunk to a temp file and decode them back.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        paths: list[Path] = []
        for c in chunks:
            p = tmp_path / f"c{c.index}.png"
            p.write_bytes(c.png_bytes)
            paths.append(p)

        decoded = service.decode_files(paths)
        assert decoded == payload


# --------------------------------------------------------------------- #
# TEST-5: performance — 100 entries export/import
# --------------------------------------------------------------------- #


def test_perf_export_import_100(em: EntryManager, km: KeyManager, tmp_path: Path) -> None:
    for i in range(100):
        em.create_entry(_sample(i))

    exporter = VaultExporter(em, km)
    out = tmp_path / "perf.json"

    start = time.perf_counter()
    exporter.export(
        out, format="json", encryption="password", password=EXPORT_PW
    )
    export_time = time.perf_counter() - start

    assert export_time < 5.0, f"export took {export_time:.2f}s"

    _wipe(em)

    importer = VaultImporter(em, km)

    start = time.perf_counter()
    summary = importer.import_file(out, password=EXPORT_PW)
    import_time = time.perf_counter() - start

    assert summary.added == 100
    assert import_time < 10.0, f"import took {import_time:.2f}s"


# --------------------------------------------------------------------- #
# Full-cycle: export -> share -> open -> import
# --------------------------------------------------------------------- #


def test_full_sharing_lifecycle(
    em: EntryManager, km: KeyManager, tmp_path: Path
) -> None:
    em.create_entry(_sample(0))
    em.create_entry(_sample(1))
    # Pick the entry with the known title instead of relying on order.
    target = next(
        e for e in em.get_all_entries() if e["title"] == "Entry-000"
    )
    entry_id = target["id"]

    # 1. Share.
    sharer = SharingService(em, km)
    pkg = sharer.create_share(
        entry_id,
        recipient="bob",
        permissions=Permissions(expires_in_days=5),
        password=SHARE_PW,
    )
    p = pkg.write(tmp_path / "share.json")

    # 2. Wipe vault.
    _wipe(em)

    # 3. Open share.
    opened = sharer.open_share(p, password=SHARE_PW)
    assert opened["header"]["recipient"] == "bob"
    assert opened["header"]["permissions"]["expires_in_days"] == 5
    assert opened["entry"]["title"] == "Entry-000"

    # 4. Import shared.
    entry = sharer.import_shared_entry(p, password=SHARE_PW)
    assert entry["title"] == "Entry-000"
    assert len(em.get_all_entries()) == 1