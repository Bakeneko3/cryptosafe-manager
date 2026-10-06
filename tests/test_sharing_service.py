"""Tests for src/core/import_export/sharing_service.py (SHR-1..4, CRY-1..4)."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.core.crypto.key_derivation import KeyDerivation
from src.core.import_export.key_exchange import generate_keypair
from src.core.import_export.sharing_service import (
    Permissions,
    SharingEncryptionError,
    SharingService,
    SharingValidationError,
)
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"
SHARE_PW = "Sh@re-P@ssword-2026!"
SAMPLE = {
    "title": "GitHub",
    "username": "alice",
    "password": "hunter2",
    "url": "https://github.com",
    "notes": "private",
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
    d = Database(tmp_path / "sharing.db")
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
    return em


@pytest.fixture
def sharer(em: EntryManager, km: KeyManager) -> SharingService:
    return SharingService(em, km)


# --------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------- #


def test_permissions_validate_ok() -> None:
    Permissions(expires_in_days=7).validate()


@pytest.mark.parametrize("days", [0, -1, 31, 100])
def test_permissions_invalid_expiration(days: int) -> None:
    with pytest.raises(SharingValidationError):
        Permissions(expires_in_days=days).validate()


def test_create_share_requires_exactly_one_method(
    sharer: SharingService, em: EntryManager
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    with pytest.raises(SharingValidationError):
        sharer.create_share(entry_id)


def test_create_share_rejects_both_methods(
    sharer: SharingService, em: EntryManager
) -> None:
    kp = generate_keypair("rsa")
    entry_id = em.get_all_entries()[0]["id"]
    with pytest.raises(SharingValidationError):
        sharer.create_share(
            entry_id, password="x", public_key_pem=kp.public_pem
        )


# --------------------------------------------------------------------- #
# Password-based share
# --------------------------------------------------------------------- #


def test_share_password_roundtrip(sharer: SharingService, em: EntryManager, tmp_path: Path) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(
        entry_id,
        recipient="bob@example.com",
        permissions=Permissions(expires_in_days=3),
        password=SHARE_PW,
    )
    p = pkg.write(tmp_path / "share.json")

    opened = sharer.open_share(p, password=SHARE_PW)
    assert opened["entry"]["title"] == "GitHub"
    assert opened["entry"]["password"] == "hunter2"
    assert opened["header"]["recipient"] == "bob@example.com"
    assert opened["header"]["permissions"]["expires_in_days"] == 3


def test_share_password_wrong_password(
    sharer: SharingService, em: EntryManager, tmp_path: Path
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")
    with pytest.raises(SharingEncryptionError):
        sharer.open_share(p, password="Wrong-P@ss-000!")


def test_share_password_requires_password_on_open(
    sharer: SharingService, em: EntryManager, tmp_path: Path
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")
    with pytest.raises(SharingEncryptionError):
        sharer.open_share(p)


# --------------------------------------------------------------------- #
# Public-key share
# --------------------------------------------------------------------- #


def test_share_public_key_rsa(sharer: SharingService, em: EntryManager, tmp_path: Path) -> None:
    kp = generate_keypair("rsa")
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(
        entry_id,
        recipient="bob",
        public_key_pem=kp.public_pem,
    )
    p = pkg.write(tmp_path / "share.pk.json")

    opened = sharer.open_share(p, private_key_pem=kp.private_pem)
    assert opened["entry"]["title"] == "GitHub"


def test_share_public_key_ec(sharer: SharingService, em: EntryManager, tmp_path: Path) -> None:
    kp = generate_keypair("ec")
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(
        entry_id,
        public_key_pem=kp.public_pem,
    )
    p = pkg.write(tmp_path / "share.pk.json")

    opened = sharer.open_share(p, private_key_pem=kp.private_pem)
    assert opened["entry"]["title"] == "GitHub"


def test_share_public_key_requires_key_on_open(
    sharer: SharingService, em: EntryManager, tmp_path: Path
) -> None:
    kp = generate_keypair("rsa")
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, public_key_pem=kp.public_pem)
    p = pkg.write(tmp_path / "share.json")
    with pytest.raises(SharingEncryptionError):
        sharer.open_share(p)


# --------------------------------------------------------------------- #
# Tamper detection (SHR-2, CRY-4)
# --------------------------------------------------------------------- #


def test_tampered_package_rejected(sharer: SharingService, em: EntryManager, tmp_path: Path) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")

    doc = json.loads(p.read_text(encoding="utf-8"))
    # Corrupt the ciphertext.
    import base64
    blob = bytearray(base64.b64decode(doc["data"]))
    blob[0] ^= 0xFF
    doc["data"] = base64.b64encode(bytes(blob)).decode("ascii")
    p.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(SharingEncryptionError):
        sharer.open_share(p, password=SHARE_PW)


def test_tampered_integrity_hash_rejected(
    sharer: SharingService, em: EntryManager, tmp_path: Path
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")

    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["integrity"]["hash"] = "0" * 64
    p.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(SharingEncryptionError):
        sharer.open_share(p, password=SHARE_PW)


# --------------------------------------------------------------------- #
# Only selected entry fields are shared (SHR-2)
# --------------------------------------------------------------------- #


def test_share_only_contains_selected_fields(
    sharer: SharingService, em: EntryManager, tmp_path: Path
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")

    opened = sharer.open_share(p, password=SHARE_PW)
    assert set(opened["entry"].keys()) == {
        "title", "username", "password", "url", "notes", "category",
    }
    # tags and id are not shared.
    assert "tags" not in opened["entry"]
    assert "id" not in opened["entry"]


# --------------------------------------------------------------------- #
# Recipient workflow (SHR-4)
# --------------------------------------------------------------------- #


def test_import_shared_entry_saves_to_vault(
    sharer: SharingService, em: EntryManager, tmp_path: Path
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")

    # Wipe vault to test clean import.
    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)

    entry = sharer.import_shared_entry(p, password=SHARE_PW)
    assert entry["title"] == "GitHub"

    titles = {e["title"] for e in em.get_all_entries()}
    assert "GitHub" in titles


def test_import_shared_entry_without_saving(
    sharer: SharingService, em: EntryManager, tmp_path: Path
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    p = pkg.write(tmp_path / "share.json")

    for e in em.get_all_entries():
        em.delete_entry(e["id"], soft_delete=False)

    entry = sharer.import_shared_entry(p, password=SHARE_PW, save_to_vault=False)
    assert entry["title"] == "GitHub"
    assert em.get_all_entries() == []


# --------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------- #


def test_share_records_in_database(
    sharer: SharingService, em: EntryManager, db: Database, tmp_path: Path
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    sharer.create_share(
        entry_id, recipient="bob", password=SHARE_PW
    )
    rows = db.fetch_all("SELECT * FROM shared_entries")
    assert len(rows) == 1
    assert rows[0]["original_entry_id"] == entry_id
    assert rows[0]["encryption_method"] == "password"
    assert rows[0]["recipient_info"] == "bob"


def test_share_expiration_in_future(
    sharer: SharingService, em: EntryManager
) -> None:
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password=SHARE_PW)
    expires = datetime.fromisoformat(pkg.expires_at)
    assert expires > datetime.now(timezone.utc)