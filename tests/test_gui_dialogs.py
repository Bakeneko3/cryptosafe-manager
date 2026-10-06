"""Smoke tests for Sprint 6 GUI dialogs."""

from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

from src.core.crypto.key_derivation import KeyDerivation
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.importer import VaultImporter
from src.core.import_export.sharing_service import SharingService
from src.core.key_manager import KeyManager
from src.core.vault.entry_manager import EntryManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"
SAMPLE = {
    "title": "GitHub",
    "username": "alice",
    "password": "hunter2",
    "url": "https://github.com",
    "notes": "",
    "category": "",
    "tags": "",
}


@pytest.fixture(scope="session")
def _tk_root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display available: {exc}")
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def root(_tk_root):
    yield _tk_root


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
    d = Database(tmp_path / "gui_dialogs.db")
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


# --------------------------------------------------------------------- #
# ExportDialog
# --------------------------------------------------------------------- #


def test_export_dialog_constructs(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.export_dialog import ExportDialog

    exporter = VaultExporter(em, km)
    dlg = ExportDialog(root, exporter, selected_entry_ids=[])
    assert dlg.result is None
    dlg._on_cancel()


def test_export_dialog_defaults(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.export_dialog import ExportDialog

    exporter = VaultExporter(em, km)
    dlg = ExportDialog(root, exporter)
    assert dlg.format_var.get() == "json"
    assert dlg.encryption_var.get() == "password"
    dlg._on_cancel()


def test_export_dialog_encryption_toggle(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.export_dialog import ExportDialog

    exporter = VaultExporter(em, km)
    dlg = ExportDialog(root, exporter)
    dlg.encryption_var.set("public_key")
    dlg._update_encryption()
    dlg.encryption_var.set("none")
    dlg._update_encryption()
    dlg._on_cancel()


# --------------------------------------------------------------------- #
# ImportDialog
# --------------------------------------------------------------------- #


def test_import_dialog_constructs(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.import_dialog import ImportDialog

    importer = VaultImporter(em, km)
    dlg = ImportDialog(root, importer)
    assert dlg.result is None
    dlg._on_cancel()


def test_import_dialog_defaults(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.import_dialog import ImportDialog

    importer = VaultImporter(em, km)
    dlg = ImportDialog(root, importer)
    assert dlg.mode_var.get() == "merge"
    dlg._on_cancel()


# --------------------------------------------------------------------- #
# SharingDialog
# --------------------------------------------------------------------- #


def test_sharing_dialog_constructs(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.sharing_dialog import SharingDialog

    sharer = SharingService(em, km)
    entry_id = em.get_all_entries()[0]["id"]
    dlg = SharingDialog(root, sharer, entry_id)
    assert dlg.result is None
    dlg._on_cancel()


def test_sharing_dialog_defaults(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.sharing_dialog import SharingDialog

    sharer = SharingService(em, km)
    entry_id = em.get_all_entries()[0]["id"]
    dlg = SharingDialog(root, sharer, entry_id)
    assert dlg.expires_var.get() == 7
    assert dlg.encryption_var.get() == "password"
    dlg._on_cancel()


# --------------------------------------------------------------------- #
# OpenShareDialog
# --------------------------------------------------------------------- #


def test_open_share_dialog_constructs(root, em: EntryManager, km: KeyManager) -> None:
    from src.gui.open_share_dialog import OpenShareDialog

    sharer = SharingService(em, km)
    dlg = OpenShareDialog(root, sharer)
    assert dlg.result is None
    dlg._on_cancel()


def test_open_share_dialog_decrypt_preview(
    root, em: EntryManager, km: KeyManager, tmp_path: Path
) -> None:
    """Create a share, then load it back in the dialog."""
    from src.gui.open_share_dialog import OpenShareDialog

    sharer = SharingService(em, km)
    entry_id = em.get_all_entries()[0]["id"]
    pkg = sharer.create_share(entry_id, password="ShareP@ss-2026!")
    p = pkg.write(tmp_path / "share.json")

    dlg = OpenShareDialog(root, sharer)
    dlg.path_var.set(str(p))
    dlg.password_var.set("ShareP@ss-2026!")
    dlg._on_decrypt()

    assert dlg._decrypted_body is not None
    assert dlg._decrypted_body["entry"]["title"] == "GitHub"
    dlg._on_cancel()


# --------------------------------------------------------------------- #
# QRViewer (construction only)
# --------------------------------------------------------------------- #


def test_qr_viewer_constructs(root) -> None:
    from src.gui.qr_viewer import QRViewer

    viewer = QRViewer(root, b"test payload for qr viewer")
    viewer.destroy()