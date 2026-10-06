"""Smoke tests for src/gui/security_settings_dialog.py (CFG-1..3 GUI)."""

from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

from src.core.security.security_profiles import load_profile
from src.core.settings_manager import SettingsManager
from src.database.db import Database


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
def manager(tmp_path: Path) -> SettingsManager:
    db = Database(tmp_path / "dlg.db")
    yield SettingsManager(db)
    db.close()


def test_dialog_constructs(root, manager: SettingsManager) -> None:
    from src.gui.security_settings_dialog import SecuritySettingsDialog

    dlg = SecuritySettingsDialog(root, manager)
    assert dlg.result is None
    dlg._on_cancel()


def test_default_selection(root, manager: SettingsManager) -> None:
    from src.gui.security_settings_dialog import SecuritySettingsDialog

    dlg = SecuritySettingsDialog(root, manager)
    assert dlg.profile_var.get() == "Standard"
    dlg._on_cancel()


def test_switching_updates_diff(root, manager: SettingsManager) -> None:
    from src.gui.security_settings_dialog import SecuritySettingsDialog

    dlg = SecuritySettingsDialog(root, manager)
    dlg._select("Paranoid")
    text = dlg.diff_text.get("1.0", tk.END)
    assert "auto_lock_timeout" in text
    dlg._on_cancel()


def test_same_profile_shows_no_changes(root, manager: SettingsManager) -> None:
    from src.gui.security_settings_dialog import SecuritySettingsDialog

    dlg = SecuritySettingsDialog(root, manager)
    dlg._select("Standard")
    text = dlg.diff_text.get("1.0", tk.END)
    assert "No changes" in text
    dlg._on_cancel()


def test_apply_persists(monkeypatch, root, manager: SettingsManager) -> None:
    from src.gui.security_settings_dialog import SecuritySettingsDialog

    # Auto-confirm.
    import tkinter.messagebox as mb
    monkeypatch.setattr(mb, "askyesno", lambda *a, **kw: True)

    dlg = SecuritySettingsDialog(root, manager)
    dlg._select("Paranoid")
    dlg._on_apply()

    assert dlg.result == "Paranoid"
    loaded = load_profile(manager)
    assert loaded.name == "Paranoid"