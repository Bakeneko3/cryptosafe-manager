"""Smoke tests for src/gui/clipboard_settings_dialog.py."""

from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

from src.core import config
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
    from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog

    dlg = ClipboardSettingsDialog(root, manager)
    assert dlg.result is None
    dlg._on_cancel()


def test_default_values_match_settings(root, manager: SettingsManager) -> None:
    from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog

    dlg = ClipboardSettingsDialog(root, manager)
    assert dlg.timeout_var.get() == config.CLIPBOARD_TIMEOUT_DEFAULT
    assert dlg.notifications_var.get() is True
    assert dlg.security_var.get() == "basic"
    dlg._on_cancel()


def test_save_persists_settings(root, manager: SettingsManager) -> None:
    from src.core.clipboard.clipboard_settings import load_clipboard_settings
    from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog

    dlg = ClipboardSettingsDialog(root, manager)
    dlg.timeout_var.set(45)
    dlg.notifications_var.set(False)
    dlg.security_var.set("advanced")
    dlg._on_save()

    assert dlg.result is not None
    assert dlg.result.timeout == 45

    loaded = load_clipboard_settings(manager)
    assert loaded.timeout == 45
    assert loaded.notifications is False
    assert loaded.security_level == "advanced"


def test_preset_selection_updates_fields(root, manager: SettingsManager) -> None:
    from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog

    dlg = ClipboardSettingsDialog(root, manager)
    dlg.preset_var.set("Public Computer")
    dlg._on_preset_selected()
    assert dlg.timeout_var.get() == 5
    assert dlg.security_var.get() == "paranoid"
    dlg._on_cancel()


def test_never_toggle_disables_spinbox(root, manager: SettingsManager) -> None:
    from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog

    dlg = ClipboardSettingsDialog(root, manager)
    dlg.never_var.set(True)
    dlg._on_never_toggled()
    assert str(dlg.timeout_spin.cget("state")) == "disabled"
    dlg._on_cancel()


def test_save_never_uses_zero(root, manager: SettingsManager) -> None:
    from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog

    dlg = ClipboardSettingsDialog(root, manager)
    dlg.never_var.set(True)
    dlg._on_never_toggled()
    dlg._on_save()
    assert dlg.result is not None
    assert dlg.result.timeout == config.CLIPBOARD_TIMEOUT_NEVER


def test_cancel_does_not_save(root, manager: SettingsManager) -> None:
    from src.core.clipboard.clipboard_settings import load_clipboard_settings
    from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog

    dlg = ClipboardSettingsDialog(root, manager)
    dlg.timeout_var.set(120)
    dlg._on_cancel()

    assert dlg.result is None
    loaded = load_clipboard_settings(manager)
    assert loaded.timeout != 120