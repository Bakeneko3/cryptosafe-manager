import tkinter as tk

import pytest

from src.core.settings_manager import SettingsManager
from src.database.db import Database
from src.gui.settings_dialog import SettingsDialog


@pytest.fixture(scope="module")
def root():
    root = tk.Tk()
    root.withdraw()

    yield root

    root.destroy()


def test_settings_dialog_saves_to_database(tmp_path, root):
    db = Database(tmp_path / "test.db")
    settings_manager = SettingsManager(db)

    dialog = SettingsDialog(
        root,
        settings_manager=settings_manager,
    )

    dialog.clipboard_timeout.set(60)
    dialog.auto_lock_timeout.set(600)
    dialog.theme.set("Dark")
    dialog.language.set("Russian")
    dialog.backup_enabled.set(False)

    dialog._save()

    assert settings_manager.get("clipboard_timeout") == 60
    assert settings_manager.get("auto_lock_timeout") == 600
    assert settings_manager.get("theme") == "Dark"
    assert settings_manager.get("language") == "Russian"
    assert settings_manager.get("backup_enabled") is False

    db.close()