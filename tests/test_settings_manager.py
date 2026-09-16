from src.core.settings_manager import SettingsManager
from src.database.db import Database


def test_settings_manager(tmp_path):
    db = Database(tmp_path / "test.db")
    settings = SettingsManager(db)

    settings.set("clipboard_timeout", 60)
    settings.set("theme", "Dark")
    settings.set("backup_enabled", False)

    assert settings.get("clipboard_timeout") == 60
    assert settings.get("theme") == "Dark"
    assert settings.get("backup_enabled") is False

    all_settings = settings.get_all()

    assert all_settings["clipboard_timeout"] == 60
    assert all_settings["theme"] == "Dark"
    assert all_settings["backup_enabled"] is False

    db.close()