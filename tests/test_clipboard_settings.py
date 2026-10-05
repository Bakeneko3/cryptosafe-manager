"""Tests for src/core/clipboard/clipboard_settings.py (CLIP-3, CFG-2, CFG-3)."""

from pathlib import Path

import pytest

from src.core import config
from src.core.clipboard.clipboard_settings import (
    ClipboardSettings,
    apply_preset,
    load_clipboard_settings,
    save_clipboard_settings,
)
from src.core.settings_manager import SettingsManager
from src.database.db import Database


@pytest.fixture
def manager(tmp_path: Path) -> SettingsManager:
    db = Database(tmp_path / "settings.db")
    yield SettingsManager(db)
    db.close()


# --------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------- #


def test_load_returns_defaults_when_missing(manager: SettingsManager) -> None:
    s = load_clipboard_settings(manager)
    assert s.timeout == config.CLIPBOARD_TIMEOUT_DEFAULT
    assert s.notifications is True
    assert s.security_level == "basic"


def test_default_is_valid() -> None:
    ClipboardSettings().validate()


# --------------------------------------------------------------------- #
# Save / load roundtrip
# --------------------------------------------------------------------- #


def test_save_and_load_roundtrip(manager: SettingsManager) -> None:
    original = ClipboardSettings(
        timeout=15,
        notifications=False,
        security_level="advanced",
        preset="Secure",
    )
    save_clipboard_settings(manager, original)

    loaded = load_clipboard_settings(manager)
    assert loaded.timeout == 15
    assert loaded.notifications is False
    assert loaded.security_level == "advanced"
    assert loaded.preset == "Secure"


def test_settings_persist_across_manager_instances(tmp_path: Path) -> None:
    db_path = tmp_path / "persist.db"

    db1 = Database(db_path)
    m1 = SettingsManager(db1)
    save_clipboard_settings(m1, ClipboardSettings(timeout=42))
    db1.close()

    db2 = Database(db_path)
    m2 = SettingsManager(db2)
    loaded = load_clipboard_settings(m2)
    assert loaded.timeout == 42
    db2.close()


# --------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------- #


def test_validate_rejects_too_small_timeout() -> None:
    s = ClipboardSettings(timeout=1)
    with pytest.raises(ValueError):
        s.validate()


def test_validate_rejects_too_big_timeout() -> None:
    s = ClipboardSettings(timeout=9999)
    with pytest.raises(ValueError):
        s.validate()


def test_validate_allows_never() -> None:
    ClipboardSettings(timeout=config.CLIPBOARD_TIMEOUT_NEVER).validate()


def test_validate_rejects_unknown_security_level() -> None:
    s = ClipboardSettings(security_level="paranoid_plus")
    with pytest.raises(ValueError):
        s.validate()


def test_validate_accepts_all_levels() -> None:
    for lvl in config.CLIPBOARD_SECURITY_LEVELS:
        ClipboardSettings(security_level=lvl).validate()


# --------------------------------------------------------------------- #
# Presets (CFG-3)
# --------------------------------------------------------------------- #


def test_apply_preset_standard() -> None:
    s = apply_preset(ClipboardSettings(), "Standard")
    assert s.timeout == 30
    assert s.security_level == "basic"
    assert s.preset == "Standard"


def test_apply_preset_secure() -> None:
    s = apply_preset(ClipboardSettings(), "Secure")
    assert s.timeout == 15
    assert s.security_level == "advanced"


def test_apply_preset_public_computer() -> None:
    s = apply_preset(ClipboardSettings(), "Public Computer")
    assert s.timeout == 5
    assert s.security_level == "paranoid"


def test_apply_unknown_preset_raises() -> None:
    with pytest.raises(ValueError):
        apply_preset(ClipboardSettings(), "Nonsense")


# --------------------------------------------------------------------- #
# Partial dict handling
# --------------------------------------------------------------------- #


def test_from_dict_ignores_unknown_keys() -> None:
    s = ClipboardSettings.from_dict(
        {"timeout": 20, "unknown_key": "x"}
    )
    assert s.timeout == 20


def test_from_dict_fills_missing_fields() -> None:
    s = ClipboardSettings.from_dict({"timeout": 20})
    assert s.timeout == 20
    assert s.notifications is True
    assert s.security_level == "basic"