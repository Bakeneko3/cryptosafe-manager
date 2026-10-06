"""Tests for src/core/security/security_profiles.py (CFG-1..3)."""

from pathlib import Path

import pytest

from src.core.security.security_profiles import (
    DEFAULT_PROFILE,
    PROFILES,
    ProfileError,
    SecurityProfile,
    diff_profiles,
    explain_profile,
    load_profile,
    set_profile,
    validate_profile,
)
from src.core.settings_manager import SettingsManager
from src.database.db import Database


@pytest.fixture
def manager(tmp_path: Path) -> SettingsManager:
    db = Database(tmp_path / "profiles.db")
    yield SettingsManager(db)
    db.close()


# --------------------------------------------------------------------- #
# Built-in profiles
# --------------------------------------------------------------------- #


def test_three_profiles_exist() -> None:
    assert set(PROFILES.keys()) == {"Standard", "Enhanced", "Paranoid"}


def test_default_profile() -> None:
    assert DEFAULT_PROFILE == "Standard"


def test_all_profiles_are_valid() -> None:
    for p in PROFILES.values():
        validate_profile(p)


def test_standard_profile_values() -> None:
    p = PROFILES["Standard"]
    assert p.auto_lock_timeout == 300
    assert p.clipboard_timeout == 30
    assert p.stealth_mode is False


def test_paranoid_is_strictest() -> None:
    std = PROFILES["Standard"]
    par = PROFILES["Paranoid"]
    assert par.auto_lock_timeout < std.auto_lock_timeout
    assert par.clipboard_timeout < std.clipboard_timeout
    assert par.stealth_mode is True


# --------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------- #


def test_validate_rejects_short_auto_lock() -> None:
    bad = SecurityProfile(
        name="Bad",
        auto_lock_timeout=30,
        clipboard_timeout=30,
        use_memory_locking=True,
        stealth_mode=False,
        panic_hotkey_enabled=True,
        start_minimized_to_tray=False,
        description="",
    )
    with pytest.raises(ProfileError):
        validate_profile(bad)


def test_validate_rejects_bad_clipboard_timeout() -> None:
    bad = SecurityProfile(
        name="Bad",
        auto_lock_timeout=300,
        clipboard_timeout=2,  # below MIN
        use_memory_locking=True,
        stealth_mode=False,
        panic_hotkey_enabled=True,
        start_minimized_to_tray=False,
        description="",
    )
    with pytest.raises(ProfileError):
        validate_profile(bad)


def test_validate_allows_never_clipboard() -> None:
    from src.core import config

    p = SecurityProfile(
        name="Never",
        auto_lock_timeout=300,
        clipboard_timeout=config.CLIPBOARD_TIMEOUT_NEVER,
        use_memory_locking=True,
        stealth_mode=False,
        panic_hotkey_enabled=True,
        start_minimized_to_tray=False,
        description="",
    )
    validate_profile(p)


# --------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------- #


def test_load_default_when_missing(manager: SettingsManager) -> None:
    profile = load_profile(manager)
    assert profile.name == "Standard"


def test_set_and_load(manager: SettingsManager) -> None:
    set_profile(manager, "Paranoid")
    profile = load_profile(manager)
    assert profile.name == "Paranoid"
    assert profile.stealth_mode is True


def test_set_unknown_profile_raises(manager: SettingsManager) -> None:
    with pytest.raises(ProfileError):
        set_profile(manager, "Nonsense")


def test_load_unknown_saved_value_falls_back(manager: SettingsManager) -> None:
    manager.set("security_profile", "NonExistentProfile")
    profile = load_profile(manager)
    assert profile.name == "Standard"


# --------------------------------------------------------------------- #
# Diff
# --------------------------------------------------------------------- #


def test_diff_profiles_empty_when_same() -> None:
    diff = diff_profiles(PROFILES["Standard"], PROFILES["Standard"])
    assert diff == []


def test_diff_profiles_shows_changes() -> None:
    diff = diff_profiles(PROFILES["Standard"], PROFILES["Paranoid"])
    fields = [f for f, _, _ in diff]
    assert "auto_lock_timeout" in fields
    assert "clipboard_timeout" in fields
    assert "stealth_mode" in fields


def test_diff_profiles_includes_values() -> None:
    diff = diff_profiles(PROFILES["Standard"], PROFILES["Paranoid"])
    auto = next(d for d in diff if d[0] == "auto_lock_timeout")
    _, old_v, new_v = auto
    assert old_v == 300
    assert new_v == 60


# --------------------------------------------------------------------- #
# Explanation
# --------------------------------------------------------------------- #


def test_explain_profile_returns_description() -> None:
    text = explain_profile(PROFILES["Enhanced"])
    assert "tray" in text.lower() or "timeout" in text.lower()