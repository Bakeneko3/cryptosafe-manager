"""
Security profiles.

A profile is a named set of security-related settings. Applying a
profile updates the underlying SettingsManager, explaining changes
through a diff.

Profiles:
  * Standard  — balanced defaults.
  * Enhanced  — shorter timeouts, memory locking on.
  * Paranoid  — minimal convenience, maximum protection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from src.core import config
from src.core.settings_manager import SettingsManager


SETTING_KEY = "security_profile"
SETTINGS_SECTION = "security"


class ProfileError(Exception):
    pass


@dataclass(frozen=True)
class SecurityProfile:
    name: str
    auto_lock_timeout: int
    clipboard_timeout: int
    use_memory_locking: bool
    stealth_mode: bool
    panic_hotkey_enabled: bool
    start_minimized_to_tray: bool
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------- #
# Built-in profiles
# --------------------------------------------------------------------- #


PROFILES: dict[str, SecurityProfile] = {
    "Standard": SecurityProfile(
        name="Standard",
        auto_lock_timeout=300,   # 5 min
        clipboard_timeout=30,
        use_memory_locking=True,
        stealth_mode=False,
        panic_hotkey_enabled=True,
        start_minimized_to_tray=False,
        description=(
            "Balanced defaults for everyday use: 5-minute auto-lock, "
            "30-second clipboard clear, memory locking on."
        ),
    ),
    "Enhanced": SecurityProfile(
        name="Enhanced",
        auto_lock_timeout=120,   # 2 min
        clipboard_timeout=15,
        use_memory_locking=True,
        stealth_mode=False,
        panic_hotkey_enabled=True,
        start_minimized_to_tray=True,
        description=(
            "Tighter timeouts (2-minute auto-lock, 15-second clipboard) "
            "and starts minimized to tray."
        ),
    ),
    "Paranoid": SecurityProfile(
        name="Paranoid",
        auto_lock_timeout=60,    # 1 min
        clipboard_timeout=5,
        use_memory_locking=True,
        stealth_mode=True,
        panic_hotkey_enabled=True,
        start_minimized_to_tray=True,
        description=(
            "Maximum protection: 1-minute auto-lock, 5-second clipboard, "
            "stealth panic mode."
        ),
    ),
}


DEFAULT_PROFILE = "Standard"


# --------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------- #


def validate_profile(profile: SecurityProfile) -> None:
    if profile.auto_lock_timeout < 60:
        raise ProfileError(
            "auto_lock_timeout must be at least 60 seconds."
        )
    if profile.clipboard_timeout not in (
        config.CLIPBOARD_TIMEOUT_NEVER,
    ) and not (
        config.CLIPBOARD_TIMEOUT_MIN
        <= profile.clipboard_timeout
        <= config.CLIPBOARD_TIMEOUT_MAX
    ):
        raise ProfileError(
            f"clipboard_timeout must be 0 or "
            f"{config.CLIPBOARD_TIMEOUT_MIN}-{config.CLIPBOARD_TIMEOUT_MAX}."
        )


# --------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------- #


def load_profile(manager: SettingsManager) -> SecurityProfile:
    """Load the currently-selected profile, falling back to default."""
    name = manager.get(SETTING_KEY, DEFAULT_PROFILE)
    if name not in PROFILES:
        name = DEFAULT_PROFILE
    return PROFILES[name]


def set_profile(manager: SettingsManager, name: str) -> SecurityProfile:
    """Persist a profile choice."""
    if name not in PROFILES:
        raise ProfileError(f"Unknown profile: {name}")
    profile = PROFILES[name]
    validate_profile(profile)
    manager.set(SETTING_KEY, name)
    return profile


def diff_profiles(
    current: SecurityProfile,
    target: SecurityProfile,
) -> list[tuple[str, Any, Any]]:
    """
    Return a list of (field, current_value, target_value) for fields
    that differ. The caller can show this to the user before applying.
    """
    out = []
    for key, new_value in target.to_dict().items():
        if key in ("name", "description"):
            continue
        old_value = current.to_dict().get(key)
        if old_value != new_value:
            out.append((key, old_value, new_value))
    return out


def explain_profile(profile: SecurityProfile) -> str:
    return profile.description