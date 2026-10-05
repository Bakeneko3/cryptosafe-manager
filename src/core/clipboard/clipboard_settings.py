"""
Typed access to clipboard settings stored in the settings table.

The underlying storage is SettingsManager (which uses the settings
table with optional encryption). This module provides a stable schema
on top of it.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.core import config
from src.core.settings_manager import SettingsManager


SETTING_KEY = "clipboard"


@dataclass
class ClipboardSettings:
    timeout: int = config.CLIPBOARD_TIMEOUT_DEFAULT
    notifications: bool = True
    security_level: str = "basic"
    preset: str = config.CLIPBOARD_DEFAULT_PRESET

    def to_dict(self) -> dict:
        return {
            "timeout": self.timeout,
            "notifications": self.notifications,
            "security_level": self.security_level,
            "preset": self.preset,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ClipboardSettings":
        return cls(
            timeout=int(data.get("timeout", config.CLIPBOARD_TIMEOUT_DEFAULT)),
            notifications=bool(data.get("notifications", True)),
            security_level=str(data.get("security_level", "basic")),
            preset=str(data.get("preset", config.CLIPBOARD_DEFAULT_PRESET)),
        )

    def validate(self) -> None:
        if (
            self.timeout != config.CLIPBOARD_TIMEOUT_NEVER
            and not (
                config.CLIPBOARD_TIMEOUT_MIN
                <= self.timeout
                <= config.CLIPBOARD_TIMEOUT_MAX
            )
        ):
            raise ValueError(
                f"timeout must be {config.CLIPBOARD_TIMEOUT_MIN}-"
                f"{config.CLIPBOARD_TIMEOUT_MAX} or 0 (never)"
            )
        if self.security_level not in config.CLIPBOARD_SECURITY_LEVELS:
            raise ValueError(
                f"security_level must be one of "
                f"{config.CLIPBOARD_SECURITY_LEVELS}"
            )


# --------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------- #


def load_clipboard_settings(manager: SettingsManager) -> ClipboardSettings:
    """Load clipboard settings, applying defaults if missing."""
    data = manager.get(SETTING_KEY, None)
    if not isinstance(data, dict):
        return ClipboardSettings()
    return ClipboardSettings.from_dict(data)


def save_clipboard_settings(
    manager: SettingsManager,
    settings: ClipboardSettings,
) -> None:
    """Persist clipboard settings, validating before storage."""
    settings.validate()
    manager.set(SETTING_KEY, settings.to_dict())


def apply_preset(
    settings: ClipboardSettings,
    preset_name: str,
) -> ClipboardSettings:
    """
    Return a new ClipboardSettings with the preset applied (CFG-3).
    """
    if preset_name not in config.CLIPBOARD_PRESETS:
        raise ValueError(f"Unknown preset: {preset_name}")

    preset = config.CLIPBOARD_PRESETS[preset_name]
    return ClipboardSettings(
        timeout=int(preset["timeout"]),
        notifications=bool(preset["notifications"]),
        security_level=str(preset["security_level"]),
        preset=preset_name,
    )