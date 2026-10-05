"""
Platform-specific clipboard adapters.

Two implementations are provided:

  * WindowsClipboardAdapter -- uses win32clipboard (pywin32) for
    native EmptyClipboard() support.
  * PyperclipAdapter        -- universal fallback via pyperclip.

A factory (get_default_adapter) chooses the best adapter for the
current platform and falls back to pyperclip if native APIs are
unavailable (ERR-1).
"""

from __future__ import annotations

import platform
import sys
from abc import ABC, abstractmethod


# --------------------------------------------------------------------- #
# Interface
# --------------------------------------------------------------------- #


class ClipboardAdapter(ABC):
    """Abstract interface for clipboard read/write."""

    name: str = "abstract"

    @abstractmethod
    def copy(self, text: str) -> bool:
        """Write text to the system clipboard. Return True on success."""

    @abstractmethod
    def clear(self) -> bool:
        """Clear the system clipboard. Return True on success."""

    @abstractmethod
    def read(self) -> str | None:
        """Read current clipboard text, or None if empty/unavailable."""


# --------------------------------------------------------------------- #
# Pyperclip (universal fallback)
# --------------------------------------------------------------------- #


class PyperclipAdapter(ClipboardAdapter):
    name = "pyperclip"

    def __init__(self) -> None:
        import pyperclip
        self._clip = pyperclip

    def copy(self, text: str) -> bool:
        try:
            self._clip.copy(text)
            return True
        except Exception:
            return False

    def clear(self) -> bool:
        try:
            self._clip.copy("")
            return True
        except Exception:
            return False

    def read(self) -> str | None:
        try:
            value = self._clip.paste()
            if not value:
                return None
            return value
        except Exception:
            return None


# --------------------------------------------------------------------- #
# Windows native (pywin32)
# --------------------------------------------------------------------- #


class WindowsClipboardAdapter(ClipboardAdapter):
    """
    Windows-native adapter using win32clipboard.

    Uses EmptyClipboard() to properly clear the clipboard, which is
    more reliable than writing an empty string.
    """

    name = "windows"

    def __init__(self) -> None:
        import win32clipboard  # type: ignore
        import win32con  # type: ignore
        self._cb = win32clipboard
        self._con = win32con

    def copy(self, text: str) -> bool:
        try:
            self._cb.OpenClipboard()
            try:
                self._cb.EmptyClipboard()
                self._cb.SetClipboardData(
                    self._con.CF_UNICODETEXT, text
                )
            finally:
                self._cb.CloseClipboard()
            return True
        except Exception:
            return False

    def clear(self) -> bool:
        try:
            self._cb.OpenClipboard()
            try:
                self._cb.EmptyClipboard()
            finally:
                self._cb.CloseClipboard()
            return True
        except Exception:
            return False

    def read(self) -> str | None:
        try:
            self._cb.OpenClipboard()
            try:
                if self._cb.IsClipboardFormatAvailable(self._con.CF_UNICODETEXT):
                    return self._cb.GetClipboardData(self._con.CF_UNICODETEXT)
                return None
            finally:
                self._cb.CloseClipboard()
        except Exception:
            return None


# --------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------- #


def get_default_adapter() -> ClipboardAdapter:
    """
    Return the best adapter for the current platform.

    On Windows, prefers the native win32 adapter when pywin32 is
    available. Otherwise falls back to pyperclip (ERR-1).
    """
    if sys.platform == "win32" and platform.system() == "Windows":
        try:
            return WindowsClipboardAdapter()
        except Exception:
            pass

    return PyperclipAdapter()