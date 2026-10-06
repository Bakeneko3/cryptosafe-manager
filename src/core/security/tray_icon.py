"""
System tray integration.

Runs the tray icon in a background thread and dispatches all callbacks
to the Tk main thread via `root.after(0, ...)`.

If `pystray` is unavailable (missing dependency, headless environment),
the wrapper degrades to a no-op.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional


try:
    import pystray
    from pystray import Menu, MenuItem
    from PIL import Image, ImageDraw

    _PYSTRAY_AVAILABLE = True
except Exception:
    _PYSTRAY_AVAILABLE = False


# --------------------------------------------------------------------- #
# Icon generation
# --------------------------------------------------------------------- #


def _make_icon_image(color: str, size: int = 64):
    """Generate a simple shield-like icon in the given color."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Simple filled circle with a smaller inner dot.
    margin = size // 8
    draw.ellipse(
        (margin, margin, size - margin, size - margin),
        fill=color,
        outline="black",
    )
    inner = size // 3
    draw.ellipse(
        (inner, inner, size - inner, size - inner),
        fill="white",
    )
    return img


ICON_LOCKED = "#c0392b"    # red
ICON_UNLOCKED = "#27ae60"  # green


# --------------------------------------------------------------------- #
# TrayIcon
# --------------------------------------------------------------------- #


class TrayIcon:
    """
    Wraps a pystray icon with Tkinter-safe callbacks.

    `root` must be a Tk instance; all callbacks are dispatched through
    `root.after(0, ...)`. The tray icon itself runs in a background
    thread.
    """

    def __init__(
        self,
        root,
        *,
        on_show: Callable[[], None],
        on_lock_toggle: Callable[[], None],
        on_clear_clipboard: Callable[[], None],
        on_panic: Callable[[], None],
        on_settings: Callable[[], None],
        on_exit: Callable[[], None],
        title: str = "CryptoSafe Manager",
    ) -> None:
        self._root = root
        self._title = title

        self._on_show = on_show
        self._on_lock_toggle = on_lock_toggle
        self._on_clear_clipboard = on_clear_clipboard
        self._on_panic = on_panic
        self._on_settings = on_settings
        self._on_exit = on_exit

        self._icon = None
        self._thread: Optional[threading.Thread] = None
        self._available = _PYSTRAY_AVAILABLE
        self._locked = True

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @property
    def available(self) -> bool:
        return self._available

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if not self._available or self.running:
            return

        menu = Menu(
            MenuItem("Show", self._dispatch(self._on_show), default=True),
            MenuItem("Lock/Unlock", self._dispatch(self._on_lock_toggle)),
            MenuItem("Clear Clipboard", self._dispatch(self._on_clear_clipboard)),
            MenuItem("Panic", self._dispatch(self._on_panic)),
            Menu.SEPARATOR,
            MenuItem("Settings", self._dispatch(self._on_settings)),
            MenuItem("Exit", self._dispatch(self._on_exit)),
        )

        self._icon = pystray.Icon(
            "cryptosafe",
            icon=_make_icon_image(ICON_LOCKED),
            title=self._title,
            menu=menu,
        )

        self._thread = threading.Thread(
            target=self._icon.run,
            name="TrayIcon",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        icon = self._icon
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass
        self._icon = None

    # ------------------------------------------------------------------ #
    # State updates
    # ------------------------------------------------------------------ #

    def set_locked(self, locked: bool) -> None:
        self._locked = locked
        if self._icon is None:
            return
        try:
            color = ICON_LOCKED if locked else ICON_UNLOCKED
            self._icon.icon = _make_icon_image(color)
            self._icon.title = self._title + (" [Locked]" if locked else " [Unlocked]")
        except Exception:
            pass

    def notify(self, message: str, title: Optional[str] = None) -> None:
        if self._icon is None:
            return
        try:
            self._icon.notify(message, title or self._title)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Dispatch to Tk main thread
    # ------------------------------------------------------------------ #

    def _dispatch(self, callback: Callable[[], None]) -> Callable:
        def wrapped(icon=None, item=None):
            try:
                self._root.after(0, callback)
            except Exception:
                callback()
        return wrapped