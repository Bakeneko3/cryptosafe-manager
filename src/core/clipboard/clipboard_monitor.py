"""
Background clipboard monitor.

Polls the system clipboard at a fixed interval and notifies the caller
when the content changes outside of our own writes.

Limitations (documented, by design):
  * Reading the clipboard is not detectable: there is no portable API
    to know that some other process *read* the clipboard. We only detect
    *content changes*.
  * Polling is used because Windows has no reliable "clipboard changed"
    event for cross-process notification without creating a message
    window.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from src.core.clipboard.platform_adapter import ClipboardAdapter


class ClipboardMonitor:
    """
    Polls the clipboard and invokes `on_external_change` when it sees a
    value it did not write itself.

    Usage:
        monitor = ClipboardMonitor(adapter, on_external_change=cb)
        monitor.start()
        ...
        monitor.stop()
    """

    def __init__(
        self,
        adapter: ClipboardAdapter,
        on_external_change: Callable[[Optional[str]], None],
        *,
        on_failure: Optional[Callable[[str], None]] = None,
        poll_interval: float = 0.5,
        max_consecutive_errors: int = 10,
    ) -> None:
        self._adapter = adapter
        self._on_external_change = on_external_change
        self._on_failure = on_failure
        self._poll_interval = poll_interval
        self._max_errors = max_consecutive_errors

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_seen: str | None = None
        self._errors = 0

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._last_seen = self._read_once()
        self._thread = threading.Thread(
            target=self._run,
            name="ClipboardMonitor",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
        self._thread = None

    # ------------------------------------------------------------------ #
    # Notice our own writes
    # ------------------------------------------------------------------ #

    def note_write(self, text: str | None) -> None:
        """
        Inform the monitor that the application just wrote `text` to
        the clipboard, so its own write is not reported as external.
        """
        self._last_seen = text

    def note_clear(self) -> None:
        """Inform the monitor that the clipboard was just cleared."""
        self._last_seen = None

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        while not self._stop_event.wait(self._poll_interval):
            current = self._read_once()

            if self._errors >= self._max_errors:
                if self._on_failure is not None:
                    try:
                        self._on_failure(
                            "Clipboard monitoring disabled: "
                            "unable to read the clipboard."
                        )
                    except Exception:
                        pass
                return

            if current != self._last_seen:
                self._last_seen = current
                try:
                    self._on_external_change(current)
                except Exception:
                    # A listener must not bring down the monitor.
                    pass

    def _read_once(self) -> str | None:
        """
        Read the clipboard once, update the error counter, and return
        the current value (or None on error).
        """
        try:
            value = self._adapter.read()
        except Exception:
            value = None

        if value is None:
            self._errors += 1
        else:
            self._errors = 0
        return value