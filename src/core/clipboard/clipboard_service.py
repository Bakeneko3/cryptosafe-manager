"""
Secure clipboard service.

Owns the auto-clear timer, publishes ClipboardCopied / ClipboardCleared
events, and coordinates with the platform adapter and the optional
background monitor.

This service does NOT encrypt the clipboard content: the system
clipboard must contain plaintext so other applications can paste it.
The protection model relies on auto-clear, not on obfuscation
(agreed in Sprint 4 planning).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, Optional

from src.core import config
from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.platform_adapter import (
    ClipboardAdapter,
    get_default_adapter,
)

if TYPE_CHECKING:
    from src.core.events import EventBus


# --------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------- #


@dataclass
class ClipboardStatus:
    active: bool = False
    data_type: str | None = None
    source_entry_id: str | None = None
    copied_at: datetime | None = None
    remaining_seconds: float = 0.0
    timeout_seconds: int = 0


# --------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------- #


class ClipboardService:
    """
    High-level clipboard façade.

    Thread-safe. All public methods acquire the internal lock.
    """

    def __init__(
        self,
        event_bus: "EventBus | None" = None,
        *,
        adapter: ClipboardAdapter | None = None,
        timeout: int = config.CLIPBOARD_TIMEOUT_DEFAULT,
        monitor: bool = True,
        on_warning: Optional[Callable[[float], None]] = None,
        on_external_change: Optional[Callable[[Optional[str]], None]] = None,
        on_monitor_failure: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._events = event_bus
        self._adapter = adapter or get_default_adapter()
        self._timeout = self._sanitize_timeout(timeout)
        self._on_warning = on_warning
        self._on_external_change = on_external_change
        self._on_monitor_failure = on_monitor_failure

        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None
        self._warning_timer: threading.Timer | None = None

        self._active_type: str | None = None
        self._active_entry_id: str | None = None
        self._active_copied_at: datetime | None = None
        self._active_deadline: float | None = None

        self._monitor: ClipboardMonitor | None = None
        if monitor:
            self._start_monitor()

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def adapter_name(self) -> str:
        return self._adapter.name

    @property
    def timeout(self) -> int:
        return self._timeout

    @property
    def monitor_running(self) -> bool:
        return self._monitor is not None and self._monitor.running

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #

    def set_timeout(self, timeout: int) -> None:
        """Set the auto-clear timeout (CLIP-2)."""
        with self._lock:
            self._timeout = self._sanitize_timeout(timeout)

    def _sanitize_timeout(self, timeout: int) -> int:
        if timeout == config.CLIPBOARD_TIMEOUT_NEVER:
            return config.CLIPBOARD_TIMEOUT_NEVER
        if timeout < config.CLIPBOARD_TIMEOUT_MIN:
            return config.CLIPBOARD_TIMEOUT_MIN
        if timeout > config.CLIPBOARD_TIMEOUT_MAX:
            return config.CLIPBOARD_TIMEOUT_MAX
        return timeout

    # ------------------------------------------------------------------ #
    # Copy
    # ------------------------------------------------------------------ #

    def copy(
        self,
        data: str,
        data_type: str = "text",
        source_entry_id: str | None = None,
    ) -> bool:
        """
        Copy data to the system clipboard and start the auto-clear timer.

        Returns True on success. Errors are swallowed: clipboard access
        can fail transiently when another process holds it open.

        Raises:
            RuntimeError: if the vault is locked (SEC-4). The caller
                          (GUI) is responsible for the lock check.
        """
        if data is None:
            return False

        with self._lock:
            # Cancel any pending timers / clear previous content first
            # (CLIP-4: new copy replaces old).
            self._cancel_timers()

            ok = self._adapter.copy(data)
            if not ok:
                return False

            self._active_type = data_type
            self._active_entry_id = source_entry_id
            self._active_copied_at = datetime.now(timezone.utc)

            if self._timeout != config.CLIPBOARD_TIMEOUT_NEVER:
                self._active_deadline = time.monotonic() + self._timeout
                self._schedule_clear(self._timeout)
                warning_at = max(
                    0, self._timeout - config.CLIPBOARD_WARNING_SECONDS
                )
                if warning_at > 0:
                    self._schedule_warning(warning_at)
            else:
                self._active_deadline = None

            if self._monitor is not None:
                self._monitor.note_write(data)

            self._publish_copied()

        return True

    # ------------------------------------------------------------------ #
    # Clear
    # ------------------------------------------------------------------ #

    def clear(self, reason: str = "manual") -> bool:
        """Clear the clipboard and stop all timers."""
        with self._lock:
            self._cancel_timers()

            ok = self._adapter.clear()
            if self._monitor is not None:
                self._monitor.note_clear()

            self._reset_state()
            self._publish_cleared(reason)

        return ok

    def clear_if_owned(self, reason: str = "manual") -> None:
        """
        Clear only if we currently own the clipboard (i.e. our own copy
        is still active). Used when the vault locks or the app closes.
        """
        with self._lock:
            if self._active_type is None:
                return
        self.clear(reason=reason)

    # ------------------------------------------------------------------ #
    # Status
    # ------------------------------------------------------------------ #

    def status(self) -> ClipboardStatus:
        with self._lock:
            if self._active_type is None or self._active_deadline is None:
                return ClipboardStatus(
                    active=self._active_type is not None,
                    data_type=self._active_type,
                    source_entry_id=self._active_entry_id,
                    copied_at=self._active_copied_at,
                    remaining_seconds=0.0,
                    timeout_seconds=self._timeout,
                )

            remaining = max(0.0, self._active_deadline - time.monotonic())
            return ClipboardStatus(
                active=True,
                data_type=self._active_type,
                source_entry_id=self._active_entry_id,
                copied_at=self._active_copied_at,
                remaining_seconds=remaining,
                timeout_seconds=self._timeout,
            )

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def shutdown(self) -> None:
        """Stop timers and monitor; used on application close."""
        with self._lock:
            self._cancel_timers()
            self._reset_state()
        if self._monitor is not None:
            self._monitor.stop()
            self._monitor = None

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _reset_state(self) -> None:
        self._active_type = None
        self._active_entry_id = None
        self._active_copied_at = None
        self._active_deadline = None

    def _cancel_timers(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self._warning_timer is not None:
            self._warning_timer.cancel()
            self._warning_timer = None

    def _schedule_clear(self, delay: float) -> None:
        self._timer = threading.Timer(delay, self._on_timeout)
        self._timer.daemon = True
        self._timer.start()

    def _schedule_warning(self, delay: float) -> None:
        self._warning_timer = threading.Timer(delay, self._on_warning_timer)
        self._warning_timer.daemon = True
        self._warning_timer.start()

    def _on_timeout(self) -> None:
        try:
            self.clear(reason="timeout")
        except Exception:
            # Timers must never crash with an unhandled exception.
            # See ERR-2 in Sprint 4 requirements.
            pass

    def _on_warning_timer(self) -> None:
        if self._on_warning is None:
            return
        with self._lock:
            remaining = config.CLIPBOARD_WARNING_SECONDS
        try:
            self._on_warning(remaining)
        except Exception:
            pass

    def _on_monitor_event(self, content: str | None) -> None:
        """
        Called by ClipboardMonitor when it detects a change we did not
        make. We treat this as "our copy is gone" and reset state.
        """
        with self._lock:
            # If our data was already cleared, nothing to do.
            if self._active_type is None:
                return
            # External change: drop our ownership, cancel timers.
            self._cancel_timers()
            self._reset_state()

        if self._on_external_change is not None:
            try:
                self._on_external_change(content)
            except Exception:
                pass

    def _start_monitor(self) -> None:
        try:
            self._monitor = ClipboardMonitor(
                self._adapter,
                on_external_change=self._on_monitor_event,
                on_failure=self._on_monitor_failure,
                poll_interval=config.CLIPBOARD_MONITOR_POLL_INTERVAL,
            )
            self._monitor.start()
        except Exception:
            # Graceful degradation (ERR-3).
            self._monitor = None

    # ------------------------------------------------------------------ #
    # Event publishing
    # ------------------------------------------------------------------ #

    def _publish_copied(self) -> None:
        if self._events is None:
            return
        from src.core.events import ClipboardCopied
        self._events.publish(
            ClipboardCopied(
                data_type=self._active_type or "text",
                source_entry_id=self._active_entry_id,
                timeout=self._timeout,
            )
        )

    def _publish_cleared(self, reason: str) -> None:
        if self._events is None:
            return
        from src.core.events import ClipboardCleared
        self._events.publish(
            ClipboardCleared(reason=reason)
        )