"""
User activity monitoring for auto-lock.

Tracks both application-level activity (mouse, keyboard, focus) via
Tk bindings and OS-level activity on Windows via GetLastInputInfo.

The monitor does not lock anything by itself: it invokes a callback
when the configured idle timeout is exceeded.
"""

from __future__ import annotations

import ctypes
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


# --------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------- #


DEFAULT_LOCK_TIMEOUT = 300  # 5 minutes
MIN_LOCK_TIMEOUT = 60       # 1 minute
MAX_LOCK_TIMEOUT = 8 * 3600  # 8 hours


@dataclass
class ActivityConfig:
    lock_timeout: int = DEFAULT_LOCK_TIMEOUT
    check_interval: float = 1.0  # how often to check the timeout


# --------------------------------------------------------------------- #
# System activity detection (Windows)
# --------------------------------------------------------------------- #


class _WindowsSystemActivity:
    """Return system idle time in seconds on Windows."""

    class _LASTINPUTINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_uint),
            ("dwTime", ctypes.c_uint),
        ]

    def __init__(self) -> None:
        self._available = True
        try:
            self._user32 = ctypes.windll.user32
            self._kernel32 = ctypes.windll.kernel32
        except Exception:
            self._available = False

    def idle_seconds(self) -> float:
        if not self._available:
            return 0.0
        info = self._LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(info)
        if not self._user32.GetLastInputInfo(ctypes.byref(info)):
            return 0.0
        # GetTickCount returns a 32-bit wrap-around counter.
        tick_count = self._kernel32.GetTickCount()
        delta = (tick_count - info.dwTime) & 0xFFFFFFFF
        return delta / 1000.0


# --------------------------------------------------------------------- #
# ActivityMonitor
# --------------------------------------------------------------------- #


class ActivityMonitor:
    """
    Monitors user activity and fires `lock_callback` when idle time
    exceeds the configured timeout.

    Thread-safe. `record_activity()` can be called from any thread.
    """

    def __init__(
        self,
        lock_callback: Callable[[], None],
        config: Optional[ActivityConfig] = None,
    ) -> None:
        self._lock_callback = lock_callback
        self._config = config or ActivityConfig()

        self._lock = threading.RLock()
        self._last_activity = time.monotonic()
        self._monitoring = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        self._windows = _WindowsSystemActivity()

    # ------------------------------------------------------------------ #
    # Config
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> ActivityConfig:
        return self._config

    def set_timeout(self, seconds: int) -> None:
        if seconds < MIN_LOCK_TIMEOUT:
            seconds = MIN_LOCK_TIMEOUT
        if seconds > MAX_LOCK_TIMEOUT:
            seconds = MAX_LOCK_TIMEOUT
        with self._lock:
            self._config = ActivityConfig(
                lock_timeout=seconds,
                check_interval=self._config.check_interval,
            )

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @property
    def running(self) -> bool:
        return self._monitoring and self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self._monitoring:
                return
            self._monitoring = True
            self._stop_event.clear()
            self._last_activity = time.monotonic()
            self._thread = threading.Thread(
                target=self._run,
                name="ActivityMonitor",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            if not self._monitoring:
                return
            self._monitoring = False
            self._stop_event.set()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
        with self._lock:
            self._thread = None

    # ------------------------------------------------------------------ #
    # Activity recording
    # ------------------------------------------------------------------ #

    def record_activity(self) -> None:
        with self._lock:
            self._last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        """Return the effective idle time (app or system, whichever is smaller)."""
        with self._lock:
            app_idle = time.monotonic() - self._last_activity
        sys_idle = self._windows.idle_seconds()
        return min(app_idle, sys_idle)

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        while not self._stop_event.wait(self._config.check_interval):
            idle = self.idle_seconds()
            if idle >= self._config.lock_timeout:
                # Avoid immediate re-trigger.
                self.record_activity()
                try:
                    self._lock_callback()
                except Exception:
                    pass