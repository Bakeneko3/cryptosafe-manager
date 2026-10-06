"""
User activity monitoring for auto-lock.
"""

from __future__ import annotations

import ctypes
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


DEFAULT_LOCK_TIMEOUT = 300
MIN_LOCK_TIMEOUT = 60
MAX_LOCK_TIMEOUT = 8 * 3600


@dataclass
class ActivityConfig:
    lock_timeout: int = DEFAULT_LOCK_TIMEOUT
    check_interval: float = 1.0
    use_system_idle: bool = True


class _WindowsSystemActivity:
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
        tick_count = self._kernel32.GetTickCount()
        delta = (tick_count - info.dwTime) & 0xFFFFFFFF
        return delta / 1000.0


class ActivityMonitor:
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
                use_system_idle=self._config.use_system_idle,
            )

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

    def record_activity(self) -> None:
        with self._lock:
            self._last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        """
        Return the effective idle time.

        With use_system_idle=True (default), returns the smaller of the
        application-level and OS-level idle times — auto-lock fires when
        neither the app nor the system sees activity.

        With use_system_idle=False, returns only the application-level
        idle time (useful for tests).
        """
        with self._lock:
            app_idle = time.monotonic() - self._last_activity
            use_sys = self._config.use_system_idle

        if not use_sys:
            return app_idle

        sys_idle = self._windows.idle_seconds()
        return min(app_idle, sys_idle)

    def _run(self) -> None:
        while not self._stop_event.wait(self._config.check_interval):
            idle = self.idle_seconds()
            if idle >= self._config.lock_timeout:
                self.record_activity()
                try:
                    self._lock_callback()
                except Exception:
                    pass