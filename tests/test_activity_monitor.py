"""Tests for src/core/security/activity_monitor.py (ACT-1, ACT-2, PERF-3)."""

import time

import pytest

from src.core.security.activity_monitor import (
    ActivityConfig,
    ActivityMonitor,
    MAX_LOCK_TIMEOUT,
    MIN_LOCK_TIMEOUT,
)


def _app_only_config(timeout: int = 1, interval: float = 0.05) -> ActivityConfig:
    return ActivityConfig(
        lock_timeout=timeout,
        check_interval=interval,
        use_system_idle=False,
    )


def test_config_defaults() -> None:
    cfg = ActivityConfig()
    assert cfg.lock_timeout == 300
    assert cfg.check_interval > 0
    assert cfg.use_system_idle is True


def test_monitor_starts_and_stops() -> None:
    m = ActivityMonitor(lock_callback=lambda: None)
    assert not m.running
    m.start()
    assert m.running
    m.stop()
    assert not m.running


def test_double_start_is_noop() -> None:
    m = ActivityMonitor(lock_callback=lambda: None)
    m.start()
    first_thread = m._thread
    m.start()
    assert m._thread is first_thread
    m.stop()


def test_record_activity_resets_idle() -> None:
    m = ActivityMonitor(
        lock_callback=lambda: None,
        config=_app_only_config(timeout=300, interval=1.0),
    )
    time.sleep(0.15)
    idle_before = m.idle_seconds()
    m.record_activity()
    idle_after = m.idle_seconds()
    assert idle_after < idle_before


def test_set_timeout_min_clamped() -> None:
    m = ActivityMonitor(lock_callback=lambda: None)
    m.set_timeout(10)
    assert m.config.lock_timeout == MIN_LOCK_TIMEOUT


def test_set_timeout_max_clamped() -> None:
    m = ActivityMonitor(lock_callback=lambda: None)
    m.set_timeout(10 ** 6)
    assert m.config.lock_timeout == MAX_LOCK_TIMEOUT


def test_lock_callback_invoked_on_timeout() -> None:
    called = []
    m = ActivityMonitor(
        lock_callback=lambda: called.append(time.monotonic()),
        config=_app_only_config(timeout=1, interval=0.05),
    )

    m.start()
    try:
        deadline = time.monotonic() + 3.0
        while not called and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        m.stop()

    assert called, "lock_callback was not invoked"


def test_activity_prevents_lock() -> None:
    called = []
    m = ActivityMonitor(
        lock_callback=lambda: called.append(1),
        config=_app_only_config(timeout=1, interval=0.05),
    )

    m.start()
    try:
        for _ in range(20):
            m.record_activity()
            time.sleep(0.05)
    finally:
        m.stop()

    assert not called


def test_idle_seconds_is_nonnegative() -> None:
    m = ActivityMonitor(lock_callback=lambda: None)
    assert m.idle_seconds() >= 0.0


def test_callback_exception_is_swallowed() -> None:
    def bad_callback():
        raise RuntimeError("boom")

    m = ActivityMonitor(
        lock_callback=bad_callback,
        config=_app_only_config(timeout=1, interval=0.05),
    )
    m.start()
    try:
        time.sleep(1.3)
    finally:
        m.stop()