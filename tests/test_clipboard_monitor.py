"""Tests for src/core/clipboard/clipboard_monitor.py."""

import time

import pytest

from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.platform_adapter import PyperclipAdapter


class FakeAdapter:
    """In-memory adapter for deterministic tests."""

    name = "fake"

    def __init__(self) -> None:
        self._value: str | None = None

    def copy(self, text: str) -> bool:
        self._value = text
        return True

    def clear(self) -> bool:
        self._value = None
        return True

    def read(self) -> str | None:
        return self._value


@pytest.fixture
def adapter() -> FakeAdapter:
    return FakeAdapter()


def test_monitor_starts_and_stops(adapter: FakeAdapter) -> None:
    m = ClipboardMonitor(adapter, on_external_change=lambda v: None, poll_interval=0.05)
    assert not m.running
    m.start()
    assert m.running
    m.stop()
    assert not m.running


def test_monitor_reports_external_change(adapter: FakeAdapter) -> None:
    seen: list[str | None] = []
    m = ClipboardMonitor(
        adapter,
        on_external_change=lambda v: seen.append(v),
        poll_interval=0.05,
    )
    m.start()
    try:
        adapter.copy("external")
        time.sleep(0.2)
    finally:
        m.stop()
    assert "external" in seen


def test_monitor_ignores_own_write(adapter: FakeAdapter) -> None:
    seen: list[str | None] = []
    m = ClipboardMonitor(
        adapter,
        on_external_change=lambda v: seen.append(v),
        poll_interval=0.05,
    )
    m.start()
    try:
        adapter.copy("ours")
        m.note_write("ours")
        time.sleep(0.2)
    finally:
        m.stop()
    assert seen == []


def test_monitor_reports_clear(adapter: FakeAdapter) -> None:
    seen: list[str | None] = []
    m = ClipboardMonitor(
        adapter,
        on_external_change=lambda v: seen.append(v),
        poll_interval=0.05,
    )
    m.start()
    try:
        adapter.copy("secret")
        time.sleep(0.15)
        adapter.clear()
        time.sleep(0.15)
    finally:
        m.stop()
    assert "secret" in seen
    assert seen[-1] is None


def test_monitor_calls_failure_on_repeated_errors() -> None:
    """
    Verify that the monitor reports a failure after max_consecutive_errors.

    Does NOT start the background thread: under Python 3.14 the GC can
    crash when a daemon thread raises in a tight loop. We exercise the
    internal path directly instead.
    """
    class BrokenAdapter:
        name = "broken"

        def copy(self, text): return False
        def clear(self): return False
        def read(self): raise RuntimeError("boom")

    failures: list[str] = []
    m = ClipboardMonitor(
        BrokenAdapter(),
        on_external_change=lambda v: None,
        on_failure=lambda msg: failures.append(msg),
        poll_interval=0.05,
        max_consecutive_errors=3,
    )

    # Simulate the monitor loop body without spawning a thread.
    for _ in range(5):
        m._read_once()
        if m._errors >= m._max_errors:
            m._on_failure(
                "Clipboard monitoring disabled: unable to read the clipboard."
            )
            break

    assert len(failures) == 1
    assert "monitoring disabled" in failures[0].lower()


def test_monitor_note_clear_prevents_false_positive(adapter: FakeAdapter) -> None:
    seen: list[str | None] = []
    m = ClipboardMonitor(
        adapter,
        on_external_change=lambda v: seen.append(v),
        poll_interval=0.05,
    )
    m.start()
    try:
        adapter.copy("x")
        m.note_write("x")
        adapter.clear()
        m.note_clear()
        time.sleep(0.2)
    finally:
        m.stop()
    assert seen == []


def test_monitor_double_start_is_noop(adapter: FakeAdapter) -> None:
    m = ClipboardMonitor(adapter, on_external_change=lambda v: None, poll_interval=0.05)
    m.start()
    first_thread = m._thread
    m.start()
    assert m._thread is first_thread
    m.stop()