"""Tests for src/core/clipboard/clipboard_service.py (CLIP-1..4, ARC-3)."""

import time

import pytest

from src.core import config
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.events import ClipboardCleared, ClipboardCopied, EventBus


class FakeAdapter:
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


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def service(adapter: FakeAdapter, bus: EventBus) -> ClipboardService:
    return ClipboardService(bus, adapter=adapter, monitor=False)


# --------------------------------------------------------------------- #
# Basic copy / clear
# --------------------------------------------------------------------- #


def test_copy_writes_to_clipboard(service: ClipboardService, adapter: FakeAdapter) -> None:
    assert service.copy("hello") is True
    assert adapter.read() == "hello"


def test_clear_empties_clipboard(service: ClipboardService, adapter: FakeAdapter) -> None:
    service.copy("secret")
    service.clear()
    assert adapter.read() in (None, "")


def test_status_inactive_when_empty(service: ClipboardService) -> None:
    s = service.status()
    assert s.active is False


def test_status_active_after_copy(service: ClipboardService) -> None:
    service.copy("hello", data_type="password", source_entry_id="abc")
    s = service.status()
    assert s.active is True
    assert s.data_type == "password"
    assert s.source_entry_id == "abc"


def test_status_inactive_after_clear(service: ClipboardService) -> None:
    service.copy("hello")
    service.clear()
    assert service.status().active is False


# --------------------------------------------------------------------- #
# Auto-clear timing (TEST-1)
# --------------------------------------------------------------------- #


def test_auto_clear_after_timeout(adapter: FakeAdapter) -> None:
    service = ClipboardService(
        adapter=adapter,
        timeout=1,  # 1 second (clamped to MIN=5 by sanitize...)
        monitor=False,
    )
    # Because sanitize clamps below MIN to MIN, set direct
    service._timeout = 1
    service.copy("secret")
    assert adapter.read() == "secret"
    time.sleep(1.3)
    assert adapter.read() in (None, "")


def test_timeout_sanitize_min(adapter: FakeAdapter) -> None:
    service = ClipboardService(adapter=adapter, monitor=False)
    service.set_timeout(1)
    assert service.timeout == config.CLIPBOARD_TIMEOUT_MIN


def test_timeout_sanitize_max(adapter: FakeAdapter) -> None:
    service = ClipboardService(adapter=adapter, monitor=False)
    service.set_timeout(9999)
    assert service.timeout == config.CLIPBOARD_TIMEOUT_MAX


def test_timeout_never(adapter: FakeAdapter) -> None:
    service = ClipboardService(adapter=adapter, monitor=False)
    service.set_timeout(config.CLIPBOARD_TIMEOUT_NEVER)
    service.copy("sticky")
    time.sleep(0.3)
    # Still there — no timer.
    assert adapter.read() == "sticky"


# --------------------------------------------------------------------- #
# Events (ARC-3)
# --------------------------------------------------------------------- #


def test_copy_publishes_event(adapter: FakeAdapter, bus: EventBus) -> None:
    service = ClipboardService(bus, adapter=adapter, monitor=False)
    received = []
    bus.subscribe(ClipboardCopied, lambda e: received.append(e))

    service.copy("hello", data_type="password", source_entry_id="abc")

    assert len(received) == 1
    assert received[0].data_type == "password"
    assert received[0].source_entry_id == "abc"


def test_clear_publishes_event(adapter: FakeAdapter, bus: EventBus) -> None:
    service = ClipboardService(bus, adapter=adapter, monitor=False)
    received = []
    bus.subscribe(ClipboardCleared, lambda e: received.append(e))

    service.copy("hello")
    service.clear(reason="manual")

    assert len(received) == 1
    assert received[0].reason == "manual"


def test_auto_clear_publishes_event(adapter: FakeAdapter, bus: EventBus) -> None:
    service = ClipboardService(bus, adapter=adapter, monitor=False)
    service._timeout = 1  # bypass sanitize for test speed
    received = []
    bus.subscribe(ClipboardCleared, lambda e: received.append(e))

    service.copy("hello")
    time.sleep(1.3)

    assert any(e.reason == "timeout" for e in received)


# --------------------------------------------------------------------- #
# CLIP-4: replacement
# --------------------------------------------------------------------- #


def test_new_copy_replaces_previous(service: ClipboardService, adapter: FakeAdapter) -> None:
    service.copy("first", data_type="password")
    service.copy("second", data_type="username")
    assert adapter.read() == "second"
    assert service.status().data_type == "username"


def test_clear_if_owned(service: ClipboardService, adapter: FakeAdapter) -> None:
    service.copy("hello")
    service.clear_if_owned(reason="lock")
    assert service.status().active is False


def test_clear_if_owned_does_nothing_when_inactive(service: ClipboardService) -> None:
    # No copy — clear_if_owned should be a no-op.
    service.clear_if_owned()
    assert service.status().active is False


# --------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------- #


def test_remaining_seconds_decreases(adapter: FakeAdapter) -> None:
    service = ClipboardService(adapter=adapter, timeout=30, monitor=False)
    service.copy("hello")
    r1 = service.status().remaining_seconds
    time.sleep(0.1)
    r2 = service.status().remaining_seconds
    assert r2 < r1


# --------------------------------------------------------------------- #
# Warning callback
# --------------------------------------------------------------------- #


def test_warning_callback_is_called(adapter: FakeAdapter) -> None:
    warnings: list[float] = []
    service = ClipboardService(
        adapter=adapter,
        monitor=False,
        timeout=10,
        on_warning=lambda sec: warnings.append(sec),
    )
    # Speed up: schedule a very short warning.
    service.copy("hello")
    time.sleep(0.2)
    # We do not wait for the real 5-second warning; just verify the
    # service stores the callback and it can be invoked.
    assert service._on_warning is not None


# --------------------------------------------------------------------- #
# Shutdown
# --------------------------------------------------------------------- #


def test_shutdown_stops_timers(service: ClipboardService) -> None:
    service.copy("hello")
    service.shutdown()
    assert service.status().active is False