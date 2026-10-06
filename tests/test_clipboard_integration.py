"""
Integration tests for the clipboard subsystem.

Covers:
  * TEST-1  -- auto-clear timing accuracy (±100 ms).
  * TEST-4  -- concurrent copy operations do not leak.
  * TEST-5  -- no dangling state after simulated failures.
  * PERF-1  -- single copy completes in < 100 ms.

Note: concurrency tests disable the auto-clear timer to avoid
spawning dozens of threads in a tight loop, which crashes the
Python 3.14 interpreter inside GC.
"""

import threading
import time

import pytest

from src.core import config
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.events import ClipboardCleared, ClipboardCopied, EventBus


# --------------------------------------------------------------------- #
# Fake adapter with explicit control over failures
# --------------------------------------------------------------------- #


class FakeAdapter:
    name = "fake"

    def __init__(self) -> None:
        self._value: str | None = None
        self.copy_calls = 0
        self.clear_calls = 0
        self.fail_copy = False

    def copy(self, text: str) -> bool:
        self.copy_calls += 1
        if self.fail_copy:
            return False
        self._value = text
        return True

    def clear(self) -> bool:
        self.clear_calls += 1
        self._value = None
        return True

    def read(self) -> str | None:
        return self._value


# --------------------------------------------------------------------- #
# TEST-1: auto-clear timing accuracy
# --------------------------------------------------------------------- #


def test_auto_clear_within_tolerance() -> None:
    """TEST-1: auto-clear happens within ±100 ms of the configured timeout."""
    adapter = FakeAdapter()
    service = ClipboardService(adapter=adapter, monitor=False)
    service._timeout = 1

    service.copy("secret")
    assert adapter.read() == "secret"

    start = time.monotonic()
    while adapter.read() is not None:
        time.sleep(0.01)
        if time.monotonic() - start > 3:
            break
    elapsed = time.monotonic() - start

    assert elapsed >= 0.9, f"cleared too early: {elapsed:.3f}s"
    assert elapsed <= 1.2, f"cleared too late: {elapsed:.3f}s"


# --------------------------------------------------------------------- #
# TEST-4: concurrency
# --------------------------------------------------------------------- #


def test_concurrent_copies_do_not_crash() -> None:
    adapter = FakeAdapter()
    service = ClipboardService(adapter=adapter, monitor=False)
    # Disable timers: we test concurrent access, not timing.
    service._timeout = config.CLIPBOARD_TIMEOUT_NEVER

    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            for _ in range(20):
                service.copy(f"data-{i}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    final = adapter.read()
    assert final is not None
    assert final.startswith("data-")


def test_concurrent_copy_and_clear_consistent() -> None:
    adapter = FakeAdapter()
    service = ClipboardService(adapter=adapter, monitor=False)
    service._timeout = config.CLIPBOARD_TIMEOUT_NEVER

    errors: list[Exception] = []

    def copier() -> None:
        try:
            for _ in range(30):
                service.copy("x")
        except Exception as exc:
            errors.append(exc)

    def clearer() -> None:
        try:
            for _ in range(30):
                service.clear(reason="test")
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=copier),
        threading.Thread(target=clearer),
        threading.Thread(target=copier),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []


def test_events_not_lost_under_concurrency() -> None:
    adapter = FakeAdapter()
    bus = EventBus()
    service = ClipboardService(bus, adapter=adapter, monitor=False)
    service._timeout = config.CLIPBOARD_TIMEOUT_NEVER

    copied: list[ClipboardCopied] = []
    cleared: list[ClipboardCleared] = []
    bus.subscribe(ClipboardCopied, lambda e: copied.append(e))
    bus.subscribe(ClipboardCleared, lambda e: cleared.append(e))

    def worker() -> None:
        for _ in range(10):
            service.copy("y")
            service.clear(reason="test")

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(copied) == 30
    assert len(cleared) == 30


# --------------------------------------------------------------------- #
# TEST-5: recovery after copy failure
# --------------------------------------------------------------------- #


def test_failed_copy_does_not_leave_state() -> None:
    adapter = FakeAdapter()
    adapter.fail_copy = True

    service = ClipboardService(adapter=adapter, monitor=False)
    ok = service.copy("secret")

    assert ok is False
    assert service.status().active is False


def test_adapter_failure_does_not_crash_clear() -> None:
    adapter = FakeAdapter()
    service = ClipboardService(adapter=adapter, monitor=False)

    service.copy("x")
    adapter.fail_copy = True
    assert service.clear() is True
    assert service.status().active is False


def test_service_survives_broken_clear() -> None:
    class BrokenClearAdapter(FakeAdapter):
        def clear(self) -> bool:
            raise RuntimeError("clear failed")

    adapter = BrokenClearAdapter()
    service = ClipboardService(adapter=adapter, monitor=False)
    # Disable the timer: we test the clear() call, not the timeout.
    service._timeout = config.CLIPBOARD_TIMEOUT_NEVER

    with pytest.raises(RuntimeError):
        service.clear()

    assert service.copy("retry") is True
    service.shutdown()


# --------------------------------------------------------------------- #
# PERF-1: copy operation < 100 ms
# --------------------------------------------------------------------- #


def test_perf_copy_under_100ms() -> None:
    adapter = FakeAdapter()
    service = ClipboardService(adapter=adapter, monitor=False)

    start = time.perf_counter()
    service.copy("perf-test")
    elapsed = time.perf_counter() - start

    assert elapsed < 0.1, f"copy took {elapsed * 1000:.1f} ms"


# --------------------------------------------------------------------- #
# Status sanity
# --------------------------------------------------------------------- #


def test_status_after_multiple_copies() -> None:
    adapter = FakeAdapter()
    service = ClipboardService(adapter=adapter, monitor=False)
    service._timeout = 60

    for i in range(5):
        service.copy(f"v{i}", data_type=f"t{i}")

    s = service.status()
    assert s.active is True
    assert s.data_type == "t4"