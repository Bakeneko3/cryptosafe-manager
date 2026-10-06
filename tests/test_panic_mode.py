"""Tests for src/core/security/panic_mode.py (PANIC-1..4)."""

import pytest

from src.core.security.panic_mode import (
    PanicConfig,
    PanicError,
    PanicMode,
)


def test_construct_default() -> None:
    p = PanicMode()
    assert p.activated is False
    assert p.activation_method is None


def test_register_handler() -> None:
    p = PanicMode()
    p.register_handler("a", lambda: None)
    assert "a" in p.handler_names()


def test_register_replaces_same_name() -> None:
    p = PanicMode()
    p.register_handler("a", lambda: None)
    p.register_handler("a", lambda: None)
    assert p.handler_names().count("a") == 1


def test_register_non_callable_raises() -> None:
    p = PanicMode()
    with pytest.raises(PanicError):
        p.register_handler("a", "not callable")  # type: ignore[arg-type]


def test_unregister_handler() -> None:
    p = PanicMode()
    p.register_handler("a", lambda: None)
    p.unregister_handler("a")
    assert "a" not in p.handler_names()


def test_activate_runs_handlers_in_order() -> None:
    order = []
    p = PanicMode()
    p.register_handler("first", lambda: order.append("first"))
    p.register_handler("second", lambda: order.append("second"))
    p.register_handler("third", lambda: order.append("third"))

    summary = p.activate(method="hotkey")
    assert order == ["first", "second", "third"]
    assert summary["method"] == "hotkey"
    assert summary["already_activated"] is False


def test_activate_is_idempotent() -> None:
    calls = []
    p = PanicMode()
    p.register_handler("h", lambda: calls.append(1))

    first = p.activate()
    second = p.activate()
    assert first["already_activated"] is False
    assert second["already_activated"] is True
    assert len(calls) == 1


def test_handler_exception_does_not_stop_others() -> None:
    done = []

    def broken():
        raise RuntimeError("boom")

    p = PanicMode()
    p.register_handler("broken", broken)
    p.register_handler("after", lambda: done.append("after"))

    summary = p.activate()
    assert "after" in done
    assert any(f["name"] == "broken" for f in summary["failed"])


def test_log_callback_receives_summary() -> None:
    received = []
    p = PanicMode(PanicConfig(log_callback=received.append))
    p.register_handler("h", lambda: None)
    p.activate(method="tray")
    assert len(received) == 1
    assert received[0]["method"] == "tray"


def test_log_callback_exception_is_swallowed() -> None:
    def boom(summary):
        raise RuntimeError("nope")

    p = PanicMode(PanicConfig(log_callback=boom))
    p.register_handler("h", lambda: None)
    # Should not raise.
    p.activate()


def test_reset_clears_activation() -> None:
    p = PanicMode()
    p.register_handler("h", lambda: None)
    p.activate()
    assert p.activated is True
    p.reset()
    assert p.activated is False


def test_activation_method_recorded() -> None:
    p = PanicMode()
    p.activate(method="hotkey")
    assert p.activation_method == "hotkey"


def test_stealth_mode_records_action() -> None:
    p = PanicMode(PanicConfig(stealth_mode=True, show_fake_error_ui=False))
    p.register_handler("h", lambda: None)
    summary = p.activate()
    assert "fake_error" in summary["stealth_actions"]


def test_empty_panic_with_no_handlers() -> None:
    p = PanicMode()
    summary = p.activate()
    assert summary["executed"] == []
    assert summary["failed"] == []