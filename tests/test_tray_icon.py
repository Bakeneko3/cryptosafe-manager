"""Tests for src/core/security/tray_icon.py (TRAY-1..3)."""

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture(scope="session")
def _tk_root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display available: {exc}")
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def root(_tk_root):
    yield _tk_root


def _noop():
    pass


def test_tray_constructs(root) -> None:
    from src.core.security.tray_icon import TrayIcon

    t = TrayIcon(
        root,
        on_show=_noop,
        on_lock_toggle=_noop,
        on_clear_clipboard=_noop,
        on_panic=_noop,
        on_settings=_noop,
        on_exit=_noop,
    )
    assert t is not None
    assert t.running is False


def test_tray_availability_flag(root) -> None:
    from src.core.security.tray_icon import TrayIcon

    t = TrayIcon(
        root,
        on_show=_noop,
        on_lock_toggle=_noop,
        on_clear_clipboard=_noop,
        on_panic=_noop,
        on_settings=_noop,
        on_exit=_noop,
    )
    assert isinstance(t.available, bool)


def test_tray_locked_state_toggle(root) -> None:
    from src.core.security.tray_icon import TrayIcon

    t = TrayIcon(
        root,
        on_show=_noop,
        on_lock_toggle=_noop,
        on_clear_clipboard=_noop,
        on_panic=_noop,
        on_settings=_noop,
        on_exit=_noop,
    )
    t.set_locked(True)
    assert t._locked is True
    t.set_locked(False)
    assert t._locked is False


def test_tray_notify_without_icon_is_safe(root) -> None:
    from src.core.security.tray_icon import TrayIcon

    t = TrayIcon(
        root,
        on_show=_noop,
        on_lock_toggle=_noop,
        on_clear_clipboard=_noop,
        on_panic=_noop,
        on_settings=_noop,
        on_exit=_noop,
    )
    t.notify("hello")  # must not raise


def test_tray_start_and_stop_if_available(root) -> None:
    from src.core.security.tray_icon import TrayIcon

    t = TrayIcon(
        root,
        on_show=_noop,
        on_lock_toggle=_noop,
        on_clear_clipboard=_noop,
        on_panic=_noop,
        on_settings=_noop,
        on_exit=_noop,
    )
    if not t.available:
        pytest.skip("pystray not available")
    t.start()
    # Starting in a headless/CI environment may not actually create
    # a tray icon, but the call must not raise.
    t.stop()