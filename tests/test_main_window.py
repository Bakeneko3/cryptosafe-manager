"""Smoke tests for src/gui/main_window.py (Sprint 3 integration)."""

from pathlib import Path

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


def test_main_window_constructs(_tk_root, tmp_path, monkeypatch) -> None:
    """
    Constructing MainWindow must not raise. We override DATABASE_PATH to
    a temp file to avoid touching the real vault.
    """
    import src.gui.main_window as mw_module

    db_path = tmp_path / "smoke.db"
    monkeypatch.setattr(mw_module, "DATABASE_PATH", db_path)

    app = mw_module.MainWindow()
    try:
        # Don't run auth gate; just check construction.
        assert app.entry_manager is not None
        assert app.key_manager is not None
    finally:
        try:
            app.database.close()
        except Exception:
            pass
        try:
            app.destroy()
        except Exception:
            pass