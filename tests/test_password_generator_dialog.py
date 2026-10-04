"""Smoke tests for src/gui/password_generator_dialog.py."""

import pytest

tk = pytest.importorskip("tkinter")

from src.core.vault.password_generator import (
    MIN_LENGTH,
    GeneratorConfig,
)
from src.gui.password_generator_dialog import PasswordGeneratorDialog


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


def test_dialog_constructs(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    assert dlg.result is None
    assert dlg.preview_var.get() != ""
    dlg._on_cancel()


def test_default_length_is_16(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    assert len(dlg.preview_var.get()) == 16
    dlg._on_cancel()


def test_regenerate_changes_password(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    first = dlg.preview_var.get()
    dlg._regenerate()
    # Almost certainly different; if not, try once more.
    if dlg.preview_var.get() == first:
        dlg._regenerate()
    assert dlg.preview_var.get() != first
    dlg._on_cancel()


def test_use_returns_password(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    pw = dlg.preview_var.get()
    dlg._on_use()
    assert dlg.result == pw


def test_cancel_returns_none(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    dlg._on_cancel()
    assert dlg.result is None


def test_disabling_all_sets_shows_error(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    dlg.uppercase_var.set(False)
    dlg.lowercase_var.set(False)
    dlg.digits_var.set(False)
    dlg.symbols_var.set(False)
    dlg._regenerate()
    assert dlg.preview_var.get() == ""
    dlg._on_cancel()


def test_use_without_preview_fails(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    dlg.uppercase_var.set(False)
    dlg.lowercase_var.set(False)
    dlg.digits_var.set(False)
    dlg.symbols_var.set(False)
    dlg._regenerate()
    dlg._on_use()
    assert dlg.result is None
    dlg._on_cancel()


def test_initial_config_used(root) -> None:
    cfg = GeneratorConfig(length=32)
    dlg = PasswordGeneratorDialog(root, initial_config=cfg)
    assert len(dlg.preview_var.get()) == 32
    dlg._on_cancel()


def test_min_length_respected(root) -> None:
    dlg = PasswordGeneratorDialog(root)
    dlg.length_scale.set(MIN_LENGTH)
    dlg._regenerate()
    assert len(dlg.preview_var.get()) == MIN_LENGTH
    dlg._on_cancel()