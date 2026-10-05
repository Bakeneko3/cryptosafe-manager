"""Tests for src/core/clipboard/platform_adapter.py."""

import sys

import pytest

from src.core.clipboard.platform_adapter import (
    ClipboardAdapter,
    PyperclipAdapter,
    get_default_adapter,
)


@pytest.fixture
def adapter() -> PyperclipAdapter:
    """Use pyperclip adapter in tests: works everywhere."""
    return PyperclipAdapter()


def test_pyperclip_copy_and_read(adapter: PyperclipAdapter) -> None:
    adapter.copy("hello")
    assert adapter.read() == "hello"


def test_pyperclip_clear(adapter: PyperclipAdapter) -> None:
    adapter.copy("secret")
    adapter.clear()
    assert adapter.read() in (None, "")


def test_pyperclip_copy_returns_true(adapter: PyperclipAdapter) -> None:
    assert adapter.copy("x") is True


def test_pyperclip_clear_returns_true(adapter: PyperclipAdapter) -> None:
    assert adapter.clear() is True


def test_pyperclip_unicode(adapter: PyperclipAdapter) -> None:
    adapter.copy("Привет 🎉")
    assert adapter.read() == "Привет 🎉"


def test_factory_returns_an_adapter() -> None:
    a = get_default_adapter()
    assert isinstance(a, ClipboardAdapter)


def test_factory_returns_windows_adapter_on_windows() -> None:
    """On Windows with pywin32 installed, prefer the native adapter."""
    a = get_default_adapter()
    if sys.platform == "win32":
        try:
            import win32clipboard  # noqa: F401
            assert a.name == "windows"
        except ImportError:
            assert a.name == "pyperclip"
    else:
        assert a.name == "pyperclip"


def test_adapter_has_name() -> None:
    assert PyperclipAdapter().name == "pyperclip"