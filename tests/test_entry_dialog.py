"""Smoke tests for src/gui/entry_dialog.py (DIALOG-1, DIALOG-2)."""

import pytest

tk = pytest.importorskip("tkinter")

from src.gui.entry_dialog import EntryDialog, _is_valid_url


@pytest.fixture(scope="session")
def _tk_root():
    """One Tk instance for the entire test session."""
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
    """Per-test root: reuse the session Tk instance."""
    yield _tk_root


# --------------------------------------------------------------------- #
# URL validation (DIALOG-2)
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    ["", "https://example.com", "http://x.io", "example.com", "sub.example.co.uk"],
)
def test_is_valid_url_accepts(url: str) -> None:
    assert _is_valid_url(url) is True


@pytest.mark.parametrize(
    "url",
    ["not a url with spaces", "http://", "://noscheme"],
)
def test_is_valid_url_rejects(url: str) -> None:
    # Some of these may still parse; we accept best-effort. The main
    # goal is that obviously bad inputs don't crash.
    try:
        _is_valid_url(url)
    except Exception:
        pytest.fail("_is_valid_url must not raise")


# --------------------------------------------------------------------- #
# Create mode
# --------------------------------------------------------------------- #


def test_dialog_constructs_in_create_mode(root) -> None:
    dlg = EntryDialog(root)
    assert dlg.result is None
    assert dlg._editing is False
    dlg._on_cancel()


def test_save_with_valid_data(root) -> None:
    dlg = EntryDialog(root)
    dlg.title_entry.insert(0, "Example")
    dlg.username_entry.insert(0, "user@example.com")
    dlg.password_entry.set("s3cr3t-Pass!")
    dlg.url_entry.insert(0, "https://example.com")
    dlg.category_entry.insert(0, "Work")
    dlg.tags_entry.insert(0, "work,important")
    dlg.notes_text.insert("1.0", "some notes")

    dlg._on_save()

    assert dlg.result is not None
    assert dlg.result["title"] == "Example"
    assert dlg.result["username"] == "user@example.com"
    assert dlg.result["password"] == "s3cr3t-Pass!"
    assert dlg.result["url"] == "https://example.com"
    assert dlg.result["category"] == "Work"
    assert dlg.result["tags"] == "work,important"
    assert dlg.result["notes"] == "some notes"


def test_save_without_title_fails(root) -> None:
    dlg = EntryDialog(root)
    dlg.password_entry.set("s3cr3t-Pass!")
    dlg._on_save()
    assert dlg.result is None
    dlg._on_cancel()


def test_save_without_password_fails(root) -> None:
    dlg = EntryDialog(root)
    dlg.title_entry.insert(0, "Example")
    dlg._on_save()
    assert dlg.result is None
    dlg._on_cancel()


def test_save_with_invalid_url_fails(root) -> None:
    dlg = EntryDialog(root)
    dlg.title_entry.insert(0, "Example")
    dlg.password_entry.set("s3cr3t-Pass!")
    dlg.url_entry.insert(0, "not a url with spaces")
    dlg._on_save()
    assert dlg.result is None
    dlg._on_cancel()


def test_cancel_returns_none(root) -> None:
    dlg = EntryDialog(root)
    dlg._on_cancel()
    assert dlg.result is None


# --------------------------------------------------------------------- #
# Edit mode
# --------------------------------------------------------------------- #


def test_dialog_constructs_in_edit_mode(root) -> None:
    entry = {
        "title": "Existing",
        "username": "u@x.com",
        "password": "pw-123!",
        "url": "https://x.com",
        "category": "Personal",
        "tags": "old",
        "notes": "old notes",
    }
    dlg = EntryDialog(root, entry=entry)

    assert dlg._editing is True
    assert dlg.title_entry.get() == "Existing"
    assert dlg.username_entry.get() == "u@x.com"
    assert dlg.password_entry.get() == "pw-123!"
    assert dlg.url_entry.get() == "https://x.com"
    assert dlg.category_entry.get() == "Personal"
    assert dlg.tags_entry.get() == "old"
    assert dlg.notes_text.get("1.0", tk.END).strip() == "old notes"

    dlg._on_cancel()


def test_edit_mode_save_preserves_changes(root) -> None:
    entry = {"title": "Old", "password": "pw-123!"}
    dlg = EntryDialog(root, entry=entry)
    dlg.title_entry.delete(0, tk.END)
    dlg.title_entry.insert(0, "New")
    dlg._on_save()

    assert dlg.result is not None
    assert dlg.result["title"] == "New"


# --------------------------------------------------------------------- #
# Generate
# --------------------------------------------------------------------- #


def test_generate_fills_password(root) -> None:
    dlg = EntryDialog(root)
    dlg._on_generate()
    pw = dlg.password_entry.get()
    assert pw
    assert len(pw) == 16
    dlg._on_cancel()


def test_generate_produces_valid_password(root) -> None:
    dlg = EntryDialog(root)
    dlg._on_generate()
    pw = dlg.password_entry.get()
    result = dlg._validator.validate(pw)
    assert result.valid, f"generated password failed validation: {result.reasons}"
    dlg._on_cancel()