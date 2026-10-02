"""Tests for src/gui/widgets/ (PasswordEntry, SecureTable, AuditLogViewer)."""

import pytest

tk = pytest.importorskip("tkinter")

from src.gui.widgets.password_entry import PasswordEntry
from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    r.destroy()


# --------------------------------------------------------------------- #
# PasswordEntry
# --------------------------------------------------------------------- #


def test_password_entry_default_masked(root) -> None:
    entry = PasswordEntry(root)
    assert entry.entry.cget("show") == "*"


def test_password_entry_get_set_clear(root) -> None:
    entry = PasswordEntry(root)
    entry.set("secret")
    assert entry.get() == "secret"
    entry.clear()
    assert entry.get() == ""


def test_password_entry_toggle_visibility(root) -> None:
    entry = PasswordEntry(root)
    assert entry.entry.cget("show") == "*"
    entry._toggle_visibility()
    assert entry.entry.cget("show") == ""
    entry._toggle_visibility()
    assert entry.entry.cget("show") == "*"


def test_password_entry_paste_inserts_clipboard_content(root) -> None:
    entry = PasswordEntry(root)
    root.clipboard_clear()
    root.clipboard_append("pasted-secret")

    result = entry._on_paste(None)
    assert result == "break"
    assert entry.get() == "pasted-secret"


def test_password_entry_paste_appends_when_no_selection(root) -> None:
    entry = PasswordEntry(root)
    entry.set("prefix-")
    entry.entry.icursor(tk.END)
    root.clipboard_clear()
    root.clipboard_append("suffix")

    entry._on_paste(None)
    assert entry.get() == "prefix-suffix"


def test_password_entry_paste_with_empty_clipboard_is_safe(root) -> None:
    entry = PasswordEntry(root)
    try:
        root.clipboard_clear()
    except tk.TclError:
        pass
    result = entry._on_paste(None)
    assert result == "break"


def test_password_entry_paste_preserves_masking(root) -> None:
    entry = PasswordEntry(root)
    root.clipboard_clear()
    root.clipboard_append("secret")
    entry._on_paste(None)
    assert entry.entry.cget("show") == "*"


def test_password_entry_paste_preserves_visibility_when_shown(root) -> None:
    entry = PasswordEntry(root)
    entry._toggle_visibility()
    root.clipboard_clear()
    root.clipboard_append("secret")
    entry._on_paste(None)
    assert entry.entry.cget("show") == ""


# --------------------------------------------------------------------- #
# SecureTable
# --------------------------------------------------------------------- #


def test_secure_table_starts_empty(root) -> None:
    table = SecureTable(root, columns=("a", "b"))
    assert table.tree.get_children() == ()


def test_secure_table_add_row(root) -> None:
    table = SecureTable(root, columns=("title", "username"))
    table.add_row(("Example", "user@example.com"))
    children = table.tree.get_children()
    assert len(children) == 1
    assert table.tree.item(children[0])["values"] == ["Example", "user@example.com"]


def test_secure_table_clear(root) -> None:
    table = SecureTable(root, columns=("a",))
    table.add_row(("x",))
    table.add_row(("y",))
    assert len(table.tree.get_children()) == 2
    table.clear()
    assert table.tree.get_children() == ()


def test_secure_table_selected_returns_none_when_empty(root) -> None:
    table = SecureTable(root, columns=("a",))
    assert table.selected() is None


# --------------------------------------------------------------------- #
# AuditLogViewer
# --------------------------------------------------------------------- #


def test_audit_log_viewer_constructs(root) -> None:
    viewer = AuditLogViewer(root)
    assert viewer is not None
    viewer.refresh()