import tkinter as tk

import pytest

from src.gui.widgets.password_entry import PasswordEntry
from src.gui.widgets.secure_table import SecureTable


@pytest.fixture(scope="module")
def root():
    root = tk.Tk()
    root.withdraw()

    yield root

    root.destroy()


def test_password_entry(root):
    widget = PasswordEntry(root)

    widget.set("secret")

    assert widget.get() == "secret"

    widget.clear()

    assert widget.get() == ""


def test_secure_table(root):
    table = SecureTable(
        root,
        columns=("title", "username"),
    )

    table.add_row(("Example", "user"))

    assert len(table.tree.get_children()) == 1

    table.clear()

    assert len(table.tree.get_children()) == 0