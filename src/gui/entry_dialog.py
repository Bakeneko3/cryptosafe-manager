"""
Entry dialog for creating and editing vault records.

Collects plaintext fields, validates them (DIALOG-2), and returns a
dict. Persistence is the caller's responsibility (EntryManager).

The dialog never touches the database or crypto directly.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from urllib.parse import urlparse

from src.core.crypto.authentication import PasswordStrengthValidator
from src.core.vault.password_generator import (
    GeneratorConfig,
    PasswordGenerator,
)
from src.gui.widgets.password_entry import PasswordEntry


def _is_valid_url(value: str) -> bool:
    """Return True if the value looks like a URL or is empty."""
    if not value:
        return True
    if any(ch.isspace() for ch in value):
        return False
    try:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        return bool(parsed.netloc) and "." in parsed.netloc
    except Exception:
        return False


class EntryDialog(tk.Toplevel):
    """
    Modal Add/Edit dialog.

    After wait_window, `self.result` is:
        * dict -- with the entered data, if the user pressed Save
        * None -- if the user cancelled or closed the dialog

    If `entry` is provided, the dialog is in Edit mode and its fields
    are pre-filled.
    """

    def __init__(self, master, entry: dict | None = None) -> None:
        super().__init__(master)

        self.result: dict | None = None
        self._entry = entry or {}
        self._editing = entry is not None

        self.title(
            "CryptoSafe Manager — "
            + ("Edit Entry" if self._editing else "New Entry")
        )
        self.geometry("520x620")
        self.resizable(False, False)

        self._validator = PasswordStrengthValidator()
        self._generator = PasswordGenerator(GeneratorConfig(length=16))

        self._create_widgets()
        self._populate()

        self.transient(master)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _e: self._on_cancel())

        self.title_entry.focus_set()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_widgets(self) -> None:
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        # Title *
        ttk.Label(container, text="Title *").pack(anchor=tk.W)
        self.title_entry = ttk.Entry(container)
        self.title_entry.pack(fill=tk.X, pady=(4, 12))

        # Username
        ttk.Label(container, text="Username").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(container)
        self.username_entry.pack(fill=tk.X, pady=(4, 12))

        # Password * with Generate button
        ttk.Label(container, text="Password *").pack(anchor=tk.W)

        pw_row = ttk.Frame(container)
        pw_row.pack(fill=tk.X, pady=(4, 4))

        self.password_entry = PasswordEntry(pw_row)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(
            pw_row,
            text="Generate",
            width=10,
            command=self._on_generate,
        ).pack(side=tk.RIGHT, padx=(5, 0))

        self.strength_label = ttk.Label(container, text="", foreground="gray")
        self.strength_label.pack(anchor=tk.W, pady=(0, 12))

        self.password_entry.entry.bind(
            "<KeyRelease>", self._update_strength
        )

        # URL
        ttk.Label(container, text="URL").pack(anchor=tk.W)
        self.url_entry = ttk.Entry(container)
        self.url_entry.pack(fill=tk.X, pady=(4, 12))

        # Category
        ttk.Label(container, text="Category").pack(anchor=tk.W)
        self.category_entry = ttk.Entry(container)
        self.category_entry.pack(fill=tk.X, pady=(4, 12))

        # Tags
        ttk.Label(container, text="Tags (comma-separated)").pack(anchor=tk.W)
        self.tags_entry = ttk.Entry(container)
        self.tags_entry.pack(fill=tk.X, pady=(4, 12))

        # Notes
        ttk.Label(container, text="Notes").pack(anchor=tk.W)
        self.notes_text = tk.Text(container, height=4, wrap="word")
        self.notes_text.pack(fill=tk.BOTH, expand=True, pady=(4, 12))

        # Status
        self.status_label = ttk.Label(container, text="", foreground="red")
        self.status_label.pack(anchor=tk.W)

        # Buttons
        button_frame = ttk.Frame(container)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(15, 0))

        ttk.Button(
            button_frame,
            text="Cancel",
            command=self._on_cancel,
        ).pack(side=tk.RIGHT)

        ttk.Button(
            button_frame,
            text="Save",
            command=self._on_save,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    # ------------------------------------------------------------------ #
    # Populate (Edit mode)
    # ------------------------------------------------------------------ #

    def _populate(self) -> None:
        if not self._editing:
            return

        self.title_entry.insert(0, str(self._entry.get("title", "")))
        self.username_entry.insert(0, str(self._entry.get("username", "")))
        self.password_entry.set(str(self._entry.get("password", "")))
        self.url_entry.insert(0, str(self._entry.get("url", "")))
        self.category_entry.insert(0, str(self._entry.get("category", "")))
        self.tags_entry.insert(0, str(self._entry.get("tags", "")))
        self.notes_text.insert("1.0", str(self._entry.get("notes", "")))

        self._update_strength()

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_generate(self) -> None:
        from src.gui.password_generator_dialog import PasswordGeneratorDialog

        dlg = PasswordGeneratorDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            self.password_entry.set(dlg.result)
            self._update_strength()

    def _update_strength(self, event=None) -> None:
        pw = self.password_entry.get()
        if not pw:
            self.strength_label.configure(text="")
            return

        result = self._validator.validate(pw)
        if result.valid:
            self.strength_label.configure(
                text="Strength: OK", foreground="green"
            )
        else:
            reason = result.reasons[0] if result.reasons else "too weak"
            self.strength_label.configure(
                text=f"Strength: {reason}", foreground="orange"
            )

    def _on_save(self) -> None:
        title = self.title_entry.get().strip()
        password = self.password_entry.get()
        url = self.url_entry.get().strip()

        if not title:
            self.status_label.configure(text="Title is required.")
            return
        if not password:
            self.status_label.configure(text="Password is required.")
            return
        if not _is_valid_url(url):
            self.status_label.configure(text="URL is not valid.")
            return

        self.result = {
            "title": title,
            "username": self.username_entry.get().strip(),
            "password": password,
            "url": url,
            "category": self.category_entry.get().strip(),
            "tags": self.tags_entry.get().strip(),
            "notes": self.notes_text.get("1.0", tk.END).strip(),
        }

        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()