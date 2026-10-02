"""
First-run setup wizard.

Collects the master password (with confirmation) and the database
location, then initializes a new vault via KeyManager.create_vault().

After this wizard completes successfully, the vault is unlocked and
the application may proceed to the main window.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from src.core.key_manager import KeyManager
from src.gui.widgets.password_entry import PasswordEntry


class SetupWizard(tk.Toplevel):
    """
    Modal first-run wizard.

    After mainloop, `self.result` is:
        * True  -- vault created and unlocked
        * False -- user cancelled or closed the window
    """

    def __init__(self, master, key_manager: KeyManager) -> None:
        super().__init__(master)

        self.key_manager = key_manager
        self.result: bool = False

        self.title("CryptoSafe Manager — First Run Setup")
        self.geometry("520x460")
        self.resizable(False, False)

        self._create_widgets()

        self.transient(master)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _e: self._on_cancel())

        self.password_entry.focus_set()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_widgets(self) -> None:
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            container,
            text="First Run Setup",
            font=("TkDefaultFont", 16, "bold"),
        ).pack(anchor=tk.W, pady=(0, 20))

        ttk.Label(
            container,
            text="Master password:",
        ).pack(anchor=tk.W)

        self.password_entry = PasswordEntry(container)
        self.password_entry.pack(fill=tk.X, pady=(5, 5))

        ttk.Label(
            container,
            text=(
                "At least 12 characters, with uppercase, lowercase, "
                "digit and symbol."
            ),
            foreground="gray",
        ).pack(anchor=tk.W, pady=(0, 15))

        ttk.Label(
            container,
            text="Confirm master password:",
        ).pack(anchor=tk.W)

        self.confirm_entry = PasswordEntry(container)
        self.confirm_entry.pack(fill=tk.X, pady=(5, 15))

        ttk.Label(
            container,
            text="Database location:",
        ).pack(anchor=tk.W)

        db_frame = ttk.Frame(container)
        db_frame.pack(fill=tk.X, pady=(5, 15))

        self.db_path_var = tk.StringVar(
            value=str(Path.home() / "cryptosafe.db")
        )

        ttk.Entry(
            db_frame,
            textvariable=self.db_path_var,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(
            db_frame,
            text="Browse",
            command=self._browse_database,
        ).pack(side=tk.RIGHT, padx=(5, 0))

        self.encryption_var = tk.StringVar(
            value="AES-256-GCM (placeholder)"
        )

        ttk.Label(
            container,
            text="Encryption:",
        ).pack(anchor=tk.W)

        ttk.Combobox(
            container,
            textvariable=self.encryption_var,
            values=("AES-256-GCM (placeholder)",),
            state="readonly",
        ).pack(fill=tk.X, pady=(5, 20))

        self.status_label = ttk.Label(
            container,
            text="",
            foreground="red",
        )
        self.status_label.pack(anchor=tk.W)

        button_frame = ttk.Frame(container)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

        ttk.Button(
            button_frame,
            text="Cancel",
            command=self._on_cancel,
        ).pack(side=tk.RIGHT)

        self.create_button = ttk.Button(
            button_frame,
            text="Create Vault",
            command=self._on_create,
        )
        self.create_button.pack(side=tk.RIGHT, padx=(0, 10))

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _browse_database(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Select database location",
            defaultextension=".db",
            filetypes=(
                ("SQLite database", "*.db"),
                ("All files", "*.*"),
            ),
        )
        if path:
            self.db_path_var.set(path)

    def _on_create(self) -> None:
        password = self.password_entry.get()
        confirmation = self.confirm_entry.get()

        if not password:
            self.status_label.configure(text="Password cannot be empty.")
            return

        if password != confirmation:
            self.status_label.configure(text="Passwords do not match.")
            return

        try:
            self.key_manager.create_vault(password)
        except ValueError as exc:
            self.status_label.configure(text=str(exc))
            return
        except Exception as exc:
            messagebox.showerror(
                "Setup failed",
                f"Unexpected error: {exc}",
                parent=self,
            )
            return

        self.result = True
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = False
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()