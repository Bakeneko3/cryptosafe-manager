"""
Change-password dialog.

Collects current / new / confirm passwords, calls
KeyManager.change_password(), and reports errors via an inline label.

The actual re-encryption runs synchronously inside KeyManager. This
dialog only blocks its own controls and displays a "changing…" hint.
Background execution with progress indication is a Sprint 3+ concern.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.core.key_manager import KeyManager
from src.gui.widgets.password_entry import PasswordEntry


class ChangePasswordDialog(tk.Toplevel):
    """
    Modal change-password dialog.

    After wait_window, `self.result` is:
        * True  -- password changed successfully
        * False -- user cancelled or the dialog was closed
    """

    def __init__(self, master, key_manager: KeyManager) -> None:
        super().__init__(master)

        self.key_manager = key_manager
        self.result: bool = False

        self.title("CryptoSafe Manager — Change Master Password")
        self.geometry("480x360")
        self.resizable(False, False)

        self._create_widgets()

        self.transient(master)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _e: self._on_cancel())

        self.current_entry.focus_set()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_widgets(self) -> None:
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            container,
            text="Change Master Password",
            font=("TkDefaultFont", 14, "bold"),
        ).pack(anchor=tk.W, pady=(0, 15))

        ttk.Label(container, text="Current password:").pack(anchor=tk.W)
        self.current_entry = PasswordEntry(container)
        self.current_entry.pack(fill=tk.X, pady=(5, 10))

        ttk.Label(container, text="New password:").pack(anchor=tk.W)
        self.new_entry = PasswordEntry(container)
        self.new_entry.pack(fill=tk.X, pady=(5, 5))

        ttk.Label(
            container,
            text=(
                "At least 12 characters, with uppercase, lowercase, "
                "digit and symbol."
            ),
            foreground="gray",
        ).pack(anchor=tk.W, pady=(0, 10))

        ttk.Label(container, text="Confirm new password:").pack(anchor=tk.W)
        self.confirm_entry = PasswordEntry(container)
        self.confirm_entry.pack(fill=tk.X, pady=(5, 10))

        self.status_label = ttk.Label(container, text="", foreground="red")
        self.status_label.pack(anchor=tk.W)

        button_frame = ttk.Frame(container)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(15, 0))

        self.cancel_button = ttk.Button(
            button_frame,
            text="Cancel",
            command=self._on_cancel,
        )
        self.cancel_button.pack(side=tk.RIGHT)

        self.change_button = ttk.Button(
            button_frame,
            text="Change",
            command=self._on_change,
        )
        self.change_button.pack(side=tk.RIGHT, padx=(0, 10))

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_change(self) -> None:
        current = self.current_entry.get()
        new = self.new_entry.get()
        confirm = self.confirm_entry.get()

        if not current or not new or not confirm:
            self.status_label.configure(text="All fields are required.")
            return

        if new != confirm:
            self.status_label.configure(text="New passwords do not match.")
            return

        self._set_busy(True)
        self.status_label.configure(text="Changing password, please wait…")
        self.update_idletasks()

        try:
            self.key_manager.change_password(current, new)
        except ValueError as exc:
            self._set_busy(False)
            self.status_label.configure(text=str(exc))
            return
        except RuntimeError as exc:
            self._set_busy(False)
            self.status_label.configure(text=str(exc))
            return
        except Exception as exc:
            self._set_busy(False)
            messagebox.showerror(
                "Change failed",
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

    def _set_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        self.change_button.configure(state=state)
        self.cancel_button.configure(state=state)