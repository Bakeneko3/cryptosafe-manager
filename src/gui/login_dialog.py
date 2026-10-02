"""
Login dialog for CryptoSafe Manager.

Shown on application start when the vault has already been initialized.
Collects the master password, calls KeyManager.unlock(), and applies
the exponential backoff returned by the manager on failures (AUTH-3).

This dialog does not touch the database directly; all auth logic lives
in KeyManager.
"""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import messagebox, ttk

from src.core.key_manager import KeyManager
from src.gui.widgets.password_entry import PasswordEntry


class LoginDialog(tk.Toplevel):
    """
    Modal login dialog.

    After mainloop, `self.result` is:
        * True  -- login succeeded, vault is unlocked
        * False -- user cancelled or closed the window
    """

    def __init__(self, master, key_manager: KeyManager) -> None:
        super().__init__(master)

        self.key_manager = key_manager
        self.result: bool = False

        self.title("CryptoSafe Manager — Unlock")
        self.geometry("420x220")
        self.resizable(False, False)

        self._create_widgets()

        self.transient(master)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Return>", lambda _e: self._on_submit())
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
            text="Unlock vault",
            font=("TkDefaultFont", 14, "bold"),
        ).pack(anchor=tk.W, pady=(0, 15))

        ttk.Label(
            container,
            text="Master password:",
        ).pack(anchor=tk.W)

        self.password_entry = PasswordEntry(container)
        self.password_entry.pack(fill=tk.X, pady=(5, 10))

        self.status_label = ttk.Label(
            container,
            text="",
            foreground="red",
        )
        self.status_label.pack(anchor=tk.W)

        button_frame = ttk.Frame(container)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(15, 0))

        self.cancel_button = ttk.Button(
            button_frame,
            text="Cancel",
            command=self._on_cancel,
        )
        self.cancel_button.pack(side=tk.RIGHT)

        self.unlock_button = ttk.Button(
            button_frame,
            text="Unlock",
            command=self._on_submit,
        )
        self.unlock_button.pack(side=tk.RIGHT, padx=(0, 10))

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_submit(self) -> None:
        password = self.password_entry.get()
        if not password:
            self.status_label.configure(text="Password cannot be empty.")
            return

        self._set_busy(True)
        try:
            result = self.key_manager.unlock(password)
        except Exception as exc:
            self._set_busy(False)
            messagebox.showerror(
                "Unlock failed",
                f"Unexpected error: {exc}",
                parent=self,
            )
            return
        finally:
            pass

        if result.success:
            self.result = True
            self.grab_release()
            self.destroy()
            return

        # Failure: apply backoff, show message, clear password field.
        delay = result.backoff_delay
        attempts = self.key_manager.session.failed_attempts
        self.status_label.configure(
            text=f"Incorrect password (attempt {attempts}). "
                 f"Please wait {delay}s before retrying."
        )
        self.password_entry.clear()

        if delay > 0:
            # Blocking sleep: acceptable for Sprint 2. Sprint 7 will
            # replace it with a non-blocking countdown.
            time.sleep(delay)

        self._set_busy(False)
        self.password_entry.focus_set()

    def _on_cancel(self) -> None:
        self.result = False
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()

    def _set_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        self.unlock_button.configure(state=state)
        self.cancel_button.configure(state=state)