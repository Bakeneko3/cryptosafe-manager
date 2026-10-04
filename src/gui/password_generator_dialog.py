"""
Password generator configuration dialog.

Lets the user adjust length, character sets, and ambiguous-character
exclusion, then returns a generated password. The dialog is used from
EntryDialog's "Generate" button.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from src.core.vault.password_generator import (
    MAX_LENGTH,
    MIN_LENGTH,
    GeneratorConfig,
    PasswordGenerator,
)


class PasswordGeneratorDialog(tk.Toplevel):
    """
    Modal generator dialog.

    After wait_window, `self.result` is:
        * str -- the generated password, if the user pressed "Use"
        * None -- if the user cancelled
    """

    def __init__(
        self,
        master,
        initial_config: GeneratorConfig | None = None,
    ) -> None:
        super().__init__(master)

        self.result: str | None = None
        self._config = initial_config or GeneratorConfig(length=16)

        self.title("CryptoSafe Manager — Generate Password")
        self.geometry("440x360")
        self.resizable(False, False)

        self._create_widgets()
        self._sync_widgets_from_config()

        self.transient(master)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _e: self._on_cancel())

        self._regenerate()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_widgets(self) -> None:
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        # Length
        length_row = ttk.Frame(container)
        length_row.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(length_row, text="Length:").pack(side=tk.LEFT)

        self.length_var = tk.IntVar(value=self._config.length)
        self.length_scale = ttk.Scale(
            length_row,
            from_=MIN_LENGTH,
            to=MAX_LENGTH,
            orient=tk.HORIZONTAL,
            command=self._on_length_changed,
        )
        self.length_scale.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))

        self.length_label = ttk.Label(length_row, text=str(self._config.length), width=3)
        self.length_label.pack(side=tk.RIGHT)

        # Character sets
        self.uppercase_var = tk.BooleanVar(value=self._config.uppercase)
        self.lowercase_var = tk.BooleanVar(value=self._config.lowercase)
        self.digits_var = tk.BooleanVar(value=self._config.digits)
        self.symbols_var = tk.BooleanVar(value=self._config.symbols)
        self.exclude_ambiguous_var = tk.BooleanVar(value=self._config.exclude_ambiguous)

        ttk.Checkbutton(
            container,
            text="Uppercase (A-Z)",
            variable=self.uppercase_var,
            command=self._regenerate,
        ).pack(anchor=tk.W)
        ttk.Checkbutton(
            container,
            text="Lowercase (a-z)",
            variable=self.lowercase_var,
            command=self._regenerate,
        ).pack(anchor=tk.W)
        ttk.Checkbutton(
            container,
            text="Digits (0-9)",
            variable=self.digits_var,
            command=self._regenerate,
        ).pack(anchor=tk.W)
        ttk.Checkbutton(
            container,
            text="Symbols (!@#$%^&*)",
            variable=self.symbols_var,
            command=self._regenerate,
        ).pack(anchor=tk.W)
        ttk.Checkbutton(
            container,
            text="Exclude ambiguous (l I 1 0 O)",
            variable=self.exclude_ambiguous_var,
            command=self._regenerate,
        ).pack(anchor=tk.W, pady=(5, 12))

        # Preview
        ttk.Label(container, text="Preview:").pack(anchor=tk.W)

        preview_row = ttk.Frame(container)
        preview_row.pack(fill=tk.X, pady=(4, 12))

        self.preview_var = tk.StringVar()
        preview_entry = ttk.Entry(
            preview_row,
            textvariable=self.preview_var,
            state="readonly",
        )
        preview_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(
            preview_row,
            text="Regenerate",
            command=self._regenerate,
        ).pack(side=tk.RIGHT, padx=(5, 0))

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
            text="Use",
            command=self._on_use,
        ).pack(side=tk.RIGHT, padx=(0, 10))

    # ------------------------------------------------------------------ #
    # Sync
    # ------------------------------------------------------------------ #

    def _sync_widgets_from_config(self) -> None:
        self.length_scale.set(self._config.length)
        self.length_label.configure(text=str(self._config.length))

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_length_changed(self, value) -> None:
        length = int(float(value))
        self.length_label.configure(text=str(length))
        self._regenerate()

    def _current_config(self) -> GeneratorConfig:
        return GeneratorConfig(
            length=int(float(self.length_scale.get())),
            uppercase=self.uppercase_var.get(),
            lowercase=self.lowercase_var.get(),
            digits=self.digits_var.get(),
            symbols=self.symbols_var.get(),
            exclude_ambiguous=self.exclude_ambiguous_var.get(),
        )

    def _regenerate(self) -> None:
        try:
            cfg = self._current_config()
            cfg.validate()
        except ValueError as exc:
            self.status_label.configure(text=str(exc))
            self.preview_var.set("")
            return

        self.status_label.configure(text="")
        gen = PasswordGenerator(cfg)
        self.preview_var.set(gen.generate())

    def _on_use(self) -> None:
        pw = self.preview_var.get()
        if not pw:
            self.status_label.configure(text="Generate a password first.")
            return
        self.result = pw
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()