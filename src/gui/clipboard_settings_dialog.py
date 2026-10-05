"""
Clipboard settings dialog.

Exposes clipboard timeout, notification preferences, security level,
and preset profiles. Persists through ClipboardSettings helpers.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.core import config
from src.core.clipboard.clipboard_settings import (
    ClipboardSettings,
    apply_preset,
    load_clipboard_settings,
    save_clipboard_settings,
)
from src.core.settings_manager import SettingsManager


class ClipboardSettingsDialog(tk.Toplevel):
    """
    Modal clipboard settings dialog.

    After wait_window, `self.result` is:
        * ClipboardSettings -- if the user pressed Save
        * None              -- if the user cancelled
    """

    def __init__(self, master, settings_manager: SettingsManager) -> None:
        super().__init__(master)

        self.settings_manager = settings_manager
        self.result: ClipboardSettings | None = None

        self._original = load_clipboard_settings(settings_manager)

        self.title("CryptoSafe Manager — Clipboard Settings")
        self.geometry("460x420")
        self.resizable(False, False)

        self._create_widgets()
        self._load_into_widgets()

        self.transient(master)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _e: self._on_cancel())

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_widgets(self) -> None:
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        # Preset (CFG-3)
        ttk.Label(container, text="Preset:").pack(anchor=tk.W)
        self.preset_var = tk.StringVar(value=self._original.preset)
        preset_combo = ttk.Combobox(
            container,
            textvariable=self.preset_var,
            values=tuple(config.CLIPBOARD_PRESETS.keys()),
            state="readonly",
        )
        preset_combo.pack(fill=tk.X, pady=(4, 12))
        preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # Timeout
        ttk.Label(container, text="Auto-clear timeout (seconds):").pack(anchor=tk.W)

        timeout_row = ttk.Frame(container)
        timeout_row.pack(fill=tk.X, pady=(4, 4))

        self.timeout_var = tk.IntVar(value=self._original.timeout)
        self.timeout_spin = ttk.Spinbox(
            timeout_row,
            from_=config.CLIPBOARD_TIMEOUT_MIN,
            to=config.CLIPBOARD_TIMEOUT_MAX,
            textvariable=self.timeout_var,
            width=8,
        )
        self.timeout_spin.pack(side=tk.LEFT)

        self.never_var = tk.BooleanVar(
            value=self._original.timeout == config.CLIPBOARD_TIMEOUT_NEVER
        )
        ttk.Checkbutton(
            timeout_row,
            text="Never auto-clear (not recommended)",
            variable=self.never_var,
            command=self._on_never_toggled,
        ).pack(side=tk.LEFT, padx=(10, 0))

        ttk.Label(
            container,
            text=(
                f"Range: {config.CLIPBOARD_TIMEOUT_MIN}–"
                f"{config.CLIPBOARD_TIMEOUT_MAX} seconds."
            ),
            foreground="gray",
        ).pack(anchor=tk.W, pady=(0, 12))

        # Notifications
        self.notifications_var = tk.BooleanVar(value=self._original.notifications)
        ttk.Checkbutton(
            container,
            text="Show notifications on copy / clear",
            variable=self.notifications_var,
        ).pack(anchor=tk.W, pady=(0, 12))

        # Security level
        ttk.Label(container, text="Security level:").pack(anchor=tk.W)
        self.security_var = tk.StringVar(value=self._original.security_level)
        ttk.Combobox(
            container,
            textvariable=self.security_var,
            values=config.CLIPBOARD_SECURITY_LEVELS,
            state="readonly",
        ).pack(fill=tk.X, pady=(4, 12))

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
    # Load / sync
    # ------------------------------------------------------------------ #

    def _load_into_widgets(self) -> None:
        self.preset_var.set(self._original.preset)
        self.timeout_var.set(self._original.timeout)
        self.notifications_var.set(self._original.notifications)
        self.security_var.set(self._original.security_level)
        self._update_timeout_state()

    def _update_timeout_state(self) -> None:
        if self.never_var.get():
            self.timeout_spin.configure(state=tk.DISABLED)
        else:
            self.timeout_spin.configure(state=tk.NORMAL)

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_preset_selected(self, _event=None) -> None:
        name = self.preset_var.get()
        try:
            applied = apply_preset(ClipboardSettings(), name)
        except ValueError as exc:
            self.status_label.configure(text=str(exc))
            return
        self.timeout_var.set(applied.timeout)
        self.notifications_var.set(applied.notifications)
        self.security_var.set(applied.security_level)
        self.never_var.set(applied.timeout == config.CLIPBOARD_TIMEOUT_NEVER)
        self._update_timeout_state()

    def _on_never_toggled(self) -> None:
        self._update_timeout_state()

    def _on_save(self) -> None:
        if self.never_var.get():
            timeout = config.CLIPBOARD_TIMEOUT_NEVER
        else:
            try:
                timeout = int(self.timeout_var.get())
            except (tk.TclError, ValueError):
                self.status_label.configure(
                    text="Timeout must be a number."
                )
                return

        candidate = ClipboardSettings(
            timeout=timeout,
            notifications=bool(self.notifications_var.get()),
            security_level=self.security_var.get(),
            preset=self.preset_var.get(),
        )

        try:
            candidate.validate()
        except ValueError as exc:
            self.status_label.configure(text=str(exc))
            return

        try:
            save_clipboard_settings(self.settings_manager, candidate)
        except Exception as exc:
            messagebox.showerror(
                "Failed to save settings",
                f"Unexpected error: {exc}",
                parent=self,
            )
            return

        self.result = candidate
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()