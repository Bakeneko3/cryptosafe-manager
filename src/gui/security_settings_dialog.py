"""
Security profile selection dialog.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.core.security.security_profiles import (
    DEFAULT_PROFILE,
    PROFILES,
    ProfileError,
    diff_profiles,
    explain_profile,
    load_profile,
    set_profile,
)
from src.core.settings_manager import SettingsManager


class SecuritySettingsDialog(tk.Toplevel):
    """
    Modal dialog for choosing a security profile.

    `self.result` is the selected profile name if applied, else None.
    """

    def __init__(self, master, settings_manager: SettingsManager) -> None:
        super().__init__(master)

        self._manager = settings_manager
        self.result: str | None = None

        self.title("CryptoSafe Manager — Security Profiles")
        self.geometry("620x520")
        self.resizable(False, False)

        self._current = load_profile(self._manager)

        self._create_widgets()
        self._select(self._current.name)

        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _e: self._on_cancel())

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_widgets(self) -> None:
        c = ttk.Frame(self, padding=16)
        c.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            c,
            text="Security Profile",
            font=("TkDefaultFont", 14, "bold"),
        ).pack(anchor=tk.W, pady=(0, 6))

        ttk.Label(
            c,
            text=(
                "Choose a predefined profile. The exact settings are "
                "shown below before applying."
            ),
            foreground="gray",
            wraplength=580,
        ).pack(anchor=tk.W, pady=(0, 10))

        # Profile radio buttons
        self.profile_var = tk.StringVar(value=self._current.name)
        for name in ("Standard", "Enhanced", "Paranoid"):
            rb = ttk.Radiobutton(
                c,
                text=f"{name} — {PROFILES[name].description}",
                variable=self.profile_var,
                value=name,
                command=self._on_profile_changed,
            )
            rb.pack(anchor=tk.W, pady=(4, 4))

        ttk.Separator(c, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(10, 6))

        ttk.Label(c, text="Changes to apply:").pack(anchor=tk.W)

        self.diff_text = tk.Text(c, height=10, wrap="word", state=tk.DISABLED)
        self.diff_text.pack(fill=tk.BOTH, expand=True, pady=(4, 10))

        self.status_label = ttk.Label(c, text="", foreground="red", wraplength=580)
        self.status_label.pack(anchor=tk.W)

        btns = ttk.Frame(c)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

        ttk.Button(btns, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)
        self.apply_btn = ttk.Button(btns, text="Apply", command=self._on_apply)
        self.apply_btn.pack(side=tk.RIGHT, padx=(0, 8))

    # ------------------------------------------------------------------ #
    # Logic
    # ------------------------------------------------------------------ #

    def _select(self, name: str) -> None:
        self.profile_var.set(name)
        self._on_profile_changed()

    def _on_profile_changed(self) -> None:
        target_name = self.profile_var.get()
        target = PROFILES[target_name]
        diff = diff_profiles(self._current, target)

        self.diff_text.configure(state=tk.NORMAL)
        self.diff_text.delete("1.0", tk.END)

        if not diff:
            self.diff_text.insert(
                "1.0",
                f"No changes — you are already on the '{target_name}' profile.",
            )
        else:
            lines = [
                f"{field}: {old}  →  {new}"
                for field, old, new in diff
            ]
            self.diff_text.insert("1.0", "\n".join(lines))

        self.diff_text.configure(state=tk.DISABLED)
        self.status_label.configure(text="")

    def _on_apply(self) -> None:
        target_name = self.profile_var.get()
        target = PROFILES[target_name]
        diff = diff_profiles(self._current, target)

        if not diff:
            self.status_label.configure(
                text=f"Already using '{target_name}'."
            )
            return

        if not messagebox.askyesno(
            "Apply profile",
            f"Apply the '{target_name}' profile? "
            f"{len(diff)} setting(s) will change.",
            parent=self,
        ):
            return

        try:
            set_profile(self._manager, target_name)
        except ProfileError as exc:
            self.status_label.configure(text=str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Failed to apply profile", str(exc), parent=self)
            return

        self.result = target_name
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()