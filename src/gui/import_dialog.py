"""
Import dialog.

Auto-detects format, offers merge/replace/dry-run modes, and reports
a summary after the operation.
"""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.core.import_export.importer import (
    ImportError_,
    ImportSummary,
    VaultImporter,
)


class ImportDialog(tk.Toplevel):
    """
    Modal import dialog.

    `self.result` is the ImportSummary if an import was performed, else None.
    """

    def __init__(self, master, importer: VaultImporter) -> None:
        super().__init__(master)

        self.importer = importer
        self.result: ImportSummary | None = None

        self.title("CryptoSafe Manager — Import Vault")
        self.geometry("520x520")
        self.resizable(False, False)

        self._create_widgets()

        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _e: self._on_cancel())

    def _create_widgets(self) -> None:
        c = ttk.Frame(self, padding=16)
        c.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            c, text="Import Vault", font=("TkDefaultFont", 14, "bold")
        ).pack(anchor=tk.W, pady=(0, 10))

        ttk.Label(
            c,
            text=(
                "Supported formats: CryptoSafe JSON, CSV, Bitwarden JSON, "
                "LastPass CSV. The format is auto-detected."
            ),
            wraplength=460,
            foreground="gray",
        ).pack(anchor=tk.W, pady=(0, 10))

        # File path
        ttk.Label(c, text="File:").pack(anchor=tk.W)
        row = ttk.Frame(c)
        row.pack(fill=tk.X, pady=(4, 10))
        self.path_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.path_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(row, text="Browse…", command=self._browse).pack(
            side=tk.RIGHT, padx=(6, 0)
        )

        # Password
        ttk.Label(c, text="Password (if encrypted):").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(c, textvariable=self.password_var, show="*").pack(
            fill=tk.X, pady=(4, 10)
        )

        # Private key
        ttk.Label(c, text="Private key (if public-key encrypted):").pack(anchor=tk.W)
        row2 = ttk.Frame(c)
        row2.pack(fill=tk.X, pady=(4, 10))
        self.private_key_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.private_key_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(row2, text="Browse…", command=self._browse_key).pack(
            side=tk.RIGHT, padx=(6, 0)
        )

        # Mode
        ttk.Label(c, text="Mode:").pack(anchor=tk.W)
        self.mode_var = tk.StringVar(value="merge")
        ttk.Radiobutton(
            c, text="Merge (skip duplicates)", variable=self.mode_var, value="merge"
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            c, text="Replace (clear vault first)", variable=self.mode_var, value="replace"
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            c, text="Dry-run (preview only)", variable=self.mode_var, value="dry-run"
        ).pack(anchor=tk.W)

        # Status
        self.status_label = ttk.Label(c, text="", foreground="red", wraplength=460)
        self.status_label.pack(anchor=tk.W, pady=(10, 0))

        # Buttons
        btns = ttk.Frame(c)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Import", command=self._on_import).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

    # ------------------------------------------------------------------ #
    # File pickers
    # ------------------------------------------------------------------ #

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Select import file",
            filetypes=(
                ("All supported", "*.json;*.csv"),
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("All files", "*.*"),
            ),
        )
        if path:
            self.path_var.set(path)

    def _browse_key(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Select private key (PEM)",
            filetypes=(("PEM", "*.pem"), ("All files", "*.*")),
        )
        if path:
            self.private_key_var.set(path)

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_import(self) -> None:
        path = self.path_var.get().strip()
        if not path:
            self.status_label.configure(text="File is required.")
            return
        if not Path(path).exists():
            self.status_label.configure(text="File not found.")
            return

        mode = self.mode_var.get()

        if mode == "replace":
            if not messagebox.askyesno(
                "Replace vault",
                "This will DELETE all existing entries before importing.\n\n"
                "Continue?",
                parent=self,
            ):
                return

        password = self.password_var.get() or None
        private_key_pem = None
        key_path = self.private_key_var.get().strip()
        if key_path and Path(key_path).exists():
            private_key_pem = Path(key_path).read_bytes()

        try:
            summary = self.importer.import_file(
                path,
                mode=mode,
                password=password,
                private_key_pem=private_key_pem,
            )
        except ImportError_ as exc:
            self.status_label.configure(text=str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc), parent=self)
            return

        self.result = summary

        text = (
            f"Format: {summary.format}\n"
            f"Mode: {summary.mode}\n"
            f"Parsed: {summary.total_parsed}\n"
            f"Added: {summary.added}\n"
            f"Skipped duplicates: {summary.skipped_duplicates}\n"
            f"Skipped malicious: {summary.skipped_malicious}\n"
        )
        if summary.errors:
            text += f"Errors: {len(summary.errors)}\n"

        if mode == "dry-run":
            messagebox.showinfo(
                "Dry-run summary",
                text + "\nNothing was written to the vault.",
                parent=self,
            )
            self.result = None
            self.grab_release()
            self.destroy()
            return

        messagebox.showinfo("Import complete", text, parent=self)
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()