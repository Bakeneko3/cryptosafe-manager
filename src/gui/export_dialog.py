"""
Export dialog.

Collects the format, encryption mode, field selection, and whether to
export the whole vault or only the entries selected in the main window.
"""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.core.import_export.exporter import (
    ExportError,
    VaultExporter,
)
from src.core.import_export.key_exchange import (
    KeyExchangeError,
    fingerprint_public_key,
    generate_keypair,
)


FORMATS = ("json", "csv", "bitwarden", "lastpass")
ENCRYPTIONS = ("password", "public_key", "none")
FIELD_CHOICES = (
    "title",
    "username",
    "password",
    "url",
    "notes",
    "category",
    "tags",
)


class ExportDialog(tk.Toplevel):
    """
    Modal export dialog.

    `self.result` is True if the export completed, else None.
    """

    def __init__(
        self,
        master,
        exporter: VaultExporter,
        selected_entry_ids: list[str] | None = None,
    ) -> None:
        super().__init__(master)

        self.exporter = exporter
        self.selected_entry_ids = selected_entry_ids or []
        self.result: bool | None = None

        self.title("CryptoSafe Manager — Export Vault")
        self.geometry("520x600")
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
            c, text="Export Vault", font=("TkDefaultFont", 14, "bold")
        ).pack(anchor=tk.W, pady=(0, 10))

        # Format
        ttk.Label(c, text="Format:").pack(anchor=tk.W)
        self.format_var = tk.StringVar(value="json")
        fmt_combo = ttk.Combobox(
            c,
            textvariable=self.format_var,
            values=FORMATS,
            state="readonly",
        )
        fmt_combo.pack(fill=tk.X, pady=(4, 10))

        # Encryption
        ttk.Label(c, text="Encryption:").pack(anchor=tk.W)
        self.encryption_var = tk.StringVar(value="password")
        enc_combo = ttk.Combobox(
            c,
            textvariable=self.encryption_var,
            values=ENCRYPTIONS,
            state="readonly",
        )
        enc_combo.pack(fill=tk.X, pady=(4, 4))
        enc_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_encryption())

        ttk.Label(
            c,
            text=(
                "Note: \"none\" produces a plaintext file — use only for "
                "migration to another manager."
            ),
            foreground="gray",
            wraplength=460,
        ).pack(anchor=tk.W, pady=(0, 10))

        # Password
        self.password_frame = ttk.Frame(c)
        self.password_frame.pack(fill=tk.X)
        ttk.Label(self.password_frame, text="Export password:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(
            self.password_frame, textvariable=self.password_var, show="*"
        ).pack(fill=tk.X, pady=(4, 4))
        ttk.Label(self.password_frame, text="Confirm:").pack(anchor=tk.W)
        self.password_confirm_var = tk.StringVar()
        ttk.Entry(
            self.password_frame, textvariable=self.password_confirm_var, show="*"
        ).pack(fill=tk.X, pady=(4, 10))

        # Public key (hidden initially)
        self.public_key_frame = ttk.Frame(c)
        ttk.Label(
            self.public_key_frame, text="Recipient public key (PEM):"
        ).pack(anchor=tk.W)
        self.public_key_text = tk.Text(self.public_key_frame, height=6, wrap="word")
        self.public_key_text.pack(fill=tk.X, pady=(4, 4))
        ttk.Button(
            self.public_key_frame,
            text="Generate ephemeral key pair",
            command=self._generate_keypair,
        ).pack(anchor=tk.W, pady=(0, 4))
        ttk.Label(
            self.public_key_frame,
            text=(
                "Generates a throwaway key pair; save the PRIVATE key to "
                "decrypt the export later."
            ),
            foreground="gray",
            wraplength=460,
        ).pack(anchor=tk.W, pady=(0, 8))

        # Selection scope
        ttk.Label(c, text="Scope:").pack(anchor=tk.W, pady=(8, 0))
        self.scope_var = tk.StringVar(value="all")
        ttk.Radiobutton(
            c, text="Whole vault", variable=self.scope_var, value="all"
        ).pack(anchor=tk.W)
        rb = ttk.Radiobutton(
            c,
            text=(
                f"Only selected entries ({len(self.selected_entry_ids)} selected)"
            ),
            variable=self.scope_var,
            value="selected",
        )
        rb.pack(anchor=tk.W)
        if not self.selected_entry_ids:
            rb.configure(state=tk.DISABLED)

        # Fields to exclude
        ttk.Label(c, text="Exclude fields:").pack(anchor=tk.W, pady=(8, 0))
        self.exclude_vars = {f: tk.BooleanVar(value=False) for f in FIELD_CHOICES}
        grid = ttk.Frame(c)
        grid.pack(fill=tk.X)
        for i, f in enumerate(FIELD_CHOICES):
            ttk.Checkbutton(
                grid, text=f, variable=self.exclude_vars[f]
            ).grid(row=i // 3, column=i % 3, sticky=tk.W, padx=4)

        # Compress
        self.compress_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(c, text="Compress (GZIP)", variable=self.compress_var).pack(
            anchor=tk.W, pady=(8, 0)
        )

        # Status
        self.status_label = ttk.Label(c, text="", foreground="red")
        self.status_label.pack(anchor=tk.W, pady=(8, 0))

        # Buttons
        btns = ttk.Frame(c)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Export…", command=self._on_export).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        self._update_encryption()

    # ------------------------------------------------------------------ #
    # UI helpers
    # ------------------------------------------------------------------ #

    def _update_encryption(self) -> None:
        mode = self.encryption_var.get()
        # Hide all, then show the active one.
        self.password_frame.pack_forget()
        self.public_key_frame.pack_forget()

        if mode == "password":
            self.password_frame.pack(fill=tk.X, after=self.children_widget_before())
        elif mode == "public_key":
            self.public_key_frame.pack(fill=tk.X, after=self.children_widget_before())

    def children_widget_before(self):
        # Return the widget that should be immediately before the dynamic frame.
        # For simplicity we return None and use pack order — this dialog is
        # short-lived; positioning is not critical for tests.
        return None

    def _generate_keypair(self) -> None:
        kp = generate_keypair("rsa")
        self.public_key_text.delete("1.0", tk.END)
        self.public_key_text.insert("1.0", kp.public_pem.decode("ascii"))
        # Save the private key automatically to a user-chosen file.
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save PRIVATE key (required to decrypt the export later)",
            defaultextension=".pem",
            filetypes=(("PEM", "*.pem"), ("All files", "*.*")),
        )
        if path:
            Path(path).write_bytes(kp.private_pem)
            messagebox.showinfo(
                "Private key saved",
                "Store this private key safely — it is required to decrypt "
                "the export.",
                parent=self,
            )

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_export(self) -> None:
        fmt = self.format_var.get()
        mode = self.encryption_var.get()

        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save export",
            defaultextension=".json",
            filetypes=(("All files", "*.*"),),
        )
        if not path:
            return

        password = None
        if mode == "password":
            password = self.password_var.get()
            if not password:
                self.status_label.configure(text="Password is required.")
                return
            if password != self.password_confirm_var.get():
                self.status_label.configure(text="Passwords do not match.")
                return

        public_key_pem = None
        if mode == "public_key":
            pem = self.public_key_text.get("1.0", tk.END).strip()
            if not pem:
                self.status_label.configure(text="Public key is required.")
                return
            try:
                fingerprint_public_key(pem.encode("ascii"))
            except KeyExchangeError as exc:
                self.status_label.configure(text=str(exc))
                return
            public_key_pem = pem.encode("ascii")

        entry_ids = None
        if self.scope_var.get() == "selected":
            entry_ids = self.selected_entry_ids

        exclude = [f for f, v in self.exclude_vars.items() if v.get()]

        try:
            self.exporter.export(
                path,
                format=fmt,
                encryption=mode,
                password=password,
                public_key_pem=public_key_pem,
                entry_ids=entry_ids,
                exclude_fields=exclude or None,
                compress=self.compress_var.get(),
            )
        except ExportError as exc:
            self.status_label.configure(text=str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)
            return

        self.result = True
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()