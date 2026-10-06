"""
Open Share dialog.

Lets the recipient open a share package and optionally save the entry
into their vault.
"""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.core.import_export.sharing_service import (
    SharingEncryptionError,
    SharingError,
    SharingService,
)


class OpenShareDialog(tk.Toplevel):
    """
    Modal dialog for opening share packages.

    `self.result` is True if an entry was saved, else None.
    """

    def __init__(self, master, sharing_service: SharingService) -> None:
        super().__init__(master)

        self.sharing_service = sharing_service
        self.result: bool | None = None
        self._decrypted_body: dict | None = None
        self._package_path: str | None = None

        self.title("CryptoSafe Manager — Open Share")
        self.geometry("560x600")
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
            c, text="Open Share Package", font=("TkDefaultFont", 14, "bold")
        ).pack(anchor=tk.W, pady=(0, 10))

        # File
        ttk.Label(c, text="Share file:").pack(anchor=tk.W)
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
        ttk.Label(c, text="Password (if password-protected):").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(c, textvariable=self.password_var, show="*").pack(
            fill=tk.X, pady=(4, 10)
        )

        # Private key
        ttk.Label(c, text="Private key (if public-key encrypted):").pack(anchor=tk.W)
        row2 = ttk.Frame(c)
        row2.pack(fill=tk.X, pady=(4, 10))
        self.key_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.key_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(row2, text="Browse…", command=self._browse_key).pack(
            side=tk.RIGHT, padx=(6, 0)
        )

        # Buttons row
        buttons = ttk.Frame(c)
        buttons.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(
            buttons, text="Decrypt and preview", command=self._on_decrypt
        ).pack(side=tk.LEFT)

        # Preview
        ttk.Label(c, text="Preview:").pack(anchor=tk.W)
        self.preview_text = tk.Text(c, height=12, wrap="word", state=tk.DISABLED)
        self.preview_text.pack(fill=tk.BOTH, expand=True, pady=(4, 10))

        # Save-to-vault option
        self.save_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            c, text="Save entry to my vault", variable=self.save_var
        ).pack(anchor=tk.W, pady=(0, 6))

        # Status
        self.status_label = ttk.Label(c, text="", foreground="red", wraplength=520)
        self.status_label.pack(anchor=tk.W, pady=(0, 6))

        # Bottom buttons
        btns = ttk.Frame(c)
        btns.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Button(btns, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)
        self.save_btn = ttk.Button(
            btns, text="Save to vault", command=self._on_save, state=tk.DISABLED
        )
        self.save_btn.pack(side=tk.RIGHT, padx=(0, 8))

    # ------------------------------------------------------------------ #
    # Pickers
    # ------------------------------------------------------------------ #

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Select share package",
            filetypes=(
                ("Share package", "*.json;*.share.json"),
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
            self.key_var.set(path)

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _on_decrypt(self) -> None:
        path = self.path_var.get().strip()
        if not path or not Path(path).exists():
            self.status_label.configure(text="Share file not found.")
            return

        password = self.password_var.get() or None
        private_key_pem = None
        key_path = self.key_var.get().strip()
        if key_path and Path(key_path).exists():
            private_key_pem = Path(key_path).read_bytes()

        try:
            body = self.sharing_service.open_share(
                path,
                password=password,
                private_key_pem=private_key_pem,
            )
        except SharingEncryptionError as exc:
            self.status_label.configure(text=str(exc))
            return
        except SharingError as exc:
            self.status_label.configure(text=str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Failed to open share", str(exc), parent=self)
            return

        self._decrypted_body = body
        self._package_path = path

        header = body.get("header") or {}
        entry = body.get("entry") or {}

        lines = [
            f"Share ID: {header.get('share_id', '-')}",
            f"From: {header.get('recipient', '-') or '-'}",
            f"Expires: {header.get('expires_at', '-')}",
            f"Permissions: {header.get('permissions', {})}",
            "",
            f"Title: {entry.get('title', '')}",
            f"Username: {entry.get('username', '')}",
            f"Password: {entry.get('password', '')}",
            f"URL: {entry.get('url', '')}",
            f"Category: {entry.get('category', '')}",
            f"Notes: {entry.get('notes', '')}",
        ]
        self.preview_text.configure(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert("1.0", "\n".join(lines))
        self.preview_text.configure(state=tk.DISABLED)

        self.status_label.configure(text="Decrypted successfully.")
        self.save_btn.configure(state=tk.NORMAL)

    def _on_save(self) -> None:
        if self._decrypted_body is None or self._package_path is None:
            return

        entry = self._decrypted_body.get("entry") or {}
        if not entry:
            self.status_label.configure(text="No entry to save.")
            return

        if self.save_var.get():
            try:
                self.sharing_service.import_shared_entry(
                    self._package_path,
                    password=self.password_var.get() or None,
                    private_key_pem=(
                        Path(self.key_var.get()).read_bytes()
                        if self.key_var.get().strip()
                        else None
                    ),
                    save_to_vault=True,
                )
            except Exception as exc:
                messagebox.showerror("Failed to save", str(exc), parent=self)
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