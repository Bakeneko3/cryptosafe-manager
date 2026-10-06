"""
Sharing dialog.

Creates a share package for a single entry using password or public-key
encryption, then writes it to a chosen file.
"""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.core.import_export.key_exchange import (
    KeyExchangeError,
    fingerprint_public_key,
)
from src.core.import_export.sharing_service import (
    Permissions,
    SharingError,
    SharingService,
    SharingValidationError,
)


class SharingDialog(tk.Toplevel):
    """
    Modal sharing dialog.

    `self.result` is the share_id string if a share was created, else None.
    """

    def __init__(
        self,
        master,
        sharing_service: SharingService,
        entry_id: str,
    ) -> None:
        super().__init__(master)

        self.sharing_service = sharing_service
        self.entry_id = entry_id
        self.result: str | None = None

        self.title("CryptoSafe Manager — Share Entry")
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
            c, text="Share Entry", font=("TkDefaultFont", 14, "bold")
        ).pack(anchor=tk.W, pady=(0, 10))

        # Recipient
        ttk.Label(c, text="Recipient (optional):").pack(anchor=tk.W)
        self.recipient_var = tk.StringVar()
        ttk.Entry(c, textvariable=self.recipient_var).pack(fill=tk.X, pady=(4, 10))

        # Expiration
        ttk.Label(c, text="Expires in (days, 1–30):").pack(anchor=tk.W)
        self.expires_var = tk.IntVar(value=7)
        ttk.Spinbox(c, from_=1, to=30, textvariable=self.expires_var).pack(
            fill=tk.X, pady=(4, 10)
        )

        # Permissions
        self.edit_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            c, text="Allow recipient to edit", variable=self.edit_var
        ).pack(anchor=tk.W, pady=(0, 10))

        # Encryption
        ttk.Label(c, text="Encryption:").pack(anchor=tk.W)
        self.encryption_var = tk.StringVar(value="password")
        ttk.Radiobutton(
            c, text="Password", variable=self.encryption_var, value="password",
            command=self._update_encryption,
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            c, text="Recipient public key", variable=self.encryption_var,
            value="public_key", command=self._update_encryption,
        ).pack(anchor=tk.W)

        # Password (shown when encryption=password)
        self.password_frame = ttk.Frame(c)
        self.password_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(self.password_frame, text="Share password:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(self.password_frame, textvariable=self.password_var, show="*").pack(
            fill=tk.X, pady=(4, 10)
        )

        # Public key (shown when encryption=public_key)
        self.pubkey_frame = ttk.Frame(c)
        ttk.Label(self.pubkey_frame, text="Recipient public key (PEM):").pack(anchor=tk.W)
        self.pubkey_text = tk.Text(self.pubkey_frame, height=6, wrap="word")
        self.pubkey_text.pack(fill=tk.X, pady=(4, 10))

        # Status
        self.status_label = ttk.Label(c, text="", foreground="red", wraplength=460)
        self.status_label.pack(anchor=tk.W, pady=(8, 0))

        # Buttons
        btns = ttk.Frame(c)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Create share…", command=self._on_share).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        self._update_encryption()

    def _update_encryption(self) -> None:
        mode = self.encryption_var.get()
        self.password_frame.pack_forget()
        self.pubkey_frame.pack_forget()
        if mode == "password":
            self.password_frame.pack(fill=tk.X, pady=(8, 0))
        else:
            self.pubkey_frame.pack(fill=tk.X, pady=(8, 0))

    def _on_share(self) -> None:
        try:
            perms = Permissions(
                read=True,
                edit=self.edit_var.get(),
                expires_in_days=int(self.expires_var.get()),
            )
            perms.validate()
        except (SharingValidationError, ValueError, tk.TclError) as exc:
            self.status_label.configure(text=str(exc))
            return

        password = None
        public_key_pem = None

        mode = self.encryption_var.get()
        if mode == "password":
            password = self.password_var.get()
            if not password:
                self.status_label.configure(text="Password is required.")
                return
        else:
            pem = self.pubkey_text.get("1.0", tk.END).strip()
            if not pem:
                self.status_label.configure(text="Public key is required.")
                return
            try:
                fingerprint_public_key(pem.encode("ascii"))
            except KeyExchangeError as exc:
                self.status_label.configure(text=str(exc))
                return
            public_key_pem = pem.encode("ascii")

        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save share package",
            defaultextension=".share.json",
            filetypes=(("Share package", "*.share.json"), ("All files", "*.*")),
        )
        if not path:
            return

        try:
            pkg = self.sharing_service.create_share(
                self.entry_id,
                recipient=self.recipient_var.get().strip(),
                permissions=perms,
                password=password,
                public_key_pem=public_key_pem,
            )
        except SharingError as exc:
            self.status_label.configure(text=str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Share failed", str(exc), parent=self)
            return

        try:
            pkg.write(path)
        except Exception as exc:
            messagebox.showerror("Write failed", str(exc), parent=self)
            return

        messagebox.showinfo(
            "Share created",
            f"Share ID: {pkg.share_id}\n"
            f"Expires: {pkg.expires_at}\n"
            f"Encryption: {pkg.encryption_method}\n\n"
            f"Saved to: {path}",
            parent=self,
        )
        self.result = pkg.share_id
        self.grab_release()
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()