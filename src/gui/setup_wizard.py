import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from src.gui.widgets.password_entry import PasswordEntry


class SetupWizard(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)

        self.title("CryptoSafe Manager — First Run Setup")
        self.geometry("500x400")
        self.resizable(False, False)

        self.result = None

        self._create_widgets()

#        self.transient(master)
#        self.grab_set()

    def _create_widgets(self):
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
        self.password_entry.pack(
            fill=tk.X,
            pady=(5, 15),
        )

        ttk.Label(
            container,
            text="Confirm master password:",
        ).pack(anchor=tk.W)

        self.confirm_entry = PasswordEntry(container)
        self.confirm_entry.pack(
            fill=tk.X,
            pady=(5, 15),
        )

        ttk.Label(
            container,
            text="Database location:",
        ).pack(anchor=tk.W)

        db_frame = ttk.Frame(container)
        db_frame.pack(fill=tk.X, pady=(5, 15))

        self.db_path_var = tk.StringVar(
            value=str(
                Path.home() / "cryptosafe.db"
            )
        )

        ttk.Entry(
            db_frame,
            textvariable=self.db_path_var,
        ).pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
        )

        ttk.Button(
            db_frame,
            text="Browse",
            command=self._browse_database,
        ).pack(
            side=tk.RIGHT,
            padx=(5, 0),
        )

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
        ).pack(
            fill=tk.X,
            pady=(5, 20),
        )

        button_frame = ttk.Frame(container)
        button_frame.pack(
            side=tk.BOTTOM,
            fill=tk.X,
        )

        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.destroy,
        ).pack(side=tk.RIGHT)

        ttk.Button(
            button_frame,
            text="Create Vault",
            command=self._create_vault,
        ).pack(
            side=tk.RIGHT,
            padx=(0, 10),
        )

    def _browse_database(self):
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

    def _create_vault(self):
        password = self.password_entry.get()
        confirmation = self.confirm_entry.get()

        if not password:
            messagebox.showerror(
                "Invalid password",
                "Master password cannot be empty.",
                parent=self,
            )
            return

        if password != confirmation:
            messagebox.showerror(
                "Invalid password",
                "Passwords do not match.",
                parent=self,
            )
            return

        self.result = {
            "master_password": password,
            "database_path": self.db_path_var.get(),
            "encryption": self.encryption_var.get(),
        }

        self.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    wizard = SetupWizard(root)
    root.wait_window(wizard)

    print(wizard.result)

    root.destroy()