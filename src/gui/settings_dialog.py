import tkinter as tk
from tkinter import ttk
from src.core.settings_manager import SettingsManager


class SettingsDialog(tk.Toplevel):
    def __init__(
        self,
        master=None,
        settings_manager: SettingsManager | None = None,
    ):
        super().__init__(master)

        self.title("CryptoSafe Manager — Settings")
        self.geometry("550x400")
        self.resizable(False, False)

        self.settings_manager = settings_manager
        self.result = None

        self._create_widgets()

        self.transient(master)

    def _create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(
            fill=tk.BOTH,
            expand=True,
            padx=10,
            pady=10,
        )

        security_tab = ttk.Frame(notebook, padding=15)
        appearance_tab = ttk.Frame(notebook, padding=15)
        advanced_tab = ttk.Frame(notebook, padding=15)

        notebook.add(
            security_tab,
            text="Security",
        )
        notebook.add(
            appearance_tab,
            text="Appearance",
        )
        notebook.add(
            advanced_tab,
            text="Advanced",
        )

        self._create_security_tab(security_tab)
        self._create_appearance_tab(appearance_tab)
        self._create_advanced_tab(advanced_tab)

        button_frame = ttk.Frame(self)
        button_frame.pack(
            fill=tk.X,
            padx=10,
            pady=(0, 10),
        )

        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.destroy,
        ).pack(side=tk.RIGHT)

        ttk.Button(
            button_frame,
            text="Save",
            command=self._save,
        ).pack(
            side=tk.RIGHT,
            padx=(0, 10),
        )

    def _create_security_tab(self, parent):
        ttk.Label(
            parent,
            text="Clipboard timeout (seconds):",
        ).pack(anchor=tk.W)

        self.clipboard_timeout = tk.IntVar(value=30)

        ttk.Spinbox(
            parent,
            from_=5,
            to=3600,
            textvariable=self.clipboard_timeout,
        ).pack(fill=tk.X, pady=(5, 20))

        ttk.Label(
            parent,
            text="Auto-lock timeout (seconds):",
        ).pack(anchor=tk.W)

        self.auto_lock_timeout = tk.IntVar(value=300)

        ttk.Spinbox(
            parent,
            from_=30,
            to=86400,
            textvariable=self.auto_lock_timeout,
        ).pack(fill=tk.X, pady=(5, 20))

    def _create_appearance_tab(self, parent):
        ttk.Label(
            parent,
            text="Theme:",
        ).pack(anchor=tk.W)

        self.theme = tk.StringVar(value="System")

        ttk.Combobox(
            parent,
            textvariable=self.theme,
            values=("System", "Light", "Dark"),
            state="readonly",
        ).pack(
            fill=tk.X,
            pady=(5, 20),
        )

        ttk.Label(
            parent,
            text="Language:",
        ).pack(anchor=tk.W)

        self.language = tk.StringVar(value="English")

        ttk.Combobox(
            parent,
            textvariable=self.language,
            values=("English", "Russian"),
            state="readonly",
        ).pack(
            fill=tk.X,
            pady=(5, 20),
        )

    def _create_advanced_tab(self, parent):
        ttk.Label(
            parent,
            text="Backup and export settings",
        ).pack(anchor=tk.W)

        self.backup_enabled = tk.BooleanVar(value=True)

        ttk.Checkbutton(
            parent,
            text="Enable automatic backups",
            variable=self.backup_enabled,
        ).pack(
            anchor=tk.W,
            pady=(10, 5),
        )

        ttk.Label(
            parent,
            text="Backup/export functionality will be implemented in Sprint 8.",
        ).pack(
            anchor=tk.W,
            pady=(10, 0),
        )

    def _save(self):
        self.result = {
            "clipboard_timeout": self.clipboard_timeout.get(),
            "auto_lock_timeout": self.auto_lock_timeout.get(),
            "theme": self.theme.get(),
            "language": self.language.get(),
            "backup_enabled": self.backup_enabled.get(),
        }

        if self.settings_manager is not None:
            for key, value in self.result.items():
                self.settings_manager.set(key, value)

        self.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    dialog = SettingsDialog(root)

    root.wait_window(dialog)

    print(dialog.result)

    root.destroy()