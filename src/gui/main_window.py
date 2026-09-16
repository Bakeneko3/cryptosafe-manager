from src.core.config import DATABASE_PATH
from src.core.settings_manager import SettingsManager
from src.database.db import Database
from src.gui.settings_dialog import SettingsDialog

from src.core.audit_logger import AuditLogger
from src.core.events import EventBus

import tkinter as tk
from tkinter import ttk


class MainWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.database = Database(DATABASE_PATH)
        self.settings_manager = SettingsManager(self.database)

        self.title("CryptoSafe Manager")
        self.geometry("900x600")
        self.minsize(700, 450)

        self._create_menu()
        self._create_main_content()
        self._create_status_bar()

        self.event_bus = EventBus()
        self.audit_logger = AuditLogger(
            self.database,
            self.event_bus,
        )

    def _create_menu(self) -> None:
        menu_bar = tk.Menu(self)

        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="New", command=self._not_implemented)
        file_menu.add_command(label="Open", command=self._not_implemented)
        file_menu.add_command(label="Backup", command=self._not_implemented)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._exit)

        edit_menu = tk.Menu(menu_bar, tearoff=False)
        edit_menu.add_command(label="Add", command=self._not_implemented)
        edit_menu.add_command(label="Edit", command=self._not_implemented)
        edit_menu.add_command(label="Delete", command=self._not_implemented)

        view_menu = tk.Menu(menu_bar, tearoff=False)
        view_menu.add_command(label="Logs", command=self._not_implemented)
        view_menu.add_command(
            label="Settings",
            command=self._open_settings,
        )

        help_menu = tk.Menu(menu_bar, tearoff=False)
        help_menu.add_command(label="About", command=self._show_about)

        menu_bar.add_cascade(label="File", menu=file_menu)
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        menu_bar.add_cascade(label="View", menu=view_menu)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menu_bar)

    def _create_main_content(self) -> None:
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        columns = (
            "title",
            "username",
            "url",
            "tags",
        )

        self.table = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
        )

        self.table.heading("title", text="Title")
        self.table.heading("username", text="Username")
        self.table.heading("url", text="URL")
        self.table.heading("tags", text="Tags")

        self.table.column("title", width=200)
        self.table.column("username", width=200)
        self.table.column("url", width=250)
        self.table.column("tags", width=150)

        self.table.pack(fill=tk.BOTH, expand=True)

        # Placeholder data for Sprint 1.
        self.table.insert(
            "",
            tk.END,
            values=(
                "Example Entry",
                "user@example.com",
                "https://example.com",
                "demo",
            ),
        )

    def _create_status_bar(self) -> None:
        self.status_bar = ttk.Frame(self, relief=tk.SUNKEN)

        self.login_status = ttk.Label(
            self.status_bar,
            text="Status: Locked",
        )
        self.login_status.pack(side=tk.LEFT, padx=10)

        self.clipboard_status = ttk.Label(
            self.status_bar,
            text="Clipboard: --",
        )
        self.clipboard_status.pack(side=tk.RIGHT, padx=10)

        self.status_bar.pack(
            side=tk.BOTTOM,
            fill=tk.X,
        )

    def _open_settings(self) -> None:
        dialog = SettingsDialog(
            self,
            settings_manager=self.settings_manager,
        )

        self.wait_window(dialog)

    def _exit(self) -> None:
        self.database.close()
        self.destroy()

    def _not_implemented(self) -> None:
        pass

    def _show_about(self) -> None:
        from tkinter import messagebox

        messagebox.showinfo(
            "About CryptoSafe Manager",
            "CryptoSafe Manager\n"
            "Secure local password manager\n"
            "Sprint 1 development build",
        )


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()