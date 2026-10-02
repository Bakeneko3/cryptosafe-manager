"""
Main application window.

Responsible for:
  * initializing core services (Database, EventBus, KeyManager, AuditLogger);
  * running the first-run SetupWizard or the LoginDialog at startup;
  * hosting the main menu, vault table, and status bar;
  * handling Lock / Change Password / Exit actions.

All authentication logic lives in KeyManager. This module only wires
UI events to service calls.

Startup flow:
    mainloop() begins -> after(100) -> _run_auth_gate() shows a modal
    dialog over the (already visible) main window.

The main window is NOT hidden during authentication: hiding it would
break Toplevel.grab_set() on some Tk builds.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.core.audit_logger import AuditLogger
from src.core.config import DATABASE_PATH
from src.core.events import EventBus, UserLoggedIn, UserLoggedOut
from src.core.key_manager import KeyManager
from src.core.settings_manager import SettingsManager
from src.database.db import Database
from src.gui.login_dialog import LoginDialog
from src.gui.settings_dialog import SettingsDialog
from src.gui.setup_wizard import SetupWizard


class MainWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.title("CryptoSafe Manager")
        self.geometry("900x600")
        self.minsize(700, 450)

        # --- core services ------------------------------------------------
        self.database = Database(DATABASE_PATH)
        self.settings_manager = SettingsManager(self.database)

        self.event_bus = EventBus()
        self.audit_logger = AuditLogger(self.database, self.event_bus)

        self.key_manager = KeyManager(
            self.database,
            event_bus=self.event_bus,
        )

        # --- UI -----------------------------------------------------------
        self._create_menu()
        self._create_main_content()
        self._create_status_bar()

        # --- subscriptions ------------------------------------------------
        self.event_bus.subscribe(UserLoggedIn, self._on_logged_in)
        self.event_bus.subscribe(UserLoggedOut, self._on_logged_out)

        # --- authentication gate ------------------------------------------
        # Run *after* the mainloop starts so that Toplevel.grab_set()
        # on child dialogs behaves correctly.
        self.after(100, self._run_auth_gate)

    # ------------------------------------------------------------------ #
    # Authentication gate
    # ------------------------------------------------------------------ #

    def _run_auth_gate(self) -> None:
        """
        Show SetupWizard (first run) or LoginDialog (existing vault).

        If the user cancels, close the application.
        """
        if not self.key_manager.is_initialized():
            dialog = SetupWizard(self, self.key_manager)
        else:
            dialog = LoginDialog(self, self.key_manager)

        self.wait_window(dialog)

        if not dialog.result:
            self._shutdown()
            return

        self._refresh_status_bar()

    def _relock_and_gate(self) -> None:
        """
        Called after Lock: show LoginDialog again.
        If the user cancels, close the application.
        """
        dialog = LoginDialog(self, self.key_manager)
        self.wait_window(dialog)

        if not dialog.result:
            self._shutdown()
            return

        self._refresh_status_bar()

    # ------------------------------------------------------------------ #
    # Shutdown
    # ------------------------------------------------------------------ #

    def _shutdown(self) -> None:
        try:
            self.key_manager.lock(reason="shutdown")
        except Exception:
            pass
        try:
            self.database.close()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Menu
    # ------------------------------------------------------------------ #

    def _create_menu(self) -> None:
        menu_bar = tk.Menu(self)

        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="New", command=self._not_implemented)
        file_menu.add_command(label="Open", command=self._not_implemented)
        file_menu.add_command(label="Backup", command=self._not_implemented)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._shutdown)

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

        security_menu = tk.Menu(menu_bar, tearoff=False)
        security_menu.add_command(
            label="Change Password",
            command=self._open_change_password,
        )
        security_menu.add_command(
            label="Lock",
            command=self._lock_vault,
        )

        help_menu = tk.Menu(menu_bar, tearoff=False)
        help_menu.add_command(label="About", command=self._show_about)

        menu_bar.add_cascade(label="File", menu=file_menu)
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        menu_bar.add_cascade(label="View", menu=view_menu)
        menu_bar.add_cascade(label="Security", menu=security_menu)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menu_bar)

    # ------------------------------------------------------------------ #
    # Main content
    # ------------------------------------------------------------------ #

    def _create_main_content(self) -> None:
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        columns = ("title", "username", "url", "tags")

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

        # Placeholder data for Sprint 2 (real CRUD arrives in Sprint 3).
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

        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _refresh_status_bar(self) -> None:
        if self.key_manager.cache.unlocked:
            self.login_status.configure(text="Status: Unlocked")
        else:
            self.login_status.configure(text="Status: Locked")

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _open_settings(self) -> None:
        dialog = SettingsDialog(
            self,
            settings_manager=self.settings_manager,
        )
        self.wait_window(dialog)

    def _open_change_password(self) -> None:
        try:
            from src.gui.change_password_dialog import ChangePasswordDialog
        except ImportError:
            messagebox.showinfo(
                "Not available",
                "Change Password dialog is not yet available.",
                parent=self,
            )
            return

        dialog = ChangePasswordDialog(self, self.key_manager)
        self.wait_window(dialog)

    def _lock_vault(self) -> None:
        self.key_manager.lock(reason="manual")
        self._relock_and_gate()

    def _not_implemented(self) -> None:
        pass

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About CryptoSafe Manager",
            "CryptoSafe Manager\n"
            "Secure local password manager\n"
            "Sprint 2 development build",
        )

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #

    def _on_logged_in(self, event: UserLoggedIn) -> None:
        self._refresh_status_bar()

    def _on_logged_out(self, event: UserLoggedOut) -> None:
        self._refresh_status_bar()


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()