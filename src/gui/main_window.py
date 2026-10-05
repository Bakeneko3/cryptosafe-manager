"""
Main application window.

Responsible for:
  * initializing core services (Database, EventBus, KeyManager,
    AuditLogger, EntryManager, ClipboardService);
  * running the first-run SetupWizard or the LoginDialog at startup;
  * hosting the main menu, vault table, search bar, and status bar;
  * handling CRUD (Add/Edit/Delete), search, clipboard operations,
    Lock, Change Password, and Exit actions.

All authentication logic lives in KeyManager. All vault persistence
lives in EntryManager. All clipboard operations go through
ClipboardService. This module only wires UI events to service calls.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.core import config
from src.core.audit_logger import AuditLogger
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.clipboard_settings import (
    load_clipboard_settings,
    save_clipboard_settings,
)
from src.core.config import DATABASE_PATH
from src.core.events import (
    EntryCreated,
    EntryDeleted,
    EntryUpdated,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
)
from src.core.key_manager import KeyManager
from src.core.settings_manager import SettingsManager
from src.core.vault.entry_manager import EntryManager, VaultError
from src.core.vault.search import search_entries
from src.database.db import Database
from src.gui.clipboard_settings_dialog import ClipboardSettingsDialog
from src.gui.entry_dialog import EntryDialog
from src.gui.login_dialog import LoginDialog
from src.gui.settings_dialog import SettingsDialog
from src.gui.setup_wizard import SetupWizard


# --------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------- #

COLUMNS = ("title", "username", "url", "updated_at")
COLUMN_HEADINGS = {
    "title": "Title",
    "username": "Username",
    "url": "URL",
    "updated_at": "Last Modified",
}
COLUMN_WIDTHS = {
    "title": 220,
    "username": 220,
    "url": 260,
    "updated_at": 160,
}
STATUS_REFRESH_MS = 1000  # update clipboard countdown every 1s


class MainWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.title("CryptoSafe Manager")
        self.geometry("1000x650")
        self.minsize(800, 500)

        # --- core services ------------------------------------------------
        self.database = Database(DATABASE_PATH)
        self.settings_manager = SettingsManager(self.database)

        self.event_bus = EventBus()
        self.audit_logger = AuditLogger(self.database, self.event_bus)

        self.key_manager = KeyManager(
            self.database,
            event_bus=self.event_bus,
        )

        self.entry_manager = EntryManager(
            self.database,
            self.key_manager,
            event_bus=self.event_bus,
        )

        # Clipboard: load persisted settings and construct the service.
        self._clipboard_settings = load_clipboard_settings(self.settings_manager)
        self.clipboard_service = ClipboardService(
            self.event_bus,
            timeout=self._clipboard_settings.timeout,
            on_warning=self._on_clipboard_warning,
        )

        # In-memory cache of decrypted entries (list of dicts).
        self._entries_cache: list[dict] = []

        # Track username visibility (GUI-3 global toggle).
        self._usernames_visible = False

        # --- UI -----------------------------------------------------------
        self._create_menu()
        self._create_toolbar()
        self._create_search_bar()
        self._create_main_content()
        self._create_context_menu()
        self._create_status_bar()

        # --- subscriptions ------------------------------------------------
        self.event_bus.subscribe(UserLoggedIn, self._on_logged_in)
        self.event_bus.subscribe(UserLoggedOut, self._on_logged_out)
        self.event_bus.subscribe(EntryCreated, self._on_entry_changed)
        self.event_bus.subscribe(EntryUpdated, self._on_entry_changed)
        self.event_bus.subscribe(EntryDeleted, self._on_entry_changed)

        # --- keyboard shortcuts -------------------------------------------
        self.bind("<Control-n>", lambda _e: self._add_entry())
        self.bind("<Control-e>", lambda _e: self._edit_selected())
        self.bind("<Delete>", lambda _e: self._delete_selected())
        self.bind("<Control-Shift-P>", lambda _e: self._toggle_usernames())
        self.bind("<Control-f>", lambda _e: self._focus_search())
        self.bind("<Control-Shift-C>", lambda _e: self._clear_clipboard())

        # --- clipboard status refresh loop --------------------------------
        self._schedule_clipboard_status_refresh()

        # --- authentication gate ------------------------------------------
        self.after(100, self._run_auth_gate)

    # ------------------------------------------------------------------ #
    # Authentication gate
    # ------------------------------------------------------------------ #

    def _run_auth_gate(self) -> None:
        if not self.key_manager.is_initialized():
            dialog = SetupWizard(self, self.key_manager)
        else:
            dialog = LoginDialog(self, self.key_manager)

        self.wait_window(dialog)

        if not dialog.result:
            self._shutdown()
            return

        self._refresh_status_bar()
        self._refresh_entries()

    def _relock_and_gate(self) -> None:
        dialog = LoginDialog(self, self.key_manager)
        self.wait_window(dialog)

        if not dialog.result:
            self._shutdown()
            return

        self._refresh_status_bar()
        self._refresh_entries()

    # ------------------------------------------------------------------ #
    # Shutdown
    # ------------------------------------------------------------------ #

    def _shutdown(self) -> None:
        try:
            self.clipboard_service.clear_if_owned(reason="shutdown")
        except Exception:
            pass
        try:
            self.clipboard_service.shutdown()
        except Exception:
            pass
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
        file_menu.add_command(label="New", command=self._add_entry)
        file_menu.add_command(label="Open", command=self._not_implemented)
        file_menu.add_command(label="Backup", command=self._not_implemented)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._shutdown)

        edit_menu = tk.Menu(menu_bar, tearoff=False)
        edit_menu.add_command(label="Add", command=self._add_entry)
        edit_menu.add_command(label="Edit", command=self._edit_selected)
        edit_menu.add_command(label="Delete", command=self._delete_selected)
        edit_menu.add_separator()
        edit_menu.add_command(
            label="Copy Password",
            command=self._copy_password_selected,
        )
        edit_menu.add_command(
            label="Copy Username",
            command=self._copy_username_selected,
        )
        edit_menu.add_command(
            label="Clear Clipboard",
            command=self._clear_clipboard,
        )

        view_menu = tk.Menu(menu_bar, tearoff=False)
        view_menu.add_command(label="Logs", command=self._not_implemented)
        view_menu.add_command(
            label="Toggle Usernames (Ctrl+Shift+P)",
            command=self._toggle_usernames,
        )
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
            label="Clipboard Settings",
            command=self._open_clipboard_settings,
        )
        security_menu.add_separator()
        security_menu.add_command(
            label="Clear Clipboard",
            command=self._clear_clipboard,
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
    # Toolbar
    # ------------------------------------------------------------------ #

    def _create_toolbar(self) -> None:
        toolbar = ttk.Frame(self, padding=(10, 6))
        toolbar.pack(fill=tk.X)

        ttk.Button(
            toolbar,
            text="+ Add",
            command=self._add_entry,
        ).pack(side=tk.LEFT)

        ttk.Button(
            toolbar,
            text="Edit",
            command=self._edit_selected,
        ).pack(side=tk.LEFT, padx=(6, 0))

        ttk.Button(
            toolbar,
            text="Delete",
            command=self._delete_selected,
        ).pack(side=tk.LEFT, padx=(6, 0))

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10
        )

        ttk.Button(
            toolbar,
            text="Copy Password",
            command=self._copy_password_selected,
        ).pack(side=tk.LEFT)

        ttk.Button(
            toolbar,
            text="Clear Clipboard",
            command=self._clear_clipboard,
        ).pack(side=tk.LEFT, padx=(6, 0))

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10
        )

        ttk.Button(
            toolbar,
            text="Show/Hide Usernames",
            command=self._toggle_usernames,
        ).pack(side=tk.LEFT)

        ttk.Button(
            toolbar,
            text="Refresh",
            command=self._refresh_entries,
        ).pack(side=tk.LEFT, padx=(6, 0))

    # ------------------------------------------------------------------ #
    # Search bar
    # ------------------------------------------------------------------ #

    def _create_search_bar(self) -> None:
        bar = ttk.Frame(self, padding=(10, 0))
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="Search:").pack(side=tk.LEFT)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filter())

        self.search_entry = ttk.Entry(bar, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))

        self.fuzzy_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            bar,
            text="Fuzzy",
            variable=self.fuzzy_var,
            command=self._apply_filter,
        ).pack(side=tk.LEFT)

        ttk.Button(
            bar,
            text="Clear",
            command=lambda: self.search_var.set(""),
        ).pack(side=tk.LEFT, padx=(6, 0))

    # ------------------------------------------------------------------ #
    # Main content (table)
    # ------------------------------------------------------------------ #

    def _create_main_content(self) -> None:
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        self.table = ttk.Treeview(
            frame,
            columns=COLUMNS,
            show="headings",
            selectmode="extended",
        )

        for col in COLUMNS:
            self.table.heading(
                col,
                text=COLUMN_HEADINGS[col],
                command=lambda c=col: self._sort_by(c),
            )
            self.table.column(col, width=COLUMN_WIDTHS[col])

        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.table.bind("<Double-1>", lambda _e: self._edit_selected())

        self._sort_reverse = False
        self._sort_column: str | None = None

    def _create_context_menu(self) -> None:
        self.context_menu = tk.Menu(self, tearoff=False)
        self.context_menu.add_command(label="Edit", command=self._edit_selected)
        self.context_menu.add_command(
            label="Copy Password",
            command=self._copy_password_selected,
        )
        self.context_menu.add_command(
            label="Copy Username",
            command=self._copy_username_selected,
        )
        self.context_menu.add_command(
            label="Copy All",
            command=self._copy_all_selected,
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Clear Clipboard",
            command=self._clear_clipboard,
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Delete",
            command=self._delete_selected,
        )

        self.table.bind("<Button-3>", self._show_context_menu)

    def _show_context_menu(self, event) -> None:
        row = self.table.identify_row(event.y)
        if row:
            self.table.selection_set(row)
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()

    # ------------------------------------------------------------------ #
    # Status bar
    # ------------------------------------------------------------------ #

    def _create_status_bar(self) -> None:
        self.status_bar = ttk.Frame(self, relief=tk.SUNKEN)

        self.login_status = ttk.Label(self.status_bar, text="Status: Locked")
        self.login_status.pack(side=tk.LEFT, padx=10)

        self.count_status = ttk.Label(self.status_bar, text="Entries: 0")
        self.count_status.pack(side=tk.LEFT, padx=10)

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

    def _schedule_clipboard_status_refresh(self) -> None:
        try:
            self._update_clipboard_status()
        finally:
            self.after(STATUS_REFRESH_MS, self._schedule_clipboard_status_refresh)

    def _update_clipboard_status(self) -> None:
        try:
            status = self.clipboard_service.status()
        except Exception:
            return

        if not status.active:
            self.clipboard_status.configure(text="Clipboard: --")
            return

        if status.timeout_seconds == config.CLIPBOARD_TIMEOUT_NEVER:
            self.clipboard_status.configure(
                text=f"Clipboard: {status.data_type} (no auto-clear)"
            )
            return

        remaining = int(status.remaining_seconds)
        self.clipboard_status.configure(
            text=f"Clipboard: {status.data_type} ({remaining}s)"
        )

    # ------------------------------------------------------------------ #
    # Entry loading & filtering
    # ------------------------------------------------------------------ #

    def _refresh_entries(self) -> None:
        if not self.key_manager.cache.unlocked:
            self._entries_cache = []
            self._render_entries([])
            return

        try:
            self._entries_cache = self.entry_manager.get_all_entries()
        except VaultError:
            self._entries_cache = []

        self._apply_filter()

    def _apply_filter(self) -> None:
        query = self.search_var.get() if hasattr(self, "search_var") else ""
        fuzzy = self.fuzzy_var.get() if hasattr(self, "fuzzy_var") else False

        if query:
            filtered = search_entries(
                self._entries_cache,
                query,
                fuzzy=fuzzy,
            )
        else:
            filtered = list(self._entries_cache)

        self._render_entries(filtered)

    def _render_entries(self, entries: list[dict]) -> None:
        if self._sort_column:
            entries = sorted(
                entries,
                key=lambda e: str(e.get(self._sort_column, "")).lower(),
                reverse=self._sort_reverse,
            )

        self.table.delete(*self.table.get_children())

        for entry in entries:
            username = str(entry.get("username", ""))
            self.table.insert(
                "",
                tk.END,
                iid=entry["id"],
                values=(
                    entry.get("title", ""),
                    self._format_username(username),
                    entry.get("url", ""),
                    entry.get("updated_at", ""),
                ),
            )

        self.count_status.configure(text=f"Entries: {len(entries)}")

    def _format_username(self, username: str) -> str:
        if self._usernames_visible or not username:
            return username
        if len(username) <= 4:
            return "•" * len(username)
        return username[:4] + "•" * (len(username) - 4)

    # ------------------------------------------------------------------ #
    # Sorting
    # ------------------------------------------------------------------ #

    def _sort_by(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False
        self._apply_filter()

    # ------------------------------------------------------------------ #
    # Selection
    # ------------------------------------------------------------------ #

    def _selected_ids(self) -> list[str]:
        return list(self.table.selection())

    def _selected_entry(self) -> dict | None:
        ids = self._selected_ids()
        if not ids:
            return None
        for entry in self._entries_cache:
            if entry["id"] == ids[0]:
                return entry
        return None

    # ------------------------------------------------------------------ #
    # CRUD actions
    # ------------------------------------------------------------------ #

    def _require_unlocked(self) -> bool:
        if not self.key_manager.cache.unlocked:
            messagebox.showwarning(
                "Vault locked",
                "Unlock the vault first.",
                parent=self,
            )
            return False
        return True

    def _add_entry(self) -> None:
        if not self._require_unlocked():
            return

        dialog = EntryDialog(self)
        self.wait_window(dialog)
        if dialog.result is None:
            return

        try:
            self.entry_manager.create_entry(dialog.result)
        except VaultError as exc:
            messagebox.showerror(
                "Failed to create entry",
                str(exc),
                parent=self,
            )
            return

        self._refresh_entries()

    def _edit_selected(self) -> None:
        if not self._require_unlocked():
            return

        entry = self._selected_entry()
        if entry is None:
            return

        dialog = EntryDialog(self, entry=entry)
        self.wait_window(dialog)
        if dialog.result is None:
            return

        try:
            self.entry_manager.update_entry(entry["id"], dialog.result)
        except VaultError as exc:
            messagebox.showerror(
                "Failed to update entry",
                str(exc),
                parent=self,
            )
            return

        self._refresh_entries()

    def _delete_selected(self) -> None:
        if not self._require_unlocked():
            return

        ids = self._selected_ids()
        if not ids:
            return

        count = len(ids)
        if not messagebox.askyesno(
            "Delete entries",
            f"Delete {count} selected entr{'y' if count == 1 else 'ies'}?",
            parent=self,
        ):
            return

        for entry_id in ids:
            try:
                self.entry_manager.delete_entry(entry_id, soft_delete=True)
            except VaultError:
                continue

        self._refresh_entries()

    # ------------------------------------------------------------------ #
    # Clipboard actions (Sprint 4)
    # ------------------------------------------------------------------ #

    def _copy_password_selected(self) -> None:
        if not self._require_unlocked():
            return
        entry = self._selected_entry()
        if entry is None:
            return
        self._copy_value(
            str(entry.get("password", "")),
            data_type="password",
            entry_id=entry["id"],
        )

    def _copy_username_selected(self) -> None:
        if not self._require_unlocked():
            return
        entry = self._selected_entry()
        if entry is None:
            return
        self._copy_value(
            str(entry.get("username", "")),
            data_type="username",
            entry_id=entry["id"],
        )

    def _copy_all_selected(self) -> None:
        if not self._require_unlocked():
            return
        entry = self._selected_entry()
        if entry is None:
            return
        combined = (
            f"Title: {entry.get('title', '')}\n"
            f"Username: {entry.get('username', '')}\n"
            f"Password: {entry.get('password', '')}\n"
            f"URL: {entry.get('url', '')}\n"
            f"Notes: {entry.get('notes', '')}"
        )
        self._copy_value(
            combined,
            data_type="entry",
            entry_id=entry["id"],
        )

    def _copy_value(
        self,
        value: str,
        *,
        data_type: str,
        entry_id: str | None,
    ) -> None:
        if not value:
            return
        ok = self.clipboard_service.copy(
            value,
            data_type=data_type,
            source_entry_id=entry_id,
        )
        if not ok:
            messagebox.showwarning(
                "Copy failed",
                "Could not write to the system clipboard. "
                "Another application may be holding it.",
                parent=self,
            )

    def _clear_clipboard(self) -> None:
        self.clipboard_service.clear(reason="manual")

    def _on_clipboard_warning(self, seconds: float) -> None:
        # Called by ClipboardService before auto-clear.
        # We use a lightweight status message instead of a modal dialog.
        try:
            self.clipboard_status.configure(
                text=f"Clipboard: clearing in {int(seconds)}s"
            )
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Toggles & focus
    # ------------------------------------------------------------------ #

    def _toggle_usernames(self) -> None:
        self._usernames_visible = not self._usernames_visible
        self._apply_filter()

    def _focus_search(self) -> None:
        self.search_entry.focus_set()

    # ------------------------------------------------------------------ #
    # Other actions
    # ------------------------------------------------------------------ #

    def _open_settings(self) -> None:
        dialog = SettingsDialog(
            self,
            settings_manager=self.settings_manager,
        )
        self.wait_window(dialog)

    def _open_clipboard_settings(self) -> None:
        dialog = ClipboardSettingsDialog(self, self.settings_manager)
        self.wait_window(dialog)

        if dialog.result is not None:
            # Apply new timeout to the running service.
            self.clipboard_service.set_timeout(dialog.result.timeout)
            self._clipboard_settings = dialog.result

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
        # SEC-3: clear the clipboard immediately on lock.
        self.clipboard_service.clear_if_owned(reason="lock")

        self.key_manager.lock(reason="manual")
        self._entries_cache = []
        self.table.delete(*self.table.get_children())
        self._relock_and_gate()

    def _not_implemented(self) -> None:
        pass

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About CryptoSafe Manager",
            "CryptoSafe Manager\n"
            "Secure local password manager\n"
            "Sprint 4 development build",
        )

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #

    def _on_logged_in(self, event: UserLoggedIn) -> None:
        self._refresh_status_bar()

    def _on_logged_out(self, event: UserLoggedOut) -> None:
        self._refresh_status_bar()

    def _on_entry_changed(self, event) -> None:
        self._refresh_entries()


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()