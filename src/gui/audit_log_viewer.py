"""
Audit log viewer window.

Displays the tamper-evident audit log with filtering, a details panel,
verification, and export. Reads through AuditExporter / LogVerifier
(which require the vault to be unlocked).
"""

from __future__ import annotations

import json
import tkinter as tk
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, ttk

from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_formatters import AuditExporter
from src.core.audit.log_verifier import LogVerifier, VerificationReport
from src.core.key_manager import KeyManager
from src.database.db import Database


COLUMNS = ("seq", "timestamp", "event_type", "severity", "source", "entry_id")
COLUMN_HEADINGS = {
    "seq": "#",
    "timestamp": "Timestamp",
    "event_type": "Type",
    "severity": "Severity",
    "source": "Source",
    "entry_id": "Entry",
}
COLUMN_WIDTHS = {
    "seq": 50,
    "timestamp": 190,
    "event_type": 160,
    "severity": 80,
    "source": 130,
    "entry_id": 150,
}


class AuditLogViewer(tk.Toplevel):
    """
    Modal-ish log viewer. Can be opened as a child of MainWindow.
    """

    def __init__(self, master, database: Database, key_manager: KeyManager) -> None:
        super().__init__(master)

        self._db = database
        self._km = key_manager
        self._exporter = AuditExporter(database, key_manager)
        self._verifier = LogVerifier(key_manager)

        self.title("CryptoSafe Manager — Audit Log")
        self.geometry("1000x650")
        self.minsize(800, 500)

        self._entries: list = []
        self._last_report: VerificationReport | None = None

        self._create_toolbar()
        self._create_filter_bar()
        self._create_table()
        self._create_details_panel()
        self._create_status_bar()

        self.transient(master)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.bind("<Escape>", lambda _e: self.destroy())

        self._reload()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(10, 6))
        bar.pack(fill=tk.X)

        ttk.Button(bar, text="Refresh", command=self._reload).pack(side=tk.LEFT)
        ttk.Button(bar, text="Verify", command=self._on_verify).pack(
            side=tk.LEFT, padx=(6, 0)
        )

        ttk.Separator(bar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10
        )

        ttk.Button(
            bar, text="Export JSON", command=self._on_export_json
        ).pack(side=tk.LEFT)
        ttk.Button(bar, text="Export CSV", command=self._on_export_csv).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        ttk.Button(bar, text="Export PDF", command=self._on_export_pdf).pack(
            side=tk.LEFT, padx=(6, 0)
        )

    def _create_filter_bar(self) -> None:
        bar = ttk.Frame(self, padding=(10, 0))
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="Event type:").pack(side=tk.LEFT)
        self.type_var = tk.StringVar()
        self.type_combo = ttk.Combobox(
            bar,
            textvariable=self.type_var,
            values=("(all)",),
            state="readonly",
            width=20,
        )
        self.type_combo.pack(side=tk.LEFT, padx=(4, 10))
        self.type_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_filter())

        ttk.Label(bar, text="Severity:").pack(side=tk.LEFT)
        self.severity_var = tk.StringVar(value="(all)")
        self.severity_combo = ttk.Combobox(
            bar,
            textvariable=self.severity_var,
            values=("(all)", "INFO", "WARN", "ERROR", "CRITICAL"),
            state="readonly",
            width=12,
        )
        self.severity_combo.pack(side=tk.LEFT, padx=(4, 10))
        self.severity_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_filter())

        ttk.Label(bar, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(bar, textvariable=self.search_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0)
        )

    def _create_table(self) -> None:
        frame = ttk.Frame(self, padding=(10, 6))
        frame.pack(fill=tk.BOTH, expand=True)

        self.table = ttk.Treeview(
            frame,
            columns=COLUMNS,
            show="headings",
            selectmode="browse",
        )
        for col in COLUMNS:
            self.table.heading(col, text=COLUMN_HEADINGS[col])
            self.table.column(col, width=COLUMN_WIDTHS[col])
        self.table.column("seq", anchor=tk.E)

        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.table.bind("<<TreeviewSelect>>", lambda _e: self._on_select())
        self.table.bind("<Double-1>", lambda _e: self._on_select())

    def _create_details_panel(self) -> None:
        frame = ttk.LabelFrame(self, text="Details", padding=8)
        frame.pack(fill=tk.X, padx=10, pady=(0, 6))

        self.details_text = tk.Text(frame, height=8, wrap="word")
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.configure(state=tk.DISABLED)

    def _create_status_bar(self) -> None:
        bar = ttk.Frame(self, relief=tk.SUNKEN)
        bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.count_label = ttk.Label(bar, text="Entries: 0")
        self.count_label.pack(side=tk.LEFT, padx=10)

        self.integrity_label = ttk.Label(bar, text="Integrity: unknown")
        self.integrity_label.pack(side=tk.LEFT, padx=10)

        self.stats_label = ttk.Label(bar, text="")
        self.stats_label.pack(side=tk.RIGHT, padx=10)

    # ------------------------------------------------------------------ #
    # Loading & filtering
    # ------------------------------------------------------------------ #

    def _reload(self) -> None:
        try:
            self._entries = self._exporter._load_entries()
        except RuntimeError as exc:
            messagebox.showwarning("Locked", str(exc), parent=self)
            self._entries = []

        # Update type dropdown.
        types = sorted({e.event_type for e in self._entries})
        self.type_combo.configure(values=("(all)", *types))
        if self.type_var.get() not in self.type_combo.cget("values"):
            self.type_var.set("(all)")

        self._apply_filter()
        self._update_stats()

    def _apply_filter(self) -> None:
        rows = list(self._entries)

        t = self.type_var.get()
        if t and t != "(all)":
            rows = [e for e in rows if e.event_type == t]

        s = self.severity_var.get()
        if s and s != "(all)":
            rows = [e for e in rows if e.severity == s]

        q = self.search_var.get().strip().lower()
        if q:
            def matches(e) -> bool:
                hay = " ".join(
                    [
                        str(e.sequence_number),
                        e.timestamp,
                        e.event_type,
                        e.severity,
                        e.source,
                        e.entry_id or "",
                        json.dumps(e.payload, ensure_ascii=False),
                    ]
                ).lower()
                return q in hay

            rows = [e for e in rows if matches(e)]

        self._render(rows)

    def _render(self, rows: list) -> None:
        self.table.delete(*self.table.get_children())
        for e in rows:
            self.table.insert(
                "",
                tk.END,
                iid=str(e.sequence_number),
                values=(
                    e.sequence_number,
                    e.timestamp,
                    e.event_type,
                    e.severity,
                    e.source,
                    e.entry_id or "",
                ),
            )
        self.count_label.configure(text=f"Entries: {len(rows)} / {len(self._entries)}")

    def _update_stats(self) -> None:
        n = len(self._entries)
        by_sev: dict[str, int] = {}
        for e in self._entries:
            by_sev[e.severity] = by_sev.get(e.severity, 0) + 1
        parts = [f"{k}:{v}" for k, v in sorted(by_sev.items())]
        self.stats_label.configure(text=" | ".join(parts) if parts else "")

    # ------------------------------------------------------------------ #
    # Details
    # ------------------------------------------------------------------ #

    def _on_select(self) -> None:
        sel = self.table.selection()
        if not sel:
            return
        seq = int(sel[0])
        entry = next((e for e in self._entries if e.sequence_number == seq), None)
        if entry is None:
            return

        text = (
            f"Sequence: {entry.sequence_number}\n"
            f"Timestamp: {entry.timestamp}\n"
            f"Type: {entry.event_type}\n"
            f"Severity: {entry.severity}\n"
            f"Source: {entry.source}\n"
            f"User: {entry.user_id}\n"
            f"Entry: {entry.entry_id or '-'}\n"
            f"Previous hash: {entry.previous_hash}\n"
            f"Signature: {entry.signature[:32]}...\n\n"
            f"Payload:\n{json.dumps(entry.payload, indent=2, ensure_ascii=False)}\n"
        )

        self.details_text.configure(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert("1.0", text)
        self.details_text.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------ #
    # Verify (VER-3)
    # ------------------------------------------------------------------ #

    def _on_verify(self) -> None:
        try:
            report = self._verifier.verify_all()
        except RuntimeError as exc:
            messagebox.showwarning("Verify failed", str(exc), parent=self)
            return
        except Exception as exc:
            messagebox.showerror("Verify failed", f"Unexpected error: {exc}", parent=self)
            return

        self._last_report = report
        if report.verified:
            self.integrity_label.configure(text="Integrity: OK")
            messagebox.showinfo(
                "Audit log integrity",
                f"Verified {report.valid_entries} / {report.total_entries} entries.\n"
                "All signatures valid, hash chain intact.",
                parent=self,
            )
            return

        self.integrity_label.configure(text="Integrity: FAILED")
        first = report.errors[0] if report.errors else None
        detail = (
            f"First error: seq {first.sequence_number} — {first.reason}"
            if first
            else "Unknown error."
        )
        messagebox.showerror(
            "Audit log integrity",
            f"Tampering detected!\n\n{report.summary()}\n\n{detail}",
            parent=self,
        )

    # ------------------------------------------------------------------ #
    # Exports
    # ------------------------------------------------------------------ #

    def _on_export_json(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export signed JSON",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            self._exporter.export_signed_json(path)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)
            return
        messagebox.showinfo("Export", f"Saved to {path}", parent=self)

    def _on_export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export CSV",
            defaultextension=".csv",
            filetypes=(("CSV", "*.csv"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            self._exporter.export_csv(path)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)
            return
        messagebox.showinfo("Export", f"Saved to {path}", parent=self)

    def _on_export_pdf(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export PDF",
            defaultextension=".pdf",
            filetypes=(("PDF", "*.pdf"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            self._exporter.export_pdf(path)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)
            return
        messagebox.showinfo("Export", f"Saved to {path}", parent=self)