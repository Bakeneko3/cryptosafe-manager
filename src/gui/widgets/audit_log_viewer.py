import tkinter as tk
from tkinter import ttk


class AuditLogViewer(ttk.Frame):
    """Placeholder audit log viewer for Sprint 1."""

    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

        self.label = ttk.Label(
            self,
            text="Audit log viewer — Sprint 5",
        )
        self.label.pack(
            padx=20,
            pady=20,
        )

    def refresh(self) -> None:
        """Refresh audit log entries."""
        pass