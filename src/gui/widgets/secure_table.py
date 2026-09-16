import tkinter as tk
from tkinter import ttk


class SecureTable(ttk.Frame):
    def __init__(
        self,
        master=None,
        columns: tuple[str, ...] = (),
        **kwargs,
    ):
        super().__init__(master, **kwargs)

        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
        )

        for column in columns:
            self.tree.heading(
                column,
                text=column.title(),
            )

        self.tree.pack(
            fill=tk.BOTH,
            expand=True,
        )

    def add_row(self, values: tuple) -> None:
        self.tree.insert(
            "",
            tk.END,
            values=values,
        )

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

    def selected(self):
        selection = self.tree.selection()

        if not selection:
            return None

        return self.tree.item(selection[0])