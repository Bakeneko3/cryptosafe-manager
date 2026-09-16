import tkinter as tk
from tkinter import ttk


class PasswordEntry(ttk.Frame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master)

        self._visible = False

        self.entry = ttk.Entry(
            self,
            show="*",
            **kwargs,
        )
        self.entry.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
        )

        self.toggle_button = ttk.Button(
            self,
            text="Show",
            width=6,
            command=self._toggle_visibility,
        )
        self.toggle_button.pack(
            side=tk.RIGHT,
            padx=(5, 0),
        )

    def _toggle_visibility(self) -> None:
        self._visible = not self._visible

        self.entry.configure(
            show="" if self._visible else "*"
        )

        self.toggle_button.configure(
            text="Hide" if self._visible else "Show"
        )

    def get(self) -> str:
        return self.entry.get()

    def set(self, value: str) -> None:
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)

    def clear(self) -> None:
        self.entry.delete(0, tk.END)