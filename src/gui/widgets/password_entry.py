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

        self._bind_clipboard()

    # ------------------------------------------------------------------ #
    # Clipboard shortcuts
    # ------------------------------------------------------------------ #
    # Only paste and select-all are supported. Copy/cut are intentionally
    # not wired: this widget masks its content, and copying the masked
    # text is useless while copying the real text would defeat the mask.

    def _bind_clipboard(self) -> None:
        self.entry.bind("<Control-v>", self._on_paste)
        self.entry.bind("<Control-V>", self._on_paste)
        self.entry.bind("<Control-a>", self._on_select_all)
        self.entry.bind("<Control-A>", self._on_select_all)

    def _on_paste(self, event: tk.Event) -> str:
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return "break"

        # Workaround: ttk.Entry with show="*" returns selection indices
        # in a different coordinate space than the actual content, so
        # delete(index) operates on the wrong characters. Temporarily
        # unmask while manipulating content, then restore.
        current_show = self.entry.cget("show")
        self.entry.configure(show="")
        try:
            try:
                start = self.entry.index("sel.first")
                end = self.entry.index("sel.last")
                self.entry.delete(start, end)
            except tk.TclError:
                pass
            self.entry.insert(tk.INSERT, text)
        finally:
            self.entry.configure(show=current_show)

        return "break"

    def _on_select_all(self, event: tk.Event) -> str:
        self.entry.selection_range(0, tk.END)
        self.entry.icursor(tk.END)
        return "break"

    # ------------------------------------------------------------------ #
    # Visibility
    # ------------------------------------------------------------------ #

    def _toggle_visibility(self) -> None:
        self._visible = not self._visible

        self.entry.configure(
            show="" if self._visible else "*"
        )

        self.toggle_button.configure(
            text="Hide" if self._visible else "Show"
        )

    # ------------------------------------------------------------------ #
    # API
    # ------------------------------------------------------------------ #

    def get(self) -> str:
        return self.entry.get()

    def set(self, value: str) -> None:
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)

    def clear(self) -> None:
        self.entry.delete(0, tk.END)

    def focus_set(self) -> None:
        self.entry.focus_set()