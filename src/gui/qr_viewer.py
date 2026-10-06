"""
QR code viewer.
"""

from __future__ import annotations

import io
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.core.import_export.qr_service import (
    QRService,
    QRError,
)


MAX_QR_DISPLAY_PX = 500


class QRViewer(tk.Toplevel):
    """Simple modal viewer for one or more QR codes."""

    def __init__(self, master, payload: bytes, title: str = "QR Code") -> None:
        super().__init__(master)

        self.payload = payload
        self.service = QRService()

        self.title(f"CryptoSafe Manager — {title}")
        self.resizable(False, False)

        self._current = 0
        self._chunks: list = []
        self._photo = None
        self._pil_image = None

        self._create_widgets()
        self._generate()
        self._center_on_screen()

        self.transient(master)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.bind("<Escape>", lambda _e: self.destroy())

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _create_widgets(self) -> None:
        c = ttk.Frame(self, padding=16)
        c.pack(fill=tk.BOTH, expand=True)

        self.image_label = ttk.Label(c)
        self.image_label.pack()

        self.meta_label = ttk.Label(c, text="", foreground="gray")
        self.meta_label.pack(pady=(8, 6))

        nav = ttk.Frame(c)
        nav.pack(fill=tk.X)
        self.prev_btn = ttk.Button(nav, text="← Prev", command=self._prev)
        self.prev_btn.pack(side=tk.LEFT)
        self.next_btn = ttk.Button(nav, text="Next →", command=self._next)
        self.next_btn.pack(side=tk.LEFT, padx=(6, 0))

        ttk.Button(
            nav, text="Save all…", command=self._save_all
        ).pack(side=tk.RIGHT)
        ttk.Button(
            nav, text="Close", command=self.destroy
        ).pack(side=tk.RIGHT, padx=(0, 6))

    def _center_on_screen(self) -> None:
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"+{x}+{y}")

    # ------------------------------------------------------------------ #
    # Generate / render
    # ------------------------------------------------------------------ #

    def _generate(self) -> None:
        try:
            self._chunks = self.service.generate(self.payload)
        except QRError as exc:
            messagebox.showerror("QR generation failed", str(exc), parent=self)
            self.destroy()
            return

        self._current = 0
        self._render()

    def _render(self) -> None:
        if not self._chunks:
            return

        chunk = self._chunks[self._current]

        from PIL import Image, ImageTk

        img = Image.open(io.BytesIO(chunk.png_bytes))

        # Downscale to fit the screen.
        img.thumbnail(
            (MAX_QR_DISPLAY_PX, MAX_QR_DISPLAY_PX),
            Image.LANCZOS,
        )
        self._pil_image = img
        self._photo = ImageTk.PhotoImage(img)
        self.image_label.configure(image=self._photo)

        self.meta_label.configure(
            text=(
                f"Chunk {chunk.index} of {chunk.total}   "
                f"(PNG {len(chunk.png_bytes)} bytes)"
            )
        )

        state_prev = tk.NORMAL if self._current > 0 else tk.DISABLED
        state_next = (
            tk.NORMAL
            if self._current < len(self._chunks) - 1
            else tk.DISABLED
        )
        self.prev_btn.configure(state=state_prev)
        self.next_btn.configure(state=state_next)

    def _prev(self) -> None:
        if self._current > 0:
            self._current -= 1
            self._render()

    def _next(self) -> None:
        if self._current < len(self._chunks) - 1:
            self._current += 1
            self._render()

    def _save_all(self) -> None:
        directory = filedialog.askdirectory(
            parent=self, title="Select folder for QR PNG files"
        )
        if not directory:
            return

        out = Path(directory)
        saved: list[Path] = []
        for c in self._chunks:
            p = out / f"qr_{c.index:03d}_of_{c.total:03d}.png"
            p.write_bytes(c.png_bytes)
            saved.append(p)

        messagebox.showinfo(
            "Saved",
            f"Saved {len(saved)} file(s) to {directory}",
            parent=self,
        )