"""
Panic mode.

Emergency response system that executes a chain of user-provided
callbacks: lock the vault, wipe memory, clear the clipboard, close
windows, and optionally show a stealth message.

PanicMode is decoupled from the rest of the application: it knows
nothing about the vault or the clipboard. Callers register handlers.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


class PanicError(Exception):
    """Raised on invalid panic configuration."""


@dataclass
class PanicConfig:
    stealth_mode: bool = False
    show_fake_error_ui: bool = True
    log_callback: Callable[[dict], None] | None = None

    def validate(self) -> None:
        pass


class PanicMode:
    """
    Coordinates the panic response.

    Handlers are executed in the order they were registered. A failure
    in one handler does not stop the others.
    """

    def __init__(self, config: PanicConfig | None = None) -> None:
        self._config = config or PanicConfig()
        self._config.validate()

        self._lock = threading.RLock()
        self._handlers: list[tuple[str, Callable[[], None]]] = []
        self._activated_at: datetime | None = None
        self._activation_method: str | None = None

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def activated(self) -> bool:
        with self._lock:
            return self._activated_at is not None

    @property
    def activated_at(self) -> datetime | None:
        with self._lock:
            return self._activated_at

    @property
    def activation_method(self) -> str | None:
        with self._lock:
            return self._activation_method

    # ------------------------------------------------------------------ #
    # Handler registration
    # ------------------------------------------------------------------ #

    def register_handler(self, name: str, handler: Callable[[], None]) -> None:
        if not callable(handler):
            raise PanicError("handler must be callable")
        with self._lock:
            self._handlers = [(n, h) for (n, h) in self._handlers if n != name]
            self._handlers.append((name, handler))

    def unregister_handler(self, name: str) -> None:
        with self._lock:
            self._handlers = [(n, h) for (n, h) in self._handlers if n != name]

    def handler_names(self) -> list[str]:
        with self._lock:
            return [n for n, _ in self._handlers]

    # ------------------------------------------------------------------ #
    # Activation
    # ------------------------------------------------------------------ #

    def activate(self, method: str = "hotkey") -> dict:
        with self._lock:
            if self._activated_at is not None:
                return {
                    "already_activated": True,
                    "method": self._activation_method,
                }

            self._activated_at = datetime.now(timezone.utc)
            self._activation_method = method
            handlers = list(self._handlers)

        executed: list[str] = []
        failed: list[dict] = []

        for name, handler in handlers:
            try:
                handler()
                executed.append(name)
            except Exception as exc:
                failed.append({"name": name, "error": str(exc)})

        stealth_actions: list[str] = []
        if self._config.stealth_mode:
            try:
                self._show_fake_error()
                stealth_actions.append("fake_error")
            except Exception as exc:
                failed.append({"name": "stealth_fake_error", "error": str(exc)})

        summary = {
            "already_activated": False,
            "method": method,
            "timestamp": self._activated_at.isoformat(),
            "executed": executed,
            "failed": failed,
            "stealth_actions": stealth_actions,
        }

        self._log(summary)
        return summary

    # ------------------------------------------------------------------ #
    # Reset
    # ------------------------------------------------------------------ #

    def reset(self) -> None:
        with self._lock:
            self._activated_at = None
            self._activation_method = None

    # ------------------------------------------------------------------ #
    # Stealth
    # ------------------------------------------------------------------ #

    def _show_fake_error(self) -> None:
        if not self._config.show_fake_error_ui:
            return
        try:
            import tkinter.messagebox as mb

            mb.showerror(
                "Application Error",
                "The application has encountered an unexpected error "
                "and must close.",
            )
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #

    def _log(self, summary: dict) -> None:
        if self._config.log_callback is None:
            return
        try:
            self._config.log_callback(summary)
        except Exception:
            pass