from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AppState:
    locked: bool = True
    clipboard_content: bytes | None = None
    clipboard_cleared_at: datetime | None = None
    last_activity: datetime | None = None


class StateManager:
    def __init__(self) -> None:
        self._state = AppState()

    @property
    def state(self) -> AppState:
        return self._state

    def lock(self) -> None:
        self._state.locked = True
        self.clear_clipboard()

    def unlock(self) -> None:
        self._state.locked = False
        self.update_activity()

    def is_locked(self) -> bool:
        return self._state.locked

    def set_clipboard_content(self, content: bytes) -> None:
        self._state.clipboard_content = content

    def get_clipboard_content(self) -> bytes | None:
        return self._state.clipboard_content

    def clear_clipboard(self) -> None:
        self._state.clipboard_content = None
        self._state.clipboard_cleared_at = datetime.now()

    def update_activity(self) -> None:
        self._state.last_activity = datetime.now()