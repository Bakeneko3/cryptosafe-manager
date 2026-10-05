from collections import defaultdict
from datetime import datetime
from typing import Callable, DefaultDict, Type


class Event:
    """Base class for application events."""


class EntryCreated(Event):
    """Published after a new vault entry has been stored."""

    def __init__(self, entry_id: str, timestamp: datetime | None = None) -> None:
        self.entry_id = entry_id
        self.timestamp = timestamp or datetime.now()


class EntryUpdated(Event):
    """Published after an existing vault entry has been modified."""

    def __init__(self, entry_id: str, timestamp: datetime | None = None) -> None:
        self.entry_id = entry_id
        self.timestamp = timestamp or datetime.now()


class EntryDeleted(Event):
    """Published after a vault entry has been deleted (hard or soft)."""

    def __init__(
        self,
        entry_id: str,
        soft: bool = True,
        timestamp: datetime | None = None,
    ) -> None:
        self.entry_id = entry_id
        self.soft = soft
        self.timestamp = timestamp or datetime.now()


class UserLoggedIn(Event):
    """Published after a successful login."""

    def __init__(self, timestamp: datetime | None = None) -> None:
        self.timestamp = timestamp or datetime.now()


class UserLoggedOut(Event):
    """Published after the user locks the vault or logs out."""

    def __init__(self, timestamp: datetime | None = None, reason: str = "manual") -> None:
        self.timestamp = timestamp or datetime.now()
        self.reason = reason


class ClipboardCopied(Event):
    """Published after data was copied to the system clipboard."""

    def __init__(
        self,
        data_type: str = "text",
        source_entry_id: str | None = None,
        timeout: int = 0,
        timestamp: datetime | None = None,
    ) -> None:
        self.data_type = data_type
        self.source_entry_id = source_entry_id
        self.timeout = timeout
        self.timestamp = timestamp or datetime.now()


class ClipboardCleared(Event):
    """Published after the clipboard was cleared."""

    def __init__(
        self,
        reason: str = "manual",
        timestamp: datetime | None = None,
    ) -> None:
        self.reason = reason
        self.timestamp = timestamp or datetime.now()


EventHandler = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: DefaultDict[
            Type[Event], list[EventHandler]
        ] = defaultdict(list)

    def subscribe(
        self,
        event_type: Type[Event],
        handler: EventHandler,
    ) -> None:
        if handler not in self._handlers[event_type]:
            self._handlers[event_type].append(handler)

    def unsubscribe(
        self,
        event_type: Type[Event],
        handler: EventHandler,
    ) -> None:
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        for handler in list(self._handlers[type(event)]):
            handler(event)