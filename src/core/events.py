from collections import defaultdict
from datetime import datetime
from typing import Callable, DefaultDict, Type


class Event:
    """Base class for application events."""


class EntryAdded(Event):
    pass


class EntryUpdated(Event):
    pass


class EntryDeleted(Event):
    pass


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
    pass


class ClipboardCleared(Event):
    pass


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