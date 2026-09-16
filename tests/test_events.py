from src.core.events import (
    ClipboardCleared,
    EntryAdded,
    EventBus,
    UserLoggedIn,
)


def test_event_can_be_published():
    bus = EventBus()
    received = []

    def handler(event):
        received.append(event)

    bus.subscribe(EntryAdded, handler)

    event = EntryAdded()
    bus.publish(event)

    assert received == [event]


def test_different_event_types_are_separate():
    bus = EventBus()
    received = []

    def handler(event):
        received.append(event)

    bus.subscribe(EntryAdded, handler)

    bus.publish(EntryAdded())
    bus.publish(UserLoggedIn())
    bus.publish(ClipboardCleared())

    assert len(received) == 1
    assert isinstance(received[0], EntryAdded)


def test_unsubscribe():
    bus = EventBus()
    received = []

    def handler(event):
        received.append(event)

    bus.subscribe(EntryAdded, handler)
    bus.unsubscribe(EntryAdded, handler)

    bus.publish(EntryAdded())

    assert received == []