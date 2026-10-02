"""Tests for src/core/events.py."""

from datetime import datetime

from src.core.events import (
    ClipboardCleared,
    ClipboardCopied,
    EntryAdded,
    EntryDeleted,
    EntryUpdated,
    Event,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
)


# --------------------------------------------------------------------- #
# EventBus basics
# --------------------------------------------------------------------- #


def test_publish_calls_subscribed_handler() -> None:
    bus = EventBus()
    received = []

    def handler(event: Event) -> None:
        received.append(event)

    bus.subscribe(EntryAdded, handler)
    bus.publish(EntryAdded())

    assert len(received) == 1
    assert isinstance(received[0], EntryAdded)


def test_publish_does_not_call_other_event_handlers() -> None:
    bus = EventBus()
    received = []

    bus.subscribe(EntryAdded, lambda e: received.append(e))
    bus.publish(EntryDeleted())

    assert received == []


def test_multiple_handlers_receive_event() -> None:
    bus = EventBus()
    calls = []

    bus.subscribe(EntryUpdated, lambda e: calls.append("a"))
    bus.subscribe(EntryUpdated, lambda e: calls.append("b"))
    bus.publish(EntryUpdated())

    assert calls == ["a", "b"]


def test_subscribe_does_not_duplicate_handlers() -> None:
    bus = EventBus()
    calls = []

    def handler(event: Event) -> None:
        calls.append(1)

    bus.subscribe(EntryAdded, handler)
    bus.subscribe(EntryAdded, handler)
    bus.publish(EntryAdded())

    assert calls == [1]


def test_unsubscribe_removes_handler() -> None:
    bus = EventBus()
    calls = []

    def handler(event: Event) -> None:
        calls.append(1)

    bus.subscribe(EntryAdded, handler)
    bus.unsubscribe(EntryAdded, handler)
    bus.publish(EntryAdded())

    assert calls == []


def test_unsubscribe_unknown_handler_is_noop() -> None:
    bus = EventBus()

    def handler(event: Event) -> None:
        pass

    bus.unsubscribe(EntryAdded, handler)  # no error


def test_handler_can_subscribe_during_publish() -> None:
    """Publishing must not break when handlers mutate subscriptions."""
    bus = EventBus()
    calls = []

    def second(event: Event) -> None:
        calls.append("second")

    def first(event: Event) -> None:
        calls.append("first")
        bus.subscribe(EntryAdded, second)

    bus.subscribe(EntryAdded, first)
    bus.publish(EntryAdded())

    assert calls == ["first"]

    bus.publish(EntryAdded())
    assert calls == ["first", "first", "second"]


# --------------------------------------------------------------------- #
# UserLoggedIn / UserLoggedOut (AUTH-2)
# --------------------------------------------------------------------- #


def test_user_logged_in_has_timestamp() -> None:
    event = UserLoggedIn()
    assert isinstance(event.timestamp, datetime)


def test_user_logged_in_accepts_explicit_timestamp() -> None:
    ts = datetime(2026, 1, 1, 12, 0, 0)
    event = UserLoggedIn(timestamp=ts)
    assert event.timestamp == ts


def test_user_logged_out_has_timestamp_and_reason() -> None:
    event = UserLoggedOut()
    assert isinstance(event.timestamp, datetime)
    assert event.reason == "manual"


def test_user_logged_out_accepts_reason() -> None:
    event = UserLoggedOut(reason="auto-lock")
    assert event.reason == "auto-lock"


def test_user_events_are_distinct_types() -> None:
    bus = EventBus()
    received = []

    bus.subscribe(UserLoggedIn, lambda e: received.append("in"))
    bus.subscribe(UserLoggedOut, lambda e: received.append("out"))

    bus.publish(UserLoggedIn())
    bus.publish(UserLoggedOut())

    assert received == ["in", "out"]