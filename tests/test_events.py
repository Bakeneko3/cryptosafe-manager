"""Tests for src/core/events.py."""

from datetime import datetime

from src.core.events import (
    ClipboardCleared,
    ClipboardCopied,
    EntryCreated,
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

    bus.subscribe(EntryCreated, handler)
    bus.publish(EntryCreated(entry_id="x"))

    assert len(received) == 1
    assert isinstance(received[0], EntryCreated)


def test_publish_does_not_call_other_event_handlers() -> None:
    bus = EventBus()
    received = []

    bus.subscribe(EntryCreated, lambda e: received.append(e))
    bus.publish(EntryDeleted(entry_id="x"))

    assert received == []


def test_multiple_handlers_receive_event() -> None:
    bus = EventBus()
    calls = []

    bus.subscribe(EntryUpdated, lambda e: calls.append("a"))
    bus.subscribe(EntryUpdated, lambda e: calls.append("b"))
    bus.publish(EntryUpdated(entry_id="x"))

    assert calls == ["a", "b"]


def test_subscribe_does_not_duplicate_handlers() -> None:
    bus = EventBus()
    calls = []

    def handler(event: Event) -> None:
        calls.append(1)

    bus.subscribe(EntryCreated, handler)
    bus.subscribe(EntryCreated, handler)
    bus.publish(EntryCreated(entry_id="x"))

    assert calls == [1]


def test_unsubscribe_removes_handler() -> None:
    bus = EventBus()
    calls = []

    def handler(event: Event) -> None:
        calls.append(1)

    bus.subscribe(EntryCreated, handler)
    bus.unsubscribe(EntryCreated, handler)
    bus.publish(EntryCreated(entry_id="x"))

    assert calls == []


def test_unsubscribe_unknown_handler_is_noop() -> None:
    bus = EventBus()

    def handler(event: Event) -> None:
        pass

    bus.unsubscribe(EntryCreated, handler)


def test_handler_can_subscribe_during_publish() -> None:
    bus = EventBus()
    calls = []

    def second(event: Event) -> None:
        calls.append("second")

    def first(event: Event) -> None:
        calls.append("first")
        bus.subscribe(EntryCreated, second)

    bus.subscribe(EntryCreated, first)
    bus.publish(EntryCreated(entry_id="x"))

    assert calls == ["first"]

    bus.publish(EntryCreated(entry_id="y"))
    assert calls == ["first", "first", "second"]


# --------------------------------------------------------------------- #
# Entry events
# --------------------------------------------------------------------- #


def test_entry_created_has_id_and_timestamp() -> None:
    e = EntryCreated(entry_id="abc")
    assert e.entry_id == "abc"
    assert isinstance(e.timestamp, datetime)


def test_entry_updated_has_id_and_timestamp() -> None:
    e = EntryUpdated(entry_id="abc")
    assert e.entry_id == "abc"
    assert isinstance(e.timestamp, datetime)


def test_entry_deleted_defaults_to_soft() -> None:
    e = EntryDeleted(entry_id="abc")
    assert e.soft is True


def test_entry_deleted_hard() -> None:
    e = EntryDeleted(entry_id="abc", soft=False)
    assert e.soft is False


# --------------------------------------------------------------------- #
# User events
# --------------------------------------------------------------------- #


def test_user_logged_in_has_timestamp() -> None:
    event = UserLoggedIn()
    assert isinstance(event.timestamp, datetime)


def test_user_logged_out_has_reason() -> None:
    assert UserLoggedOut().reason == "manual"
    assert UserLoggedOut(reason="auto-lock").reason == "auto-lock"


def test_user_events_are_distinct_types() -> None:
    bus = EventBus()
    received = []

    bus.subscribe(UserLoggedIn, lambda e: received.append("in"))
    bus.subscribe(UserLoggedOut, lambda e: received.append("out"))

    bus.publish(UserLoggedIn())
    bus.publish(UserLoggedOut())

    assert received == ["in", "out"]