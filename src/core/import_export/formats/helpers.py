"""
Shared helpers for all format handlers.
"""

from __future__ import annotations


ENTRY_FIELDS = (
    "title",
    "username",
    "password",
    "url",
    "notes",
    "category",
    "tags",
)


def empty_entry() -> dict:
    return {field: "" for field in ENTRY_FIELDS}


def ensure_entry_shape(entry: dict) -> dict:
    """Return a dict with exactly the standard entry fields, all strings."""
    return {
        field: _to_text(entry.get(field, ""))
        for field in ENTRY_FIELDS
    }


def _to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return str(value)