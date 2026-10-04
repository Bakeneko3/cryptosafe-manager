"""
In-memory search and filtering over decrypted vault entries.

Entries are stored encrypted in the database and are decrypted by
EntryManager before reaching this module. Search therefore runs over
plain dicts and stays completely independent of storage.

Supported query syntax (SEARCH-1):

    "work"                  -- free-text: matches title, username, url, notes
    "title:work"            -- field filter (title/username/url/notes/category/tag)
    "category:Work"         -- same, but on category
    "tag:important"         -- tag filter
    "title:work tag:urgent" -- multiple filters combined with AND

Fuzzy matching (typo tolerance) is provided by difflib.SequenceMatcher
with a configurable similarity threshold. It is opt-in via
`fuzzy=True` because it is slower than plain substring search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Callable, Iterable


# --------------------------------------------------------------------- #
# Filter model
# --------------------------------------------------------------------- #


ALLOWED_FIELDS = {"title", "username", "url", "notes", "category", "tag"}


@dataclass(frozen=True)
class SearchQuery:
    """Parsed representation of a user query."""

    free_text: str = ""
    fields: tuple[tuple[str, str], ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.free_text and not self.fields


def parse_query(raw: str) -> SearchQuery:
    """
    Parse a user query string into a SearchQuery.

    Tokens of the form `field:value` become field filters when `field`
    is recognised. Everything else becomes free text. Unknown fields
    are treated as free text (never silently dropped).
    """
    if not raw or not raw.strip():
        return SearchQuery()

    free_parts: list[str] = []
    fields: list[tuple[str, str]] = []

    for token in raw.split():
        if ":" in token:
            field, _, value = token.partition(":")
            field = field.lower()
            if field in ALLOWED_FIELDS and value:
                fields.append((field, value))
                continue
        free_parts.append(token)

    return SearchQuery(
        free_text=" ".join(free_parts),
        fields=tuple(fields),
    )


# --------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------- #


Matcher = Callable[[str, str, float], bool]


def _field_value(entry: dict, field: str) -> str:
    if field == "tag":
        return str(entry.get("tags", ""))
    return str(entry.get(field, ""))


def _substring_match(haystack: str, needle: str, threshold: float = 0.0) -> bool:
    return needle.lower() in haystack.lower()


def _fuzzy_match(haystack: str, needle: str, threshold: float = 0.8) -> bool:
    """
    Return True if `needle` is similar enough to any token in haystack.

    The haystack is split on non-word characters so that strings like
    "alice@example.com" become tokens ["alice", "example", "com"] and
    each token can be compared independently.
    """
    if not needle:
        return True
    haystack_lower = haystack.lower()
    needle_lower = needle.lower()

    if needle_lower in haystack_lower:
        return True

    for token in re.split(r"\W+", haystack_lower):
        if not token:
            continue
        ratio = SequenceMatcher(None, token, needle_lower).ratio()
        if ratio >= threshold:
            return True
    return False


# --------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------- #


def _entry_matches(
    entry: dict,
    query: SearchQuery,
    matcher: Matcher,
    threshold: float,
) -> bool:
    for field, value in query.fields:
        if not matcher(_field_value(entry, field), value, threshold):
            return False

    if query.free_text:
        searchable = (
            _field_value(entry, "title"),
            _field_value(entry, "username"),
            _field_value(entry, "url"),
            _field_value(entry, "notes"),
            _field_value(entry, "category"),
            _field_value(entry, "tags"),
        )
        if not any(matcher(h, query.free_text, threshold) for h in searchable):
            return False

    return True


def search_entries(
    entries: Iterable[dict],
    raw_query: str,
    *,
    fuzzy: bool = False,
    fuzzy_threshold: float = 0.8,
) -> list[dict]:
    """
    Filter `entries` according to the query.

    Without `fuzzy`, uses case-insensitive substring matching.
    With `fuzzy=True`, falls back to SequenceMatcher for typo tolerance.
    """
    query = parse_query(raw_query)
    if query.is_empty:
        return list(entries)

    matcher: Matcher = _fuzzy_match if fuzzy else _substring_match

    result: list[dict] = []
    for entry in entries:
        if _entry_matches(entry, query, matcher, fuzzy_threshold):
            result.append(entry)
    return result