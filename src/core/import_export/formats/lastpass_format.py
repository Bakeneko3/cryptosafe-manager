"""
LastPass CSV format handler.

Columns:
    url,username,password,extra,name,grouping,fav

https://support.lastpass.com/help/import-your-passwords
"""

from __future__ import annotations

import csv
import io

from src.core.import_export.formats.helpers import (
    empty_entry,
    ensure_entry_shape,
)


LASTPASS_COLUMNS = ("url", "username", "password", "extra", "name", "grouping", "fav")


class LastPassFormatError(Exception):
    """Raised when a LastPass CSV file cannot be parsed."""


def render(entries: list[dict]) -> bytes:
    """Serialize entries as a LastPass-compatible CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(LASTPASS_COLUMNS)

    for e in entries:
        e = ensure_entry_shape(e)
        writer.writerow(
            [
                e["url"],
                e["username"],
                e["password"],
                e["notes"],
                e["title"],
                e["category"],
                "0",
            ]
        )
    return buf.getvalue().encode("utf-8")


def parse(data: bytes) -> list[dict]:
    """Parse a LastPass CSV export into plaintext entries."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LastPassFormatError(
            f"LastPass CSV is not valid UTF-8: {exc}"
        ) from exc

    buf = io.StringIO(text)
    reader = csv.reader(buf)

    try:
        header = next(reader)
    except StopIteration:
        raise LastPassFormatError("Empty LastPass CSV.")

    header = [h.strip().lower() for h in header]
    required = {"url", "username", "password", "name"}
    if not required.issubset(set(header)):
        raise LastPassFormatError(
            f"LastPass CSV missing required columns: {required - set(header)}"
        )

    index = {h: i for i, h in enumerate(header)}

    entries: list[dict] = []
    for row in reader:
        if not row:
            continue
        entry = empty_entry()
        entry["url"] = _at(row, index.get("url"))
        entry["username"] = _at(row, index.get("username"))
        entry["password"] = _at(row, index.get("password"))
        entry["notes"] = _at(row, index.get("extra"))
        entry["title"] = _at(row, index.get("name"))
        entry["category"] = _at(row, index.get("grouping"))
        entries.append(ensure_entry_shape(entry))
    return entries


def _at(row: list[str], idx: int | None) -> str:
    if idx is None or idx >= len(row):
        return ""
    return row[idx] or ""