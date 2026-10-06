"""
Generic CSV format (FMT-3).

Columns: title,username,password,url,notes,category,tags

Special characters and line breaks are handled by the csv module
(RFC 4180 quoting).
"""

from __future__ import annotations

import csv
import io

from src.core.import_export.formats.helpers import (
    ensure_entry_shape,
)


CSV_COLUMNS = (
    "title",
    "username",
    "password",
    "url",
    "notes",
    "category",
    "tags",
)


class CsvFormatError(Exception):
    """Raised when a CSV file cannot be parsed."""


def render(entries: list[dict]) -> bytes:
    """Serialize entries as CSV (UTF-8)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()
    for e in entries:
        row = ensure_entry_shape(e)
        writer.writerow({k: row.get(k, "") for k in CSV_COLUMNS})
    return buf.getvalue().encode("utf-8")


def parse(data: bytes) -> list[dict]:
    """Parse a CSV file into plaintext entries."""
    try:
        text = data.decode("utf-8-sig")  # tolerate BOM
    except UnicodeDecodeError as exc:
        raise CsvFormatError(f"CSV is not valid UTF-8: {exc}") from exc

    buf = io.StringIO(text)
    try:
        reader = csv.DictReader(buf)
        if reader.fieldnames is None:
            raise CsvFormatError("CSV has no header row.")
        rows = list(reader)
    except csv.Error as exc:
        raise CsvFormatError(f"Malformed CSV: {exc}") from exc

    entries: list[dict] = []
    for row in rows:
        entry = {k: (row.get(k) or "") for k in CSV_COLUMNS}
        entries.append(ensure_entry_shape(entry))
    return entries