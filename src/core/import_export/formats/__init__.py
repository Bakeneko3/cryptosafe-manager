"""
Format handlers for import/export.

Each module exposes two functions:
    render(entries: list[dict]) -> bytes
    parse(data: bytes) -> list[dict]

Where an entry is a plain dict with keys:
    title, username, password, url, notes, category, tags
"""

from src.core.import_export.formats import (
    bitwarden_format,
    csv_format,
    json_format,
    lastpass_format,
)

__all__ = [
    "bitwarden_format",
    "csv_format",
    "json_format",
    "lastpass_format",
]