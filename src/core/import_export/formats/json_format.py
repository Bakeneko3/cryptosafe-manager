"""
Native CryptoSafe JSON format.

The clear-text JSON document produced by this module contains only
plaintext entries — encryption is applied on top of it by the exporter
(see FMT-1 in the Sprint 6 requirements).

Structure:

    {
        "version": "1.0",
        "cryptosafe_export": true,
        "timestamp": "2026-...Z",
        "source": "CryptoSafe Manager",
        "entry_count": N,
        "entries": [
            {
                "title": ..., "username": ..., "password": ...,
                "url": ..., "notes": ..., "category": ..., "tags": ...
            },
            ...
        ]
    }
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from src.core.import_export.formats.helpers import (
    empty_entry,
    ensure_entry_shape,
)


FORMAT_VERSION = "1.0"


class JsonFormatError(Exception):
    """Raised when a JSON document cannot be parsed."""


def render(entries: list[dict]) -> bytes:
    """Serialize plaintext entries into a CryptoSafe JSON document."""
    doc = {
        "version": FORMAT_VERSION,
        "cryptosafe_export": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "CryptoSafe Manager",
        "entry_count": len(entries),
        "entries": [ensure_entry_shape(e) for e in entries],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")


def parse(data: bytes) -> list[dict]:
    """Parse a CryptoSafe JSON document into plaintext entries."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JsonFormatError(f"Invalid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise JsonFormatError("Top-level JSON must be an object.")

    if not doc.get("cryptosafe_export"):
        raise JsonFormatError("Not a CryptoSafe export file.")

    entries = doc.get("entries")
    if not isinstance(entries, list):
        raise JsonFormatError("Missing or invalid 'entries' field.")

    return [ensure_entry_shape(e) for e in entries if isinstance(e, dict)]