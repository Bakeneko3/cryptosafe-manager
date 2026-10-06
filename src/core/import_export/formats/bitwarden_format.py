"""
Bitwarden JSON format handler.

Follows the public Bitwarden export schema as documented at
https://bitwarden.com/help/condition-bitwarden-import/

Supported item types:
    type 1 -- Login
    type 2 -- Secure Note
    type 3 -- Card (partially: name and notes only)
    type 4 -- Identity (partially)

Only Login and Secure Note carry meaningful data for us; other types
are imported as empty entries with a title, so the user does not lose
the fact that the item existed.
"""

from __future__ import annotations

import json
from typing import Any

from src.core.import_export.formats.helpers import (
    empty_entry,
    ensure_entry_shape,
)


class BitwardenFormatError(Exception):
    """Raised when a Bitwarden JSON file cannot be parsed."""


def render(entries: list[dict]) -> bytes:
    """
    Serialize entries into a Bitwarden-compatible JSON document.

    We produce only Login items (type 1). Folders are not emitted.
    """
    folders: list[dict] = []
    items: list[dict] = []

    for idx, e in enumerate(entries):
        e = ensure_entry_shape(e)
        items.append(
            {
                "id": None,
                "organizationId": None,
                "folderId": None,
                "type": 1,
                "name": e["title"],
                "notes": e["notes"],
                "favorite": False,
                "login": {
                    "uris": (
                        [{"match": None, "uri": e["url"]}]
                        if e["url"]
                        else []
                    ),
                    "username": e["username"],
                    "password": e["password"],
                    "totp": None,
                },
            }
        )

    doc = {"folders": folders, "items": items}
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")


def parse(data: bytes) -> list[dict]:
    """Parse a Bitwarden JSON export into plaintext entries."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BitwardenFormatError(f"Invalid JSON: {exc}") from exc

    if not isinstance(doc, dict) or "items" not in doc:
        raise BitwardenFormatError("Not a Bitwarden export (missing 'items').")

    folders_by_id = {
        f.get("id"): f.get("name", "")
        for f in doc.get("folders", [])
        if isinstance(f, dict)
    }

    entries: list[dict] = []
    for item in doc["items"]:
        if not isinstance(item, dict):
            continue
        entries.append(_item_to_entry(item, folders_by_id))
    return entries


# --------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------- #


def _item_to_entry(item: dict, folders: dict) -> dict:
    entry = empty_entry()
    entry["title"] = str(item.get("name") or "")
    entry["notes"] = str(item.get("notes") or "")

    folder_id = item.get("folderId")
    if folder_id and folder_id in folders:
        entry["category"] = str(folders[folder_id])

    item_type = item.get("type")
    if item_type == 1:
        login = item.get("login") or {}
        entry["username"] = str(login.get("username") or "")
        entry["password"] = str(login.get("password") or "")
        uris = login.get("uris") or []
        if uris and isinstance(uris, list):
            first = uris[0]
            if isinstance(first, dict):
                entry["url"] = str(first.get("uri") or "")

    return ensure_entry_shape(entry)