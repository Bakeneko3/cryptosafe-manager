"""
Vault entry CRUD controller.

Wraps per-entry encryption (AESGCMService), the database, and the event
bus into a single façade used by the GUI. Plaintext fields are serialized
to JSON, encrypted with the vault's current key, and stored as an opaque
BLOB in vault_entries.encrypted_data.

Wire envelope inside encrypted_data (ENC-4):
    nonce (12 B) || ciphertext || tag (16 B)

JSON payload structure (DATA-2, ENC-3):
    {
        "title":      str,
        "username":   str,
        "password":   str,
        "url":        str,
        "notes":      str,
        "category":   str,
        "version":    int,
        "created_at": ISO-8601 str,
        "updated_at": ISO-8601 str,
    }
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from src.core.vault.encryption_service import AESGCMService
from src.database.db import Database

if TYPE_CHECKING:
    from src.core.events import EventBus
    from src.core.key_manager import KeyManager


SOFT_DELETE_TTL_DAYS = 30
ENTRY_VERSION = 1


# --------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------- #


class VaultError(Exception):
    """Base class for vault operation failures."""


class VaultValidationError(VaultError):
    """Raised when entry data fails validation."""


class VaultOperationError(VaultError):
    """
    Raised on any operation failure whose details must not be leaked
    to the caller (SEC-4). Callers should show a generic message.
    """


# --------------------------------------------------------------------- #
# EntryManager
# --------------------------------------------------------------------- #


class EntryManager:
    def __init__(
        self,
        database: Database,
        key_manager: "KeyManager",
        event_bus: "EventBus | None" = None,
        *,
        encryption_service: AESGCMService | None = None,
    ) -> None:
        self._db = database
        self._km = key_manager
        self._events = event_bus
        self._crypto = encryption_service or AESGCMService(key_manager)

    # ------------------------------------------------------------------ #
    # CRUD-1: create
    # ------------------------------------------------------------------ #

    def create_entry(self, data: dict) -> str:
        """
        Create a new vault entry.

        Returns the UUID string of the created entry. Raises
        VaultValidationError on bad input, VaultOperationError on any
        storage or crypto failure (including a locked vault).
        """
        self._validate_create(data)

        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        payload = self._build_payload(data, entry_id, created_at=now)

        try:
            blob = self._encrypt_payload(payload)
        except RuntimeError as exc:
            # Raised by AESGCMService when the vault is locked.
            raise VaultOperationError("Vault is locked.") from exc

        tags = data.get("tags") or ""
        if not isinstance(tags, str):
            tags = ",".join(str(t) for t in tags)

        try:
            with self._db.transaction():
                self._db.execute_in_transaction(
                    """
                    INSERT INTO vault_entries
                        (id, encrypted_data, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (entry_id, blob, now, now, tags),
                )
        except Exception as exc:
            raise VaultOperationError("Failed to create entry.") from exc

        if self._events is not None:
            from src.core.events import EntryCreated
            self._events.publish(EntryCreated(entry_id=entry_id))

        return entry_id

    # ------------------------------------------------------------------ #
    # CRUD-1: read
    # ------------------------------------------------------------------ #

    def get_entry(self, entry_id: str) -> dict:
        """
        Retrieve and decrypt a single entry.

        Raises VaultOperationError on any failure, including "not found",
        to avoid leaking whether a given ID exists (SEC-4).
        """
        try:
            row = self._db.fetch_one(
                "SELECT encrypted_data, tags FROM vault_entries WHERE id = ?",
                (entry_id,),
            )
        except Exception as exc:
            raise VaultOperationError("Failed to load entry.") from exc

        if row is None:
            raise VaultOperationError("Failed to load entry.")

        try:
            payload = self._decrypt_payload(bytes(row["encrypted_data"]))
        except RuntimeError as exc:
            raise VaultOperationError("Vault is locked.") from exc
        except Exception as exc:
            raise VaultOperationError("Failed to load entry.") from exc

        payload["tags"] = row["tags"] or ""
        return payload

    def get_all_entries(self) -> list[dict]:
        """
        Retrieve and decrypt all vault entries.

        Entries that fail to decrypt (corrupted or wrong key) are
        skipped: one bad blob must not make the whole vault unreadable.
        """
        try:
            rows = self._db.fetch_all(
                """
                SELECT id, encrypted_data, tags, created_at, updated_at
                FROM vault_entries
                ORDER BY updated_at DESC
                """
            )
        except Exception as exc:
            raise VaultOperationError("Failed to load entries.") from exc

        result: list[dict] = []
        for row in rows:
            try:
                payload = self._decrypt_payload(bytes(row["encrypted_data"]))
            except Exception:
                # Skip corrupted/unreadable entries silently; caller gets
                # the rest. This must not raise (SEC-4: no leak).
                continue
            payload["tags"] = row["tags"] or ""
            result.append(payload)

        return result

    # ------------------------------------------------------------------ #
    # CRUD-1: update
    # ------------------------------------------------------------------ #

    def update_entry(self, entry_id: str, data: dict) -> dict:
        """
        Update an existing vault entry.

        Merges `data` into the current payload, updates updated_at,
        re-encrypts, and stores atomically. Returns the new payload.

        Raises VaultValidationError on bad input, VaultOperationError
        on any failure (including unknown ID, per SEC-4).
        """
        if not isinstance(data, dict):
            raise VaultValidationError("Entry data must be a dict.")

        try:
            current = self.get_entry(entry_id)
        except VaultOperationError:
            raise

        # Merge: only provided keys overwrite existing ones.
        merged = {**current}
        for key in ("title", "username", "password", "url", "notes", "category"):
            if key in data:
                merged[key] = str(data[key])

        if "title" in data and not str(data["title"]).strip():
            raise VaultValidationError("Title is required.")
        if "password" in data and not data["password"]:
            raise VaultValidationError("Password is required.")

        now = datetime.now(timezone.utc).isoformat()
        merged["updated_at"] = now

        # Persist a clean payload (strip tags — it lives in its own column).
        payload = self._build_payload(
            {k: v for k, v in merged.items() if k != "tags"},
            entry_id,
            created_at=merged.get("created_at", now),
            updated_at=now,
        )

        try:
            blob = self._encrypt_payload(payload)
        except RuntimeError as exc:
            raise VaultOperationError("Vault is locked.") from exc

        # Tags: update only if explicitly provided.
        if "tags" in data:
            raw = data["tags"] or ""
            tags = raw if isinstance(raw, str) else ",".join(str(t) for t in raw)
            try:
                with self._db.transaction():
                    self._db.execute_in_transaction(
                        """
                        UPDATE vault_entries
                        SET encrypted_data = ?, updated_at = ?, tags = ?
                        WHERE id = ?
                        """,
                        (blob, now, tags, entry_id),
                    )
            except Exception as exc:
                raise VaultOperationError("Failed to update entry.") from exc
        else:
            try:
                with self._db.transaction():
                    self._db.execute_in_transaction(
                        """
                        UPDATE vault_entries
                        SET encrypted_data = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (blob, now, entry_id),
                    )
            except Exception as exc:
                raise VaultOperationError("Failed to update entry.") from exc

        if self._events is not None:
            from src.core.events import EntryUpdated
            self._events.publish(EntryUpdated(entry_id=entry_id))

        payload["tags"] = data.get("tags", merged.get("tags", ""))
        return payload

    # ------------------------------------------------------------------ #
    # CRUD-1: delete (CRUD-4: soft delete)
    # ------------------------------------------------------------------ #

    def delete_entry(self, entry_id: str, soft_delete: bool = True) -> None:
        """
        Delete an entry.

        With soft_delete=True (default) the row is moved to
        deleted_entries and scheduled for expiry after SOFT_DELETE_TTL_DAYS.
        With soft_delete=False the row is removed permanently.

        Raises VaultOperationError on any failure (including unknown ID).
        """
        try:
            row = self._db.fetch_one(
                "SELECT encrypted_data, tags FROM vault_entries WHERE id = ?",
                (entry_id,),
            )
        except Exception as exc:
            raise VaultOperationError("Failed to delete entry.") from exc

        if row is None:
            raise VaultOperationError("Failed to delete entry.")

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        expires_iso = (now + timedelta(days=SOFT_DELETE_TTL_DAYS)).isoformat()

        try:
            with self._db.transaction():
                if soft_delete:
                    self._db.execute_in_transaction(
                        """
                        INSERT OR REPLACE INTO deleted_entries
                            (id, encrypted_data, deleted_at, expires_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (entry_id, row["encrypted_data"], now_iso, expires_iso),
                    )
                self._db.execute_in_transaction(
                    "DELETE FROM vault_entries WHERE id = ?",
                    (entry_id,),
                )
        except Exception as exc:
            raise VaultOperationError("Failed to delete entry.") from exc

        if self._events is not None:
            from src.core.events import EntryDeleted
            self._events.publish(EntryDeleted(entry_id=entry_id, soft=soft_delete))

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _validate_create(self, data: dict) -> None:
        if not isinstance(data, dict):
            raise VaultValidationError("Entry data must be a dict.")
        title = data.get("title")
        if not title or not str(title).strip():
            raise VaultValidationError("Title is required.")
        password = data.get("password")
        if not password:
            raise VaultValidationError("Password is required.")

    def _build_payload(
        self,
        data: dict,
        entry_id: str,
        *,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "id": entry_id,
            "title": str(data.get("title", "")),
            "username": str(data.get("username", "")),
            "password": str(data.get("password", "")),
            "url": str(data.get("url", "")),
            "notes": str(data.get("notes", "")),
            "category": str(data.get("category", "")),
            "version": ENTRY_VERSION,
            "created_at": created_at or now,
            "updated_at": updated_at or now,
        }

    def _encrypt_payload(self, payload: dict) -> bytes:
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self._crypto.encrypt(plaintext)

    def _decrypt_payload(self, blob: bytes) -> dict:
        plaintext = self._crypto.decrypt(blob)
        return json.loads(plaintext.decode("utf-8"))