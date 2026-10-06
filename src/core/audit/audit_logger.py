"""
Tamper-evident audit logger.

Replaces the Sprint 1/2 plaintext AuditLogger with a signed, hash-chained
log:

    sequence_number : monotonically increasing row id
    previous_hash   : SHA-256 hex of the previous entry's plaintext JSON
                      (or 64 zeros for the genesis entry)
    entry_data      : the JSON payload of the entry, AES-GCM encrypted
                      with a key derived from the master password
                      (context "cryptosafe-audit-enc")
    signature       : Ed25519 signature over the plaintext JSON payload
                      using a key derived with context "cryptosafe-audit-signing"

The signature covers the plaintext payload, not the encrypted blob.
Encryption-at-rest is a separate concern (DB-2): the verifier decrypts
first, then verifies the signature.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.audit.log_signer import LogSigner
from src.core.events import (
    ClipboardCleared,
    ClipboardCopied,
    EntryCreated,
    EntryDeleted,
    EntryUpdated,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
)
from src.database.db import Database

if TYPE_CHECKING:
    from src.core.key_manager import KeyManager


# --------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------- #


GENESIS_HASH = "0" * 64
NONCE_SIZE = 12
USER_ID_LOCAL = "local"

# Keys that must never appear in log details.
_SENSITIVE_KEYS = {
    "password",
    "encryption_key",
    "master_password",
    "signing_key",
    "log_key",
    "secret",
    "token",
}


# --------------------------------------------------------------------- #
# Sanitization (LOG-3)
# --------------------------------------------------------------------- #


def _sanitize_details(details: dict[str, Any]) -> dict[str, Any]:
    """
    Replace sensitive values with "[REDACTED]" (LOG-3).
    Recurses into nested dicts and lists.
    """
    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: ("[REDACTED]" if k.lower() in _SENSITIVE_KEYS else walk(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return walk(details)


# --------------------------------------------------------------------- #
# Severity inference
# --------------------------------------------------------------------- #


def _severity_for(event_type: str) -> str:
    if event_type in ("user_login_failed", "tampering_detected"):
        return "CRITICAL"
    if event_type in ("user_logged_out", "entry_deleted"):
        return "WARN"
    return "INFO"


# --------------------------------------------------------------------- #
# AuditLogger
# --------------------------------------------------------------------- #


class AuditLogger:
    """
    Subscribes to security-relevant events and writes signed,
    hash-chained entries to the audit_log table.

    Requires the vault to be unlocked: the signing and log-encryption
    keys come from KeyManager. Events received while the vault is
    locked are dropped silently; the vault lock itself is logged by
    the caller after unlock, not before.
    """

    def __init__(
        self,
        database: Database,
        event_bus: EventBus,
        key_manager: "KeyManager | None" = None,
    ) -> None:
        self.database = database
        self.event_bus = event_bus
        self.key_manager = key_manager

        self._subscribe()

    # ------------------------------------------------------------------ #
    # Subscriptions
    # ------------------------------------------------------------------ #

    def _subscribe(self) -> None:
        self.event_bus.subscribe(UserLoggedIn, self._handle_user_logged_in)
        self.event_bus.subscribe(UserLoggedOut, self._handle_user_logged_out)

        self.event_bus.subscribe(EntryCreated, self._handle_entry_created)
        self.event_bus.subscribe(EntryUpdated, self._handle_entry_updated)
        self.event_bus.subscribe(EntryDeleted, self._handle_entry_deleted)

        self.event_bus.subscribe(ClipboardCopied, self._handle_clipboard_copied)
        self.event_bus.subscribe(ClipboardCleared, self._handle_clipboard_cleared)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def log_event(
        self,
        event_type: str,
        *,
        source: str = "audit_logger",
        severity: str | None = None,
        details: dict[str, Any] | None = None,
        entry_id: str | None = None,
    ) -> None:
        """
        Log an arbitrary event. Used for events that are not published
        on the EventBus (startup, shutdown, tampering, etc.).
        """
        self._write(
            event_type=event_type,
            source=source,
            severity=severity or _severity_for(event_type),
            details=details or {},
            entry_id=entry_id,
        )

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #

    def _handle_user_logged_in(self, event: UserLoggedIn) -> None:
        self._write(
            event_type="user_logged_in",
            source="key_manager",
            severity="INFO",
            details={},
        )

    def _handle_user_logged_out(self, event: UserLoggedOut) -> None:
        self._write(
            event_type="user_logged_out",
            source="key_manager",
            severity="INFO",
            details={"reason": event.reason},
        )

    def _handle_entry_created(self, event: EntryCreated) -> None:
        self._write(
            event_type="entry_created",
            source="entry_manager",
            severity="INFO",
            details={},
            entry_id=event.entry_id,
        )

    def _handle_entry_updated(self, event: EntryUpdated) -> None:
        self._write(
            event_type="entry_updated",
            source="entry_manager",
            severity="INFO",
            details={},
            entry_id=event.entry_id,
        )

    def _handle_entry_deleted(self, event: EntryDeleted) -> None:
        self._write(
            event_type="entry_deleted",
            source="entry_manager",
            severity="WARN",
            details={"soft": event.soft},
            entry_id=event.entry_id,
        )

    def _handle_clipboard_copied(self, event: ClipboardCopied) -> None:
        self._write(
            event_type="clipboard_copied",
            source="clipboard_service",
            severity="INFO",
            details={
                "data_type": event.data_type,
                "timeout": event.timeout,
            },
            entry_id=event.source_entry_id,
        )

    def _handle_clipboard_cleared(self, event: ClipboardCleared) -> None:
        self._write(
            event_type="clipboard_cleared",
            source="clipboard_service",
            severity="INFO",
            details={"reason": event.reason},
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _can_write(self) -> bool:
        return self.key_manager is not None and self.key_manager.cache.unlocked

    def _is_log_empty(self) -> bool:
        row = self.database.fetch_one("SELECT 1 FROM audit_log LIMIT 1")
        return row is None

    def _write(
        self,
        *,
        event_type: str,
        source: str,
        severity: str,
        details: dict[str, Any],
        entry_id: str | None = None,
    ) -> None:
        if not self._can_write():
            return

        # Lazy genesis: create the first entry before writing anything else.
        if event_type != "system_genesis" and self._is_log_empty():
            self._write(
                event_type="system_genesis",
                source="audit_logger",
                severity="INFO",
                details={"message": "Audit log initialized"},
            )

        # Build signer (raises if the vault somehow became locked).
        try:
            signer = LogSigner(self.key_manager)
        except Exception:
            return

        log_enc_key = self.key_manager.derive_audit_log_encryption_key()
        if log_enc_key is None:
            return

        timestamp = datetime.now(timezone.utc).isoformat()
        sanitized = _sanitize_details(details)

        # Previous hash for the chain (hash of the previous plaintext JSON).
        prev_row = self.database.fetch_one(
            "SELECT entry_data FROM audit_log ORDER BY sequence_number DESC LIMIT 1"
        )
        if prev_row is None:
            previous_hash = GENESIS_HASH
        else:
            previous_hash = self._compute_previous_hash(
                prev_row["entry_data"], log_enc_key
            )

        payload = {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "user_id": USER_ID_LOCAL,
            "entry_id": entry_id,
            "details": sanitized,
            "previous_hash": previous_hash,
        }

        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        payload_bytes = payload_json.encode("utf-8")

        # Sign the plaintext payload with Ed25519.
        signature_hex = signer.sign(payload_bytes).hex()

        # AES-GCM encrypt the payload for at-rest protection (DB-2).
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(bytes(log_enc_key))
        ct_and_tag = aesgcm.encrypt(nonce, payload_bytes, None)
        encrypted_blob = nonce + ct_and_tag

        # Persist the entry.
        self.database.execute(
            """
            INSERT INTO audit_log (
                timestamp, event_type, severity, source, user_id,
                entry_id, previous_hash, entry_data, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event_type,
                severity,
                source,
                USER_ID_LOCAL,
                entry_id,
                previous_hash,
                encrypted_blob,
                signature_hex,
            ),
        )

        # Store the public key once for external verification.
        self._ensure_public_key(signer)

    def _ensure_public_key(self, signer: LogSigner) -> None:
        existing = self.database.fetch_one(
            "SELECT public_key FROM audit_public_key WHERE id = 1"
        )
        if existing is not None:
            return
        self.database.execute(
            """
            INSERT INTO audit_public_key (id, public_key, created_at)
            VALUES (1, ?, ?)
            """,
            (signer.public_key_hex(), datetime.now(timezone.utc).isoformat()),
        )

    def _compute_previous_hash(
        self,
        encrypted_blob: bytes,
        log_enc_key: bytes,
    ) -> str:
        """
        Decrypt the previous entry's blob and compute its plaintext hash.
        Falls back to GENESIS_HASH if the previous entry cannot be read.
        """
        try:
            blob = bytes(encrypted_blob)
            nonce = blob[:NONCE_SIZE]
            ct_and_tag = blob[NONCE_SIZE:]
            aesgcm = AESGCM(bytes(log_enc_key))
            plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
            return hashlib.sha256(plaintext).hexdigest()
        except (InvalidTag, ValueError):
            return GENESIS_HASH