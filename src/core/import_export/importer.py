"""
Vault importer.

Detects the format of a file, decrypts it if necessary, validates every
entry (types, sanitization, size), and writes the results to the vault
using one of three modes:

    merge   -- add new entries; skip duplicates
    replace -- clear the vault and import everything
    dry-run -- validate and report without writing anything

Every import is logged to import_export_history and (optionally) to
the audit log.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from src.core.import_export.formats import (
    bitwarden_format,
    csv_format,
    json_format,
    lastpass_format,
)

if TYPE_CHECKING:
    from src.core.audit.audit_logger import AuditLogger
    from src.core.key_manager import KeyManager
    from src.core.vault.entry_manager import EntryManager


# --------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------- #


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
IMPORT_TIMEOUT_SECONDS = 30

# Anti-malware patterns (SEC-5). Case-insensitive substring match on
# the raw decoded entry strings.
_MALICIOUS_PATTERNS = (
    "<script",
    "javascript:",
    "=cmd|",
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "<?php",
    "eval(",
)

# Magic bytes for common executable formats.
_EXECUTABLE_MAGIC = (
    b"MZ",            # Windows PE
    b"\x7fELF",       # Linux ELF
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary
)


# --------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------- #


class ImportError_(Exception):
    """Base error for import failures."""


class ImportFormatError(ImportError_):
    """File format could not be detected or parsed."""


class ImportDecryptionError(ImportError_):
    """Decryption failed."""


class ImportSecurityError(ImportError_):
    """File rejected for security reasons."""


class ImportTimeoutError(ImportError_):
    """Import took longer than the allowed timeout."""


# --------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------- #


@dataclass
class ImportSummary:
    format: str
    encryption: str
    mode: str
    total_parsed: int = 0
    added: int = 0
    updated: int = 0
    skipped_duplicates: int = 0
    skipped_malicious: int = 0
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "encryption": self.encryption,
            "mode": self.mode,
            "total_parsed": self.total_parsed,
            "added": self.added,
            "updated": self.updated,
            "skipped_duplicates": self.skipped_duplicates,
            "skipped_malicious": self.skipped_malicious,
            "errors": list(self.errors),
            "dry_run": self.dry_run,
        }


# --------------------------------------------------------------------- #
# Importer
# --------------------------------------------------------------------- #


class VaultImporter:
    def __init__(
        self,
        entry_manager: "EntryManager",
        key_manager: "KeyManager",
        *,
        audit_logger: "AuditLogger | None" = None,
    ) -> None:
        self._em = entry_manager
        self._km = key_manager
        self._audit = audit_logger

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def import_file(
        self,
        path: str | Path,
        *,
        mode: str = "merge",
        password: str | None = None,
        private_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
        format_hint: str | None = None,
        max_file_size: int = MAX_FILE_SIZE,
        timeout: int = IMPORT_TIMEOUT_SECONDS,
    ) -> ImportSummary:
        if mode not in ("merge", "replace", "dry-run"):
            raise ImportError_(f"Unsupported import mode: {mode}")

        file_path = Path(path)
        if not file_path.exists():
            raise ImportError_(f"File not found: {file_path}")

        size = file_path.stat().st_size
        if size > max_file_size:
            raise ImportSecurityError(
                f"File too large: {size} bytes (limit {max_file_size})."
            )

        raw = file_path.read_bytes()

        # Detect gzip.
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception as exc:
                raise ImportFormatError(f"Gzip decompression failed: {exc}") from exc

        start = time.monotonic()

        # Decode the outer envelope (JSON with "cryptosafe_export": true)
        # when present; otherwise treat the file as a plain format file.
        try:
            envelope = json.loads(raw.decode("utf-8"))
            is_cryptosafe = isinstance(envelope, dict) and envelope.get("cryptosafe_export")
        except Exception:
            envelope = None
            is_cryptosafe = False

        if is_cryptosafe:
            fmt, encryption = self._read_envelope_metadata(envelope)
            plaintext = self._decrypt_envelope(
                envelope, password, private_key_pem, private_key_password
            )
        else:
            fmt = format_hint or self._detect_format(raw)
            encryption = "none"
            plaintext = raw

        if time.monotonic() - start > timeout:
            raise ImportTimeoutError("Import timed out during decryption.")

        # Parse plaintext into entries.
        parser = self._parser_for(fmt)
        try:
            entries = parser(plaintext)
        except Exception as exc:
            raise ImportFormatError(f"Failed to parse {fmt}: {exc}") from exc

        summary = ImportSummary(format=fmt, encryption=encryption, mode=mode)
        summary.total_parsed = len(entries)

        # Validate & sanitize; detect duplicates.
        existing = self._collect_existing_titles()
        valid_entries: list[dict] = []
        for entry in entries:
            if time.monotonic() - start > timeout:
                raise ImportTimeoutError(
                    "Import timed out during validation."
                )
            if not self._is_safe(entry):
                summary.skipped_malicious += 1
                continue
            title = (entry.get("title") or "").strip()
            if not title:
                summary.errors.append("Entry with empty title skipped.")
                continue
            if title.lower() in existing and mode == "merge":
                summary.skipped_duplicates += 1
                continue
            valid_entries.append(entry)

        summary.added = len(valid_entries)

        if mode == "dry-run":
            summary.dry_run = True
            self._record_history(summary, file_size=size)
            return summary

        # Write.
        if mode == "replace":
            with self._km._db.transaction():
                self._km._db.execute_in_transaction("DELETE FROM vault_entries")
                for entry in valid_entries:
                    self._em.create_entry(entry)
        else:  # merge
            for entry in valid_entries:
                try:
                    self._em.create_entry(entry)
                except Exception as exc:
                    summary.errors.append(f"Failed to add '{entry.get('title')}': {exc}")
                    summary.added -= 1

        self._record_history(summary, file_size=size)
        return summary

    # ------------------------------------------------------------------ #
    # Envelope handling
    # ------------------------------------------------------------------ #

    @staticmethod
    def _read_envelope_metadata(envelope: dict) -> tuple[str, str]:
        fmt = envelope.get("format", "json")
        enc = envelope.get("encryption", {})
        algorithm = enc.get("algorithm", "unknown")
        if algorithm == "AES-256-GCM":
            return fmt, "password"
        if algorithm == "hybrid":
            return fmt, "public_key"
        if algorithm == "none":
            return fmt, "none"
        return fmt, str(algorithm)

    def _decrypt_envelope(
        self,
        envelope: dict,
        password: str | None,
        private_key_pem: bytes | None,
        private_key_password: bytes | None,
    ) -> bytes:
        enc = envelope.get("encryption") or {}
        algorithm = enc.get("algorithm", "none")
        data = envelope.get("data")
        if not isinstance(data, str):
            raise ImportFormatError("Envelope missing 'data' field.")
        blob = base64.b64decode(data)

        # Verify integrity hash if present.
        integrity = envelope.get("integrity") or {}
        expected_hash = integrity.get("hash")

        if algorithm == "none":
            plaintext = blob
        elif algorithm == "AES-256-GCM":
            if not password:
                raise ImportDecryptionError("Password required for this file.")
            salt = base64.b64decode(enc["salt"])
            nonce = base64.b64decode(enc["nonce"])
            iterations = int(enc.get("iterations", 100_000))
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )
            key = kdf.derive(password.encode("utf-8"))
            try:
                plaintext = AESGCM(key).decrypt(nonce, blob, None)
            except Exception as exc:
                raise ImportDecryptionError(
                    f"Decryption failed: wrong password or tampered file ({exc})"
                ) from exc
        elif algorithm == "hybrid":
            if not private_key_pem:
                raise ImportDecryptionError("Private key required for this file.")
            from src.core.import_export.key_exchange import decrypt_with_private_key
            try:
                plaintext = decrypt_with_private_key(
                    blob, private_key_pem, private_key_password
                )
            except Exception as exc:
                raise ImportDecryptionError(
                    f"Public-key decryption failed: {exc}"
                ) from exc
        else:
            raise ImportFormatError(f"Unsupported encryption: {algorithm}")

        if expected_hash:
            actual = hashlib.sha256(plaintext).hexdigest()
            if actual != expected_hash:
                raise ImportSecurityError(
                    "Integrity hash mismatch — file has been tampered with."
                )

        return plaintext

    # ------------------------------------------------------------------ #
    # Format detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _detect_format(raw: bytes) -> str:
        # Strip BOM.
        text = raw.decode("utf-8", errors="ignore").lstrip("\ufeff").strip()

        if not text:
            raise ImportFormatError("Empty file.")

        # JSON?
        if text[:1] in "{[":
            try:
                doc = json.loads(text)
                if isinstance(doc, dict) and "items" in doc:
                    return "bitwarden"
                return "json"
            except Exception:
                raise ImportFormatError("Malformed JSON.")

        # CSV — look at the header.
        first_line = text.splitlines()[0].lower()
        if "grouping" in first_line and "extra" in first_line:
            return "lastpass"
        if "title" in first_line and "password" in first_line:
            return "csv"

        raise ImportFormatError("Could not detect file format.")

    @staticmethod
    def _parser_for(fmt: str):
        if fmt == "json":
            return json_format.parse
        if fmt == "csv":
            return csv_format.parse
        if fmt == "bitwarden":
            return bitwarden_format.parse
        if fmt == "lastpass":
            return lastpass_format.parse
        raise ImportFormatError(f"Unsupported format: {fmt}")

    # ------------------------------------------------------------------ #
    # Sanitization (SEC-5)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_safe(entry: dict) -> bool:
        for key, value in entry.items():
            if not isinstance(value, str):
                continue
            lowered = value.lower()
            for pattern in _MALICIOUS_PATTERNS:
                if pattern in lowered:
                    return False
            # Reject strings that look like binary executables.
            if value.startswith(tuple(m.decode("latin-1") for m in _EXECUTABLE_MAGIC)):
                return False
        return True

    def _collect_existing_titles(self) -> set[str]:
        try:
            entries = self._em.get_all_entries()
            return {(e.get("title") or "").strip().lower() for e in entries}
        except Exception:
            return set()

    # ------------------------------------------------------------------ #
    # History & audit
    # ------------------------------------------------------------------ #

    def _record_history(self, summary: ImportSummary, *, file_size: int) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            self._km._db.execute(
                """
                INSERT INTO import_export_history
                    (operation_type, format, encryption, entry_count,
                     file_size, checksum, verification_status, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "import",
                    summary.format,
                    summary.encryption,
                    summary.added,
                    file_size,
                    None,
                    "ok" if summary.ok else "errors",
                    timestamp,
                    json.dumps(summary.to_dict()),
                ),
            )
        except Exception:
            pass

        if self._audit is not None:
            try:
                self._audit.log_event(
                    "import_completed",
                    source="importer",
                    severity="INFO" if summary.ok else "WARN",
                    details=summary.to_dict(),
                )
            except Exception:
                pass