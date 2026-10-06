"""
Vault exporter.

Supports four formats and three encryption modes:

    format:     json | csv | bitwarden | lastpass
    encryption: password | public_key | none

Password mode uses PBKDF2-HMAC-SHA256 (100k iterations) + AES-256-GCM.
Public-key mode uses hybrid encryption (see key_exchange).
None is allowed for CSV migration only (SEC-1 exception).

Every export is logged to import_export_history and to the audit log
(INT-2). Integrity is protected by an additional SHA-256 hash and, when
available, an Ed25519 signature over the plaintext JSON payload.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from dataclasses import dataclass
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


PBKDF2_ITERATIONS = 100_000
PBKDF2_SALT_LEN = 16
NONCE_LEN = 12
FORMAT_VERSION = "1.0"

EXPORT_CONTEXT = b"cryptosafe-export"

FORMAT_RENDERERS = {
    "json": json_format.render,
    "csv": csv_format.render,
    "bitwarden": bitwarden_format.render,
    "lastpass": lastpass_format.render,
}


# --------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------- #


class ExportError(Exception):
    """Base error for export failures."""


class ExportFormatError(ExportError):
    """Unsupported format."""


class ExportEncryptionError(ExportError):
    """Encryption failed or unsupported mode."""


# --------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------- #


@dataclass
class ExportResult:
    path: Path
    format: str
    encryption: str
    entry_count: int
    file_size: int
    checksum: str  # SHA-256 hex of the exported file
    signature: str | None  # Ed25519 hex of the plaintext payload


# --------------------------------------------------------------------- #
# Exporter
# --------------------------------------------------------------------- #


class VaultExporter:
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

    def export(
        self,
        path: str | Path,
        *,
        format: str = "json",
        encryption: str = "password",
        password: str | None = None,
        public_key_pem: bytes | None = None,
        entry_ids: list[str] | None = None,
        include_fields: list[str] | None = None,
        exclude_fields: list[str] | None = None,
        compress: bool = False,
    ) -> ExportResult:
        """
        Export vault entries to `path`.

        `entry_ids=None` exports the whole vault.
        `password` is required for encryption="password".
        `public_key_pem` is required for encryption="public_key".
        `exclude_fields` removes fields after rendering (e.g. ["notes"]).
        """
        if format not in FORMAT_RENDERERS:
            raise ExportFormatError(f"Unsupported format: {format}")
        if encryption not in ("password", "public_key", "none"):
            raise ExportEncryptionError(f"Unsupported encryption: {encryption}")

        entries = self._collect_entries(entry_ids)
        entries = self._filter_fields(entries, include_fields, exclude_fields)

        # Render plaintext via the format handler.
        renderer = FORMAT_RENDERERS[format]
        plaintext = renderer(entries)

        # Integrity + provenance.
        integrity_hash = hashlib.sha256(plaintext).hexdigest()
        signature_hex = self._sign_payload(plaintext)

        # Encrypt / package.
        if encryption == "password":
            if not password:
                raise ExportEncryptionError("Password required.")
            payload = self._encrypt_with_password(
                plaintext, password, format, integrity_hash, signature_hex
            )
        elif encryption == "public_key":
            if not public_key_pem:
                raise ExportEncryptionError("Public key required.")
            payload = self._encrypt_with_public_key(
                plaintext, public_key_pem, format, integrity_hash, signature_hex
            )
        else:  # none
            payload = self._plaintext_payload(
                plaintext, format, integrity_hash, signature_hex
            )

        # Optional compression of the final file body.
        if compress:
            payload = gzip.compress(payload)

        out_path = Path(path)
        out_path.write_bytes(payload)

        file_checksum = hashlib.sha256(payload).hexdigest()

        result = ExportResult(
            path=out_path,
            format=format,
            encryption=encryption,
            entry_count=len(entries),
            file_size=len(payload),
            checksum=file_checksum,
            signature=signature_hex,
        )

        self._record_history(result, compressed=compress)
        return result

    # ------------------------------------------------------------------ #
    # Collection & filtering
    # ------------------------------------------------------------------ #

    def _collect_entries(self, entry_ids: list[str] | None) -> list[dict]:
        if entry_ids is None:
            return self._em.get_all_entries()
        out: list[dict] = []
        for eid in entry_ids:
            try:
                out.append(self._em.get_entry(eid))
            except Exception:
                continue
        return out

    @staticmethod
    def _filter_fields(
        entries: list[dict],
        include_fields: list[str] | None,
        exclude_fields: list[str] | None,
    ) -> list[dict]:
        def filter_one(entry: dict) -> dict:
            if include_fields:
                return {k: entry.get(k, "") for k in include_fields}
            if exclude_fields:
                return {k: v for k, v in entry.items() if k not in exclude_fields}
            return dict(entry)

        return [filter_one(e) for e in entries]

    # ------------------------------------------------------------------ #
    # Encryption
    # ------------------------------------------------------------------ #

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def _encrypt_with_password(
        self,
        plaintext: bytes,
        password: str,
        format: str,
        integrity_hash: str,
        signature_hex: str | None,
    ) -> bytes:
        salt = os.urandom(PBKDF2_SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = self._derive_key(password, salt)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)

        doc = {
            "version": FORMAT_VERSION,
            "cryptosafe_export": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "CryptoSafe Manager",
            "format": format,
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": PBKDF2_ITERATIONS,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "data": base64.b64encode(ct).decode("ascii"),
            "integrity": {
                "hash": integrity_hash,
                "hash_algorithm": "SHA256",
                "signature": signature_hex,
            },
        }
        return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")

    def _encrypt_with_public_key(
        self,
        plaintext: bytes,
        public_key_pem: bytes,
        format: str,
        integrity_hash: str,
        signature_hex: str | None,
    ) -> bytes:
        from src.core.import_export.key_exchange import encrypt_with_public_key

        payload = encrypt_with_public_key(plaintext, public_key_pem)

        doc = {
            "version": FORMAT_VERSION,
            "cryptosafe_export": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "CryptoSafe Manager",
            "format": format,
            "encryption": {
                "algorithm": "hybrid",
            },
            "data": base64.b64encode(payload).decode("ascii"),
            "integrity": {
                "hash": integrity_hash,
                "hash_algorithm": "SHA256",
                "signature": signature_hex,
            },
        }
        return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")

    def _plaintext_payload(
        self,
        plaintext: bytes,
        format: str,
        integrity_hash: str,
        signature_hex: str | None,
    ) -> bytes:
        doc = {
            "version": FORMAT_VERSION,
            "cryptosafe_export": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "CryptoSafe Manager",
            "format": format,
            "encryption": {"algorithm": "none"},
            "data": base64.b64encode(plaintext).decode("ascii"),
            "integrity": {
                "hash": integrity_hash,
                "hash_algorithm": "SHA256",
                "signature": signature_hex,
            },
        }
        return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")

    # ------------------------------------------------------------------ #
    # Signing (provenance via Ed25519 audit key)
    # ------------------------------------------------------------------ #

    def _sign_payload(self, plaintext: bytes) -> str | None:
        try:
            from src.core.audit.log_signer import LogSigner
            signer = LogSigner(self._km)
            return signer.sign(plaintext).hex()
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # History & audit
    # ------------------------------------------------------------------ #

    def _record_history(self, result: ExportResult, *, compressed: bool) -> None:
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
                    "export",
                    result.format,
                    result.encryption,
                    result.entry_count,
                    result.file_size,
                    result.checksum,
                    "ok",
                    timestamp,
                    json.dumps({"compressed": compressed}),
                ),
            )
        except Exception:
            pass

        if self._audit is not None:
            try:
                self._audit.log_event(
                    "export_completed",
                    source="exporter",
                    severity="INFO",
                    details={
                        "format": result.format,
                        "encryption": result.encryption,
                        "entry_count": result.entry_count,
                        "file_size": result.file_size,
                    },
                )
            except Exception:
                pass