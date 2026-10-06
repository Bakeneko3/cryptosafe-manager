"""
Secure entry sharing.

Produces a share package for a single vault entry, encrypted either
with a user-chosen password or with the recipient's public key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

if TYPE_CHECKING:
    from src.core.audit.audit_logger import AuditLogger
    from src.core.import_export.key_exchange import KeyPair
    from src.core.key_manager import KeyManager
    from src.core.vault.entry_manager import EntryManager


PACKAGE_VERSION = "1.0"
PBKDF2_ITERATIONS = 100_000
PBKDF2_SALT_LEN = 16
NONCE_LEN = 12

SHAREABLE_FIELDS = (
    "title",
    "username",
    "password",
    "url",
    "notes",
    "category",
)

MIN_EXPIRATION_DAYS = 1
MAX_EXPIRATION_DAYS = 30


class SharingError(Exception):
    pass


class SharingValidationError(SharingError):
    pass


class SharingEncryptionError(SharingError):
    pass


@dataclass
class Permissions:
    read: bool = True
    edit: bool = False
    expires_in_days: int = 7

    def validate(self) -> None:
        if not (MIN_EXPIRATION_DAYS <= self.expires_in_days <= MAX_EXPIRATION_DAYS):
            raise SharingValidationError(
                f"expires_in_days must be in "
                f"[{MIN_EXPIRATION_DAYS}, {MAX_EXPIRATION_DAYS}]"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "read": self.read,
            "edit": self.edit,
            "expires_in_days": self.expires_in_days,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Permissions":
        return cls(
            read=bool(data.get("read", True)),
            edit=bool(data.get("edit", False)),
            expires_in_days=int(data.get("expires_in_days", 7)),
        )


@dataclass
class SharePackage:
    share_id: str
    package_bytes: bytes
    package_hash: str
    expires_at: str
    encryption_method: str

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_bytes(self.package_bytes)
        return p


class SharingService:
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
    # Share creation
    # ------------------------------------------------------------------ #

    def create_share(
        self,
        entry_id: str,
        *,
        recipient: str = "",
        permissions: Permissions | None = None,
        password: str | None = None,
        public_key_pem: bytes | None = None,
    ) -> SharePackage:
        perms = permissions or Permissions()
        perms.validate()

        if (password is None) == (public_key_pem is None):
            raise SharingValidationError(
                "Provide exactly one of password or public_key_pem."
            )

        entry = self._em.get_entry(entry_id)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=perms.expires_in_days)
        share_id = str(uuid.uuid4())

        shared_entry = {k: str(entry.get(k, "")) for k in SHAREABLE_FIELDS}

        header = {
            "version": PACKAGE_VERSION,
            "share_id": share_id,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "recipient": recipient,
            "permissions": perms.to_dict(),
        }

        plaintext = json.dumps(
            {"header": header, "entry": shared_entry},
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")

        if password is not None:
            encryption_method = "password"
            payload = self._encrypt_password(plaintext, password, header)
        else:
            encryption_method = "public_key"
            payload = self._encrypt_public_key(plaintext, public_key_pem, header)

        integrity_hash = hashlib.sha256(plaintext).hexdigest()

        package = {
            "cryptosafe_share": True,
            **payload,
            "integrity": {
                "hash": integrity_hash,
                "hash_algorithm": "SHA256",
            },
        }
        package_bytes = json.dumps(
            package, indent=2, ensure_ascii=False
        ).encode("utf-8")

        package_hash = hashlib.sha256(package_bytes).hexdigest()

        self._record_share(
            share_id=share_id,
            entry_id=entry_id,
            encryption_method=encryption_method,
            recipient=recipient,
            permissions=perms,
            expires_at=expires_at,
        )

        return SharePackage(
            share_id=share_id,
            package_bytes=package_bytes,
            package_hash=package_hash,
            expires_at=expires_at.isoformat(),
            encryption_method=encryption_method,
        )

    # ------------------------------------------------------------------ #
    # Recipient workflow
    # ------------------------------------------------------------------ #

    def open_share(
        self,
        package_path: str | Path,
        *,
        password: str | None = None,
        private_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
    ) -> dict:
        raw = Path(package_path).read_bytes()
        return self.open_share_bytes(
            raw,
            password=password,
            private_key_pem=private_key_pem,
            private_key_password=private_key_password,
        )

    def open_share_bytes(
        self,
        raw: bytes,
        *,
        password: str | None = None,
        private_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
    ) -> dict:
        try:
            package = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise SharingEncryptionError(f"Invalid package: {exc}") from exc

        if not package.get("cryptosafe_share"):
            raise SharingEncryptionError("Not a CryptoSafe share package.")

        enc = package.get("encryption") or {}
        algorithm = enc.get("algorithm")

        if algorithm == "AES-256-GCM":
            if not password:
                raise SharingEncryptionError("Password required.")
            plaintext = self._decrypt_password(package, password)
        elif algorithm == "hybrid":
            if not private_key_pem:
                raise SharingEncryptionError("Private key required.")
            plaintext = self._decrypt_public_key(
                package, private_key_pem, private_key_password
            )
        else:
            raise SharingEncryptionError(f"Unsupported encryption: {algorithm}")

        expected = (package.get("integrity") or {}).get("hash")
        if expected:
            actual = hashlib.sha256(plaintext).hexdigest()
            if actual != expected:
                raise SharingEncryptionError(
                    "Integrity hash mismatch — package was tampered with."
                )

        try:
            return json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise SharingEncryptionError(f"Malformed package body: {exc}") from exc

    def import_shared_entry(
        self,
        package_path: str | Path,
        *,
        password: str | None = None,
        private_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
        save_to_vault: bool = True,
    ) -> dict:
        body = self.open_share(
            package_path,
            password=password,
            private_key_pem=private_key_pem,
            private_key_password=private_key_password,
        )
        entry = body.get("entry") or {}

        if save_to_vault:
            self._em.create_entry(entry)

        if self._audit is not None:
            try:
                self._audit.log_event(
                    "share_imported",
                    source="sharing_service",
                    severity="INFO",
                    details={
                        "share_id": (body.get("header") or {}).get("share_id"),
                        "saved": save_to_vault,
                    },
                )
            except Exception:
                pass

        return entry

    # ------------------------------------------------------------------ #
    # Encryption internals
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

    def _encrypt_password(
        self,
        plaintext: bytes,
        password: str,
        header: dict,
    ) -> dict:
        salt = os.urandom(PBKDF2_SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = self._derive_key(password, salt)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return {
            "header": header,
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": PBKDF2_ITERATIONS,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "data": base64.b64encode(ct).decode("ascii"),
        }

    def _encrypt_public_key(
        self,
        plaintext: bytes,
        public_key_pem: bytes | None,
        header: dict,
    ) -> dict:
        if not public_key_pem:
            raise SharingEncryptionError("Public key required.")
        from src.core.import_export.key_exchange import encrypt_with_public_key
        blob = encrypt_with_public_key(plaintext, public_key_pem)
        return {
            "header": header,
            "encryption": {"algorithm": "hybrid"},
            "data": base64.b64encode(blob).decode("ascii"),
        }

    def _decrypt_password(self, package: dict, password: str) -> bytes:
        enc = package["encryption"]
        salt = base64.b64decode(enc["salt"])
        nonce = base64.b64decode(enc["nonce"])
        iterations = int(enc.get("iterations", PBKDF2_ITERATIONS))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode("utf-8"))
        ct = base64.b64decode(package["data"])
        try:
            return AESGCM(key).decrypt(nonce, ct, None)
        except Exception as exc:
            raise SharingEncryptionError(
                f"Decryption failed: {exc}"
            ) from exc

    def _decrypt_public_key(
        self,
        package: dict,
        private_key_pem: bytes,
        private_key_password: bytes | None,
    ) -> bytes:
        from src.core.import_export.key_exchange import decrypt_with_private_key
        blob = base64.b64decode(package["data"])
        try:
            return decrypt_with_private_key(
                blob, private_key_pem, private_key_password
            )
        except Exception as exc:
            raise SharingEncryptionError(
                f"Public-key decryption failed: {exc}"
            ) from exc

    # ------------------------------------------------------------------ #
    # Persistence & audit
    # ------------------------------------------------------------------ #

    def _record_share(
        self,
        *,
        share_id: str,
        entry_id: str,
        encryption_method: str,
        recipient: str,
        permissions: Permissions,
        expires_at: datetime,
    ) -> None:
        shared_at = datetime.now(timezone.utc).isoformat()
        try:
            self._km._db.execute(
                """
                INSERT INTO shared_entries
                    (shared_id, original_entry_id, encryption_method,
                     recipient_info, permissions, shared_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    share_id,
                    entry_id,
                    encryption_method,
                    recipient,
                    json.dumps(permissions.to_dict()),
                    shared_at,
                    expires_at.isoformat(),
                ),
            )
        except Exception:
            pass

        if self._audit is not None:
            try:
                self._audit.log_event(
                    "share_created",
                    source="sharing_service",
                    severity="INFO",
                    details={
                        "share_id": share_id,
                        "recipient": recipient,
                        "encryption_method": encryption_method,
                        "expires_at": expires_at.isoformat(),
                    },
                )
            except Exception:
                pass