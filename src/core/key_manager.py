"""
KeyManager facade for CryptoSafe Manager.

Wires together:
  * KeyDerivation   -- Argon2id, PBKDF2, and HKDF subkey derivation
  * KeyCache        -- in-memory encryption key storage
  * AuthSession     -- login/session/failure tracking
  * BackoffPolicy   -- exponential backoff on failed logins
  * Database        -- key_store persistence
  * EventBus        -- optional: publishes UserLoggedIn / UserLoggedOut

Public API:
    * is_initialized()
    * create_vault(password)
    * unlock(password)
    * lock(reason)
    * get_encryption_key()
    * change_password(current, new)
    * get_audit_salt() -> bytes | None
    * derive_audit_signing_key() -> bytes | None
    * derive_audit_log_encryption_key() -> bytes | None
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core import config
from src.core.crypto.authentication import (
    AuthSession,
    BackoffPolicy,
    PasswordStrengthValidator,
)
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyCache
from src.core.events import UserLoggedIn, UserLoggedOut
from src.database.db import Database

if TYPE_CHECKING:
    from src.core.events import EventBus


NONCE_SIZE = 12


# --------------------------------------------------------------------- #
# key_store record types (KEY-3, DB-1)
# --------------------------------------------------------------------- #


KEY_TYPE_AUTH_HASH = "auth_hash"
KEY_TYPE_ENC_SALT = "enc_salt"
KEY_TYPE_AUDIT_SALT = "audit_salt"
KEY_TYPE_PARAMS = "params"


@dataclass(frozen=True)
class VaultStatus:
    initialized: bool
    unlocked: bool


@dataclass(frozen=True)
class UnlockResult:
    success: bool
    backoff_delay: int = 0


# --------------------------------------------------------------------- #
# KeyManager
# --------------------------------------------------------------------- #


class KeyManager:
    def __init__(
        self,
        database: Database,
        *,
        event_bus: "EventBus | None" = None,
        key_derivation: KeyDerivation | None = None,
        key_cache: KeyCache | None = None,
        validator: PasswordStrengthValidator | None = None,
        backoff: BackoffPolicy | None = None,
    ) -> None:
        self._db = database
        self._events = event_bus
        self._kd = key_derivation or KeyDerivation()
        self._cache = key_cache or KeyCache()
        self._validator = validator or PasswordStrengthValidator()
        self._backoff = backoff or BackoffPolicy()
        self._session = AuthSession()

        # Keep the derived subkeys in memory while unlocked.
        self._audit_signing_key: bytes | None = None
        self._audit_log_enc_key: bytes | None = None
        self._master_key: bytes | None = None

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    @property
    def session(self) -> AuthSession:
        return self._session

    @property
    def cache(self) -> KeyCache:
        return self._cache

    @property
    def key_derivation(self) -> KeyDerivation:
        return self._kd

    def is_initialized(self) -> bool:
        row = self._db.fetch_one(
            "SELECT 1 FROM key_store WHERE key_type = ? LIMIT 1",
            (KEY_TYPE_AUTH_HASH,),
        )
        return row is not None

    def status(self) -> VaultStatus:
        return VaultStatus(
            initialized=self.is_initialized(),
            unlocked=self._cache.unlocked,
        )

    def get_encryption_key(self) -> bytearray | None:
        return self._cache.get()

    # ------------------------------------------------------------------ #
    # Audit subkeys (CRY-2, ARC-3)
    # ------------------------------------------------------------------ #

    def get_audit_salt(self) -> bytes | None:
        row = self._db.fetch_one(
            "SELECT key_data FROM key_store WHERE key_type = ? LIMIT 1",
            (KEY_TYPE_AUDIT_SALT,),
        )
        if row is None:
            return None
        return bytes(row["key_data"])

    def derive_audit_signing_key(self) -> bytes | None:
        """
        Return the Ed25519 seed (32 bytes) for audit log signing.
        The value is cached while the vault is unlocked.
        """
        if not self._cache.unlocked:
            return None
        if self._audit_signing_key is not None:
            return self._audit_signing_key
        if self._master_key is None:
            return None
        self._audit_signing_key = self._kd.derive_signing_key(self._master_key)
        return self._audit_signing_key

    def derive_audit_log_encryption_key(self) -> bytes | None:
        if not self._cache.unlocked:
            return None
        if self._audit_log_enc_key is not None:
            return self._audit_log_enc_key
        if self._master_key is None:
            return None
        self._audit_log_enc_key = self._kd.derive_log_encryption_key(self._master_key)
        return self._audit_log_enc_key

    # ------------------------------------------------------------------ #
    # First-run: create vault
    # ------------------------------------------------------------------ #

    def create_vault(self, password: str) -> None:
        if self.is_initialized():
            raise ValueError("Vault is already initialized.")

        result = self._validator.validate(password)
        if not result.valid:
            raise ValueError(
                "Password does not meet policy: "
                + "; ".join(result.reasons)
            )

        auth_hash = self._kd.create_auth_hash(password)
        enc_salt = self._kd.generate_salt(config.PBKDF2_SALT_LEN)
        audit_salt = self._kd.generate_salt(config.PBKDF2_SALT_LEN)
        params = self._build_params_snapshot()

        with self._db.transaction():
            self._db.execute_in_transaction(
                "INSERT INTO key_store (key_type, key_data, version) VALUES (?, ?, ?)",
                (KEY_TYPE_AUTH_HASH, auth_hash.encode("utf-8"), config.KEY_STORE_VERSION),
            )
            self._db.execute_in_transaction(
                "INSERT INTO key_store (key_type, key_data, version) VALUES (?, ?, ?)",
                (KEY_TYPE_ENC_SALT, enc_salt, config.KEY_STORE_VERSION),
            )
            self._db.execute_in_transaction(
                "INSERT INTO key_store (key_type, key_data, version) VALUES (?, ?, ?)",
                (KEY_TYPE_AUDIT_SALT, audit_salt, config.KEY_STORE_VERSION),
            )
            self._db.execute_in_transaction(
                "INSERT INTO key_store (key_type, key_data, version) VALUES (?, ?, ?)",
                (KEY_TYPE_PARAMS, json.dumps(params).encode("utf-8"), config.KEY_STORE_VERSION),
            )

        master_key = self._kd.derive_encryption_key(password, enc_salt)
        self._master_key = master_key
        self._cache.store(master_key)

        self._session.record_login()
        if self._events is not None:
            self._events.publish(UserLoggedIn())

    # ------------------------------------------------------------------ #
    # Login / logout
    # ------------------------------------------------------------------ #

    def unlock(self, password: str) -> UnlockResult:
        if not self.is_initialized():
            raise ValueError("Vault is not initialized.")

        auth_row = self._db.fetch_one(
            "SELECT key_data FROM key_store WHERE key_type = ? LIMIT 1",
            (KEY_TYPE_AUTH_HASH,),
        )
        salt_row = self._db.fetch_one(
            "SELECT key_data FROM key_store WHERE key_type = ? LIMIT 1",
            (KEY_TYPE_ENC_SALT,),
        )
        if auth_row is None or salt_row is None:
            raise RuntimeError("Vault is corrupted: missing key material.")

        stored_hash = auth_row["key_data"].decode("utf-8")
        enc_salt = bytes(salt_row["key_data"])

        if not self._kd.verify_password(password, stored_hash):
            attempts = self._session.record_failure()
            return UnlockResult(
                success=False,
                backoff_delay=self._backoff.delay_for(attempts),
            )

        master_key = self._kd.derive_encryption_key(password, enc_salt)
        self._master_key = master_key
        self._cache.store(master_key)

        self._session.record_login()
        if self._events is not None:
            self._events.publish(UserLoggedIn())
        return UnlockResult(success=True, backoff_delay=0)

    def lock(self, reason: str = "manual") -> None:
        self._cache.lock()
        self._session.record_logout()

        # Wipe cached subkeys.
        if self._audit_signing_key is not None:
            self._audit_signing_key = b"\x00" * len(self._audit_signing_key)
        if self._audit_log_enc_key is not None:
            self._audit_log_enc_key = b"\x00" * len(self._audit_log_enc_key)
        if self._master_key is not None:
            self._master_key = b"\x00" * len(self._master_key)
        self._audit_signing_key = None
        self._audit_log_enc_key = None
        self._master_key = None

        if self._events is not None:
            self._events.publish(UserLoggedOut(reason=reason))

    # ------------------------------------------------------------------ #
    # Password change & key rotation (CHANGE-1..4)
    # ------------------------------------------------------------------ #

    def change_password(self, current_password: str, new_password: str) -> None:
        if not self.is_initialized():
            raise ValueError("Vault is not initialized.")

        if not self._cache.unlocked or self._cache.get() is None:
            raise RuntimeError("Vault must be unlocked to change the password.")

        auth_row = self._db.fetch_one(
            "SELECT key_data FROM key_store WHERE key_type = ? LIMIT 1",
            (KEY_TYPE_AUTH_HASH,),
        )
        salt_row = self._db.fetch_one(
            "SELECT key_data FROM key_store WHERE key_type = ? LIMIT 1",
            (KEY_TYPE_ENC_SALT,),
        )
        if auth_row is None or salt_row is None:
            raise RuntimeError("Vault is corrupted: missing key material.")

        stored_hash = auth_row["key_data"].decode("utf-8")
        old_salt = bytes(salt_row["key_data"])

        if not self._kd.verify_password(current_password, stored_hash):
            raise ValueError("Current password is incorrect.")

        validation = self._validator.validate(new_password)
        if not validation.valid:
            raise ValueError(
                "New password does not meet policy: "
                + "; ".join(validation.reasons)
            )

        if new_password == current_password:
            raise ValueError("New password must differ from the current one.")

        old_key = self._kd.derive_encryption_key(current_password, old_salt)
        new_hash = self._kd.create_auth_hash(new_password)
        new_salt = self._kd.generate_salt(config.PBKDF2_SALT_LEN)
        new_audit_salt = self._kd.generate_salt(config.PBKDF2_SALT_LEN)
        new_key = self._kd.derive_encryption_key(new_password, new_salt)

        try:
            self._re_encrypt_all_entries(old_key, new_key)
            with self._db.transaction():
                self._db.execute_in_transaction(
                    "UPDATE key_store SET key_data = ?, version = ? WHERE key_type = ?",
                    (new_hash.encode("utf-8"), config.KEY_STORE_VERSION, KEY_TYPE_AUTH_HASH),
                )
                self._db.execute_in_transaction(
                    "UPDATE key_store SET key_data = ?, version = ? WHERE key_type = ?",
                    (new_salt, config.KEY_STORE_VERSION, KEY_TYPE_ENC_SALT),
                )
                self._db.execute_in_transaction(
                    "UPDATE key_store SET key_data = ?, version = ? WHERE key_type = ?",
                    (new_audit_salt, config.KEY_STORE_VERSION, KEY_TYPE_AUDIT_SALT),
                )
        finally:
            old_key = b"\x00" * len(old_key)  # noqa: F841

        self._master_key = new_key
        self._cache.store(new_key)

        # Subkeys are invalidated; they will be re-derived lazily.
        self._audit_signing_key = None
        self._audit_log_enc_key = None

        self._session.record_login()
        if self._events is not None:
            self._events.publish(UserLoggedIn())

    def _re_encrypt_all_entries(self, old_key: bytes, new_key: bytes) -> None:
        old_aesgcm = AESGCM(bytes(old_key))
        new_aesgcm = AESGCM(bytes(new_key))

        rows = self._db.fetch_all(
            "SELECT id, encrypted_data FROM vault_entries"
        )

        with self._db.transaction():
            for row in rows:
                entry_id = row["id"]
                blob = bytes(row["encrypted_data"])

                nonce = blob[:NONCE_SIZE]
                ct_and_tag = blob[NONCE_SIZE:]

                try:
                    plaintext = old_aesgcm.decrypt(nonce, ct_and_tag, None)
                except InvalidTag as exc:
                    raise RuntimeError(
                        f"Failed to re-encrypt entry {entry_id}: "
                        f"authentication failed."
                    ) from exc

                new_nonce = os.urandom(NONCE_SIZE)
                new_ct_and_tag = new_aesgcm.encrypt(new_nonce, plaintext, None)
                new_blob = new_nonce + new_ct_and_tag

                self._db.execute_in_transaction(
                    "UPDATE vault_entries SET encrypted_data = ? WHERE id = ?",
                    (new_blob, entry_id),
                )

    # ------------------------------------------------------------------ #
    # Diagnostics
    # ------------------------------------------------------------------ #

    def _build_params_snapshot(self) -> dict:
        return {
            "version": config.KEY_STORE_VERSION,
            "argon2": {
                "time_cost": self._kd.params.time_cost,
                "memory_cost": self._kd.params.memory_cost,
                "parallelism": self._kd.params.parallelism,
                "hash_len": self._kd.params.hash_len,
                "salt_len": self._kd.params.salt_len,
            },
            "pbkdf2": {
                "iterations": self._kd.pbkdf2_iterations,
                "salt_len": config.PBKDF2_SALT_LEN,
                "key_len": config.PBKDF2_KEY_LEN,
            },
        }

    def _read_params(self) -> dict | None:
        row = self._db.fetch_one(
            "SELECT key_data FROM key_store WHERE key_type = ? LIMIT 1",
            (KEY_TYPE_PARAMS,),
        )
        if row is None:
            return None
        try:
            return json.loads(row["key_data"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None