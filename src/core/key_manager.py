"""
KeyManager facade for CryptoSafe Manager.

Wires together:
  * KeyDerivation   -- Argon2id hashing + PBKDF2 key derivation
  * KeyCache        -- in-memory encryption key storage
  * AuthSession     -- login/session/failure tracking
  * BackoffPolicy   -- exponential backoff on failed logins
  * Database        -- key_store persistence
  * EventBus        -- optional: publishes UserLoggedIn / UserLoggedOut
  * EncryptionService -- used for re-encrypting the vault on password change

Public API:
    * is_initialized()                -- has a vault been created?
    * create_vault(password)          -- first-run initialization
    * unlock(password)                -- login, returns (success, backoff_delay)
    * lock(reason)                    -- lock the vault
    * get_encryption_key()            -- access the cached key (or None)
    * change_password(current, new)   -- rotate master password + re-encrypt vault

The master password is never stored. Only the Argon2id hash (for
verification) and the PBKDF2 salt (for re-derivation) are persisted
in the key_store table. The derived encryption key lives only in
KeyCache and is never written to disk (SEC-1, SEC-2).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

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
    from src.core.crypto.abstract import EncryptionService
    from src.core.events import EventBus


# --------------------------------------------------------------------- #
# key_store record types (KEY-3, DB-1)
# --------------------------------------------------------------------- #


KEY_TYPE_AUTH_HASH = "auth_hash"
KEY_TYPE_ENC_SALT = "enc_salt"
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
        encryption_service_factory: "Callable[[KeyManager], EncryptionService] | None" = None,
        key_derivation: KeyDerivation | None = None,
        key_cache: KeyCache | None = None,
        validator: PasswordStrengthValidator | None = None,
        backoff: BackoffPolicy | None = None,
    ) -> None:
        self._db = database
        self._events = event_bus
        self._encryption_service_factory = encryption_service_factory
        self._kd = key_derivation or KeyDerivation()
        self._cache = key_cache or KeyCache()
        self._validator = validator or PasswordStrengthValidator()
        self._backoff = backoff or BackoffPolicy()
        self._session = AuthSession()

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
                (KEY_TYPE_PARAMS, json.dumps(params).encode("utf-8"), config.KEY_STORE_VERSION),
            )

        enc_key = self._kd.derive_encryption_key(password, enc_salt)
        self._cache.store(enc_key)
        enc_key = b"\x00" * len(enc_key)  # noqa: F841

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

        enc_key = self._kd.derive_encryption_key(password, enc_salt)
        self._cache.store(enc_key)
        enc_key = b"\x00" * len(enc_key)  # noqa: F841

        self._session.record_login()
        if self._events is not None:
            self._events.publish(UserLoggedIn())
        return UnlockResult(success=True, backoff_delay=0)

    def lock(self, reason: str = "manual") -> None:
        self._cache.lock()
        self._session.record_logout()
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
        new_key = self._kd.derive_encryption_key(new_password, new_salt)

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

        self._cache.store(new_key)
        new_key = b"\x00" * len(new_key)  # noqa: F841
        old_key = b"\x00" * len(old_key)  # noqa: F841

        self._session.record_login()
        if self._events is not None:
            self._events.publish(UserLoggedIn())

    def _re_encrypt_all_entries(self, old_key: bytes, new_key: bytes) -> None:
        """
        Decrypt every vault entry with old_key and re-encrypt with new_key.

        Runs in a single transaction. The EncryptionService currently in
        use is the Sprint 2 placeholder (XOR); the real AES-256-GCM
        implementation lands in Sprint 3 and will not change this call
        site.
        """
        from src.core.crypto.placeholder import AES256Placeholder

        # Build a temporary service bound to a fake manager that yields
        # the desired key. This keeps the change_password logic independent
        # of how EncryptionService obtains its key.
        #
        # Implementation note: we do not reuse self._cache because we need
        # to decrypt with the OLD key while the new key is already prepared.
        old_svc = _StaticKeyService(AES256Placeholder, old_key)
        new_svc = _StaticKeyService(AES256Placeholder, new_key)

        rows = self._db.fetch_all(
            "SELECT id, encrypted_password FROM vault_entries"
        )

        with self._db.transaction():
            for row in rows:
                entry_id = row["id"]
                blob = bytes(row["encrypted_password"])
                plaintext = old_svc.decrypt(blob)
                re_encrypted = new_svc.encrypt(plaintext)
                self._db.execute_in_transaction(
                    "UPDATE vault_entries SET encrypted_password = ? WHERE id = ?",
                    (re_encrypted, entry_id),
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


# --------------------------------------------------------------------- #
# Helper: a throwaway EncryptionService bound to a fixed key
# --------------------------------------------------------------------- #


class _StaticKeyService:
    """
    Wraps an EncryptionService class to make it use a fixed key instead
    of pulling it from a live KeyManager.

    Used only internally by KeyManager.change_password, where we must
    hold two keys at once (old and new).
    """

    def __init__(self, service_cls, key: bytes) -> None:
        manager = _StaticKeyManager(key)
        self._svc = service_cls(manager)

    def encrypt(self, data: bytes) -> bytes:
        return self._svc.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._svc.decrypt(data)


class _StaticKeyManager:
    """Minimal KeyManager-shaped object returning a fixed key."""

    def __init__(self, key: bytes) -> None:
        self._key = bytearray(key)

    def get_encryption_key(self) -> bytearray:
        return self._key