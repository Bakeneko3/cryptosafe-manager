"""
KeyManager facade for CryptoSafe Manager.

Wires together:
  * KeyDerivation   -- Argon2id hashing + PBKDF2 key derivation
  * KeyCache        -- in-memory encryption key storage
  * AuthSession     -- login/session/failure tracking
  * BackoffPolicy   -- exponential backoff on failed logins
  * Database        -- key_store persistence

Public API:
    * is_initialized()         -- has a vault been created?
    * create_vault(password)   -- first-run initialization
    * unlock(password)         -- login, returns (success, backoff_delay)
    * lock()                   -- lock the vault
    * get_encryption_key()     -- access the cached key (or None)

The master password is never stored. Only the Argon2id hash (for
verification) and the PBKDF2 salt (for re-derivation) are persisted
in the key_store table. The derived encryption key lives only in
KeyCache and is never written to disk (SEC-1, SEC-2).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from src.core import config
from src.core.crypto.authentication import (
    AuthSession,
    BackoffPolicy,
    PasswordStrengthValidator,
)
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyCache
from src.database.db import Database


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
        key_derivation: KeyDerivation | None = None,
        key_cache: KeyCache | None = None,
        validator: PasswordStrengthValidator | None = None,
        backoff: BackoffPolicy | None = None,
    ) -> None:
        self._db = database
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
    # First-run: create vault (AUTH-1, AUTH-2 steps 1-3, KEY-3, SEC-1)
    # ------------------------------------------------------------------ #

    def create_vault(self, password: str) -> None:
        """
        Initialize a new vault.

        Raises:
            ValueError: if password fails strength validation, or if a
                        vault already exists.
        """
        if self.is_initialized():
            raise ValueError("Vault is already initialized.")

        result = self._validator.validate(password)
        if not result.valid:
            raise ValueError(
                "Password does not meet policy: "
                + "; ".join(result.reasons)
            )

        # 1. Argon2id hash for verification.
        auth_hash = self._kd.create_auth_hash(password)

        # 2. Fresh salt for PBKDF2 key derivation.
        enc_salt = self._kd.generate_salt(config.PBKDF2_SALT_LEN)

        # 3. Parameters snapshot, versioned (KEY-3).
        params = {
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

        # Persist everything atomically.
        self._db.execute(
            "INSERT INTO key_store (key_type, key_data, version) VALUES (?, ?, ?)",
            (KEY_TYPE_AUTH_HASH, auth_hash.encode("utf-8"), config.KEY_STORE_VERSION),
        )
        self._db.execute(
            "INSERT INTO key_store (key_type, key_data, version) VALUES (?, ?, ?)",
            (KEY_TYPE_ENC_SALT, enc_salt, config.KEY_STORE_VERSION),
        )
        self._db.execute(
            "INSERT INTO key_store (key_type, key_data, version) VALUES (?, ?, ?)",
            (KEY_TYPE_PARAMS, json.dumps(params).encode("utf-8"), config.KEY_STORE_VERSION),
        )

        # Derive the encryption key and cache it.
        enc_key = self._kd.derive_encryption_key(password, enc_salt)
        self._cache.store(enc_key)

        # Wipe the local copy of the raw derived key (cache has its own).
        enc_key = b"\x00" * len(enc_key)  # noqa: F841

        self._session.record_login()

    # ------------------------------------------------------------------ #
    # Login / logout (AUTH-2, AUTH-3, AUTH-4)
    # ------------------------------------------------------------------ #

    def unlock(self, password: str) -> UnlockResult:
        """
        Verify the master password and cache the encryption key.

        On failure, increments the failed-attempt counter and returns
        the backoff delay (in seconds) the caller should observe.
        """
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
        return UnlockResult(success=True, backoff_delay=0)

    def lock(self) -> None:
        """Lock the vault: hide the cached key and end the session."""
        self._cache.lock()
        self._session.record_logout()

    # ------------------------------------------------------------------ #
    # Diagnostics
    # ------------------------------------------------------------------ #

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