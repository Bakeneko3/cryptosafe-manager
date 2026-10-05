"""
Key derivation primitives for CryptoSafe Manager.

This module is pure cryptography: it has no knowledge of the database,
events, or GUI. It exposes:

  * Argon2id       -- master password hashing (verification only).
  * PBKDF2-HMAC    -- main AES-256 encryption key for vault entries.
  * HKDF-SHA256    -- subkeys derived from the main key material, used
                      for audit log signing and audit log encryption.
                      Key separation: each subkey uses a distinct context
                      string (RFC 5869).

Both Argon2id and PBKDF2 parameters come from `src.core.config`.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2 import Type as Argon2Type
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.core import config


# --------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------- #


class KeyDerivationError(Exception):
    """Base error for key-derivation failures."""


class InvalidParameterError(KeyDerivationError):
    """Raised when a parameter is outside of its allowed range."""


# --------------------------------------------------------------------- #
# HKDF contexts (key separation, CRY-2)
# --------------------------------------------------------------------- #


CONTEXT_VAULT_ENC = b"cryptosafe-vault-enc"
CONTEXT_AUDIT_SIGNING = b"cryptosafe-audit-signing"
CONTEXT_AUDIT_ENC = b"cryptosafe-audit-enc"


# --------------------------------------------------------------------- #
# Parameter container
# --------------------------------------------------------------------- #


@dataclass(frozen=True)
class Argon2Params:
    """Validated Argon2id parameters."""

    time_cost: int
    memory_cost: int
    parallelism: int
    hash_len: int
    salt_len: int


# --------------------------------------------------------------------- #
# Parameter validation (SEC-4)
# --------------------------------------------------------------------- #


def _validate_argon2_params(
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
    salt_len: int,
) -> Argon2Params:
    if time_cost < 1 or time_cost > config.ARGON2_MAX_TIME_COST:
        raise InvalidParameterError(
            f"argon2 time_cost must be in [1, {config.ARGON2_MAX_TIME_COST}], "
            f"got {time_cost}"
        )
    if memory_cost < 8 or memory_cost > config.ARGON2_MAX_MEMORY_COST:
        raise InvalidParameterError(
            f"argon2 memory_cost must be in [8, {config.ARGON2_MAX_MEMORY_COST}] KiB, "
            f"got {memory_cost}"
        )
    if parallelism < 1 or parallelism > config.ARGON2_MAX_PARALLELISM:
        raise InvalidParameterError(
            f"argon2 parallelism must be in [1, {config.ARGON2_MAX_PARALLELISM}], "
            f"got {parallelism}"
        )
    if hash_len < 16 or hash_len > 128:
        raise InvalidParameterError(
            f"argon2 hash_len must be in [16, 128], got {hash_len}"
        )
    if salt_len < 8 or salt_len > 64:
        raise InvalidParameterError(
            f"argon2 salt_len must be in [8, 64], got {salt_len}"
        )

    return Argon2Params(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        salt_len=salt_len,
    )


def _validate_pbkdf2_iterations(iterations: int) -> int:
    if iterations < 1 or iterations > config.PBKDF2_MAX_ITERATIONS:
        raise InvalidParameterError(
            f"pbkdf2 iterations must be in [1, {config.PBKDF2_MAX_ITERATIONS}], "
            f"got {iterations}"
        )
    return iterations


# --------------------------------------------------------------------- #
# KeyDerivation
# --------------------------------------------------------------------- #


class KeyDerivation:
    """
    Stateless key-derivation service.

    Argon2id parameters, PBKDF2 iteration count, and HKDF hash algorithm
    are read from `src.core.config` at construction time. Use the
    `params` property to introspect the effective Argon2 configuration.
    """

    def __init__(
        self,
        *,
        time_cost: int = config.ARGON2_TIME_COST,
        memory_cost: int = config.ARGON2_MEMORY_COST,
        parallelism: int = config.ARGON2_PARALLELISM,
        hash_len: int = config.ARGON2_HASH_LEN,
        salt_len: int = config.ARGON2_SALT_LEN,
        pbkdf2_iterations: int = config.PBKDF2_ITERATIONS,
    ) -> None:
        self._params = _validate_argon2_params(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
        )
        self._pbkdf2_iterations = _validate_pbkdf2_iterations(pbkdf2_iterations)

        self._hasher = PasswordHasher(
            time_cost=self._params.time_cost,
            memory_cost=self._params.memory_cost,
            parallelism=self._params.parallelism,
            hash_len=self._params.hash_len,
            salt_len=self._params.salt_len,
            type=Argon2Type.ID,
        )

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    @property
    def params(self) -> Argon2Params:
        return self._params

    @property
    def pbkdf2_iterations(self) -> int:
        return self._pbkdf2_iterations

    # ------------------------------------------------------------------ #
    # Argon2id: password hashing & verification (HASH-1..3, KEY-1)
    # ------------------------------------------------------------------ #

    def create_auth_hash(self, password: str) -> str:
        if not password:
            raise ValueError("password must not be empty")
        return self._hasher.hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        if not password or not stored_hash:
            return False
        try:
            return self._hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError):
            return False

    @staticmethod
    def needs_rehash(stored_hash: str) -> bool:
        if not stored_hash:
            return True
        try:
            from argon2 import PasswordHasher as _PH
            return _PH().check_needs_rehash(stored_hash)
        except Exception:
            return True

    # ------------------------------------------------------------------ #
    # Salts
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_salt(length: int = config.PBKDF2_SALT_LEN) -> bytes:
        if length < 8 or length > 64:
            raise InvalidParameterError(
                f"salt length must be in [8, 64], got {length}"
            )
        return secrets.token_bytes(length)

    # ------------------------------------------------------------------ #
    # PBKDF2: master key derivation (KEY-1, KEY-2)
    # ------------------------------------------------------------------ #

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive the main 32-byte key material from the master password.

        This is the *root* key from which subkeys are derived via HKDF.
        It is never used directly to encrypt data; use
        `derive_subkey(...)` for that.
        """
        if not password:
            raise ValueError("password must not be empty")
        if not salt:
            raise ValueError("salt must not be empty")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=config.PBKDF2_KEY_LEN,
            salt=salt,
            iterations=self._pbkdf2_iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    # ------------------------------------------------------------------ #
    # HKDF: subkey derivation (CRY-2)
    # ------------------------------------------------------------------ #

    @staticmethod
    def derive_subkey(
        master_key: bytes,
        context: bytes,
        length: int = 32,
    ) -> bytes:
        """
        Derive a subkey from the master key material via HKDF-SHA256.

        `context` is an application-specific string that provides
        domain separation between subkeys derived from the same root
        (e.g. encryption vs. signing vs. audit-log encryption).
        """
        if not master_key:
            raise ValueError("master_key must not be empty")
        if not context:
            raise ValueError("context must not be empty")
        if length < 16 or length > 64:
            raise InvalidParameterError(
                f"subkey length must be in [16, 64], got {length}"
            )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,           # context already provides separation
            info=context,
        )
        return hkdf.derive(master_key)

    def derive_signing_key(self, master_key: bytes) -> bytes:
        """
        Derive the Ed25519 seed (32 bytes) used to sign audit log entries.
        """
        return self.derive_subkey(
            master_key,
            context=CONTEXT_AUDIT_SIGNING,
            length=32,
        )

    def derive_log_encryption_key(self, master_key: bytes) -> bytes:
        """
        Derive the AES-256 key used to encrypt audit log entry data
        at rest (DB-2).
        """
        return self.derive_subkey(
            master_key,
            context=CONTEXT_AUDIT_ENC,
            length=32,
        )

    def derive_vault_encryption_key(self, master_key: bytes) -> bytes:
        """
        Derive the AES-256 key used to encrypt vault entries.

        Kept for symmetry with the other contexts; the existing vault
        code continues to use the master key directly.
        """
        return self.derive_subkey(
            master_key,
            context=CONTEXT_VAULT_ENC,
            length=32,
        )