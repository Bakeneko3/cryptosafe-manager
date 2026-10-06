"""
Ed25519 signing for audit log entries.

The signing key is derived from the master key material via HKDF with
the context "cryptosafe-audit-signing" (see KeyDerivation). It is held
only in memory and never written to disk (CRY-2).

The corresponding public key is stored once in the audit_public_key
table so that exports can be verified independently.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.core.key_manager import KeyManager


class SigningKeyUnavailableError(Exception):
    """Raised when the vault is locked and no signing key is available."""


class LogSigner:
    """
    Wraps an Ed25519 private key derived from the vault's master key.

    The private key never leaves this class; only `sign`, `verify`,
    and `public_key_bytes` are exposed.
    """

    def __init__(self, key_manager: KeyManager) -> None:
        seed = key_manager.derive_audit_signing_key()
        if seed is None:
            raise SigningKeyUnavailableError(
                "Audit signing key is not available (vault is locked)."
            )

        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(seed))
        self._public_key = self._private_key.public_key()

    # ------------------------------------------------------------------ #
    # Sign / verify
    # ------------------------------------------------------------------ #

    def sign(self, data: bytes) -> bytes:
        """Sign data and return the raw 64-byte signature."""
        return self._private_key.sign(bytes(data))

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Return True if the signature is valid for data."""
        try:
            self._public_key.verify(bytes(signature), bytes(data))
            return True
        except InvalidSignature:
            return False

    # ------------------------------------------------------------------ #
    # Public key
    # ------------------------------------------------------------------ #

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_hex(self) -> str:
        return self.public_key_bytes().hex()

    # ------------------------------------------------------------------ #
    # Static verification from a raw public key
    # ------------------------------------------------------------------ #

    @staticmethod
    def verify_with_public_key(
        data: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Verify a signature using a raw Ed25519 public key (no vault needed)."""
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key))
            key.verify(bytes(signature), bytes(data))
            return True
        except (InvalidSignature, ValueError):
            return False