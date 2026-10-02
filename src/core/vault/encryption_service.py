"""
Per-entry AES-256-GCM encryption.

Replaces the Sprint 1 XOR placeholder with real authenticated encryption.
The service is bound to a KeyManager (see ARC-2 in Sprint 2) and pulls
the current encryption key from its cache on each operation.

Wire format (ENC-4):
    nonce (12 bytes) || ciphertext (variable) || tag (16 bytes)

The 12-byte nonce is generated fresh on every encryption using
os.urandom(12) (ENC-2). The tag is appended by AESGCM automatically
and validated on decrypt; tampered or truncated data raises
DecryptionError (ENC-5).
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.abstract import EncryptionService


NONCE_SIZE = 12
TAG_SIZE = 16
MIN_CIPHERTEXT_SIZE = NONCE_SIZE + TAG_SIZE


class DecryptionError(Exception):
    """Raised when ciphertext fails authentication (tampered or corrupt)."""


class AESGCMService(EncryptionService):
    """
    AES-256-GCM encryption service bound to a KeyManager.

    The key is read from KeyManager.get_encryption_key() on every call,
    so locking the vault immediately makes this service unusable until
    it is unlocked again.
    """

    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes or bytearray")

        key = self._require_key()
        nonce = os.urandom(NONCE_SIZE)

        aesgcm = AESGCM(bytes(key))
        # AESGCM.encrypt returns ciphertext || tag.
        ct_and_tag = aesgcm.encrypt(nonce, bytes(data), None)

        return nonce + ct_and_tag

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes or bytearray")

        blob = bytes(ciphertext)
        if len(blob) < MIN_CIPHERTEXT_SIZE:
            raise DecryptionError("Ciphertext is too short.")

        key = self._require_key()
        nonce = blob[:NONCE_SIZE]
        ct_and_tag = blob[NONCE_SIZE:]

        aesgcm = AESGCM(bytes(key))
        try:
            return aesgcm.decrypt(nonce, ct_and_tag, None)
        except InvalidTag as exc:
            raise DecryptionError(
                "Authentication tag verification failed."
            ) from exc

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _require_key(self) -> bytes:
        key = self._key_manager.get_encryption_key()
        if key is None:
            raise RuntimeError(
                "Encryption key is not available (vault is locked)."
            )
        return bytes(key)