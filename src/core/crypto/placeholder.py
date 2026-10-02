"""
Temporary XOR-based placeholder encryption service.

This is NOT secure cryptography. It exists so the rest of the codebase
can be wired against the real interface before AES-256-GCM lands in
Sprint 3.

Sprint 2 update (ARC-2): the service now reads the key from the injected
KeyManager instead of receiving it per call.
"""

from src.core.crypto.abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    """
    XOR placeholder bound to a KeyManager.

    The name mirrors the real AES-256-GCM implementation that will
    replace this class in Sprint 3; the interface is identical.
    """

    def encrypt(self, data: bytes) -> bytes:
        key = self._require_key()
        return self._xor(data, key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        key = self._require_key()
        return self._xor(ciphertext, key)

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

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        if not key:
            raise ValueError("Encryption key cannot be empty")
        return bytes(
            value ^ key[index % len(key)]
            for index, value in enumerate(data)
        )