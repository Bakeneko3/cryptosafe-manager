from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    """
    Temporary XOR-based encryption placeholder for Sprint 1.

    This is NOT secure cryptography.
    It will be replaced with AES-256-GCM in Sprint 3.
    """

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if not key:
            raise ValueError("Encryption key cannot be empty")

        return self._xor(data, key)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        if not key:
            raise ValueError("Decryption key cannot be empty")

        return self._xor(data, key)

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        return bytes(
            value ^ key[index % len(key)]
            for index, value in enumerate(data)
        )