from abc import ABC, abstractmethod


class EncryptionService(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using the provided key."""
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using the provided key."""
        raise NotImplementedError