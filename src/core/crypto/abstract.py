"""
Abstract encryption service.

Sprint 2 update (ARC-2): the service no longer takes a raw key per call.
Instead, it is constructed with a KeyManager and obtains the encryption
key from it on demand. This keeps key material encapsulated and ensures
the service never holds a stale reference.

The concrete implementation decides how to derive/fetch the key. This
abstract class only fixes the public interface.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.key_manager import KeyManager


class EncryptionService(ABC):
    """Abstract encryption service bound to a KeyManager."""

    def __init__(self, key_manager: "KeyManager") -> None:
        self._key_manager = key_manager

    @property
    def key_manager(self) -> "KeyManager":
        return self._key_manager

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using the key held by the KeyManager."""
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using the key held by the KeyManager."""
        raise NotImplementedError