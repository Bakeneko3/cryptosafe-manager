from dataclasses import dataclass


@dataclass
class StoredKey:
    key_type: str
    salt: bytes
    key_hash: bytes
    params: str


class KeyManager:
    """
    Placeholder key manager for Sprint 1.

    Real Argon2-based key derivation will be implemented in Sprint 2.
    """

    def derive_key(self, password: str, salt: bytes) -> bytes:
        if not password:
            raise ValueError("Password cannot be empty")

        if not salt:
            raise ValueError("Salt cannot be empty")

        # Temporary placeholder only.
        return password.encode("utf-8")

    def store_key(self, key: StoredKey) -> None:
        # Persistence will be implemented in Sprint 2.
        raise NotImplementedError

    def load_key(self, key_type: str) -> StoredKey | None:
        # Persistence will be implemented in Sprint 2.
        raise NotImplementedError