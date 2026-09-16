import pytest

from src.core.key_manager import KeyManager


def test_derive_key_placeholder():
    manager = KeyManager()

    password = "test-password"
    salt = b"test-salt"

    key = manager.derive_key(password, salt)

    assert isinstance(key, bytes)
    assert key == password.encode("utf-8")


def test_empty_password_rejected():
    manager = KeyManager()

    with pytest.raises(ValueError):
        manager.derive_key("", b"test-salt")


def test_empty_salt_rejected():
    manager = KeyManager()

    with pytest.raises(ValueError):
        manager.derive_key("test-password", b"")