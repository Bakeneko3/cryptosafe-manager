import pytest

from src.core.crypto.placeholder import AES256Placeholder


def test_encrypt_decrypt_round_trip():
    crypto = AES256Placeholder()

    key = b"test-key"
    plaintext = b"my secret password"

    encrypted = crypto.encrypt(plaintext, key)

    assert encrypted != plaintext
    assert crypto.decrypt(encrypted, key) == plaintext


def test_empty_data():
    crypto = AES256Placeholder()

    key = b"test-key"

    encrypted = crypto.encrypt(b"", key)

    assert encrypted == b""
    assert crypto.decrypt(encrypted, key) == b""


def test_empty_key_rejected():
    crypto = AES256Placeholder()

    with pytest.raises(ValueError):
        crypto.encrypt(b"secret", b"")

    with pytest.raises(ValueError):
        crypto.decrypt(b"secret", b"")


def test_wrong_key_does_not_return_original_data():
    crypto = AES256Placeholder()

    plaintext = b"secret password"
    encrypted = crypto.encrypt(plaintext, b"correct-key")

    decrypted = crypto.decrypt(encrypted, b"wrong-key")

    assert decrypted != plaintext