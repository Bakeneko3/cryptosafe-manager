"""
Public-key infrastructure for secure vault sharing.

Supports two key types:
  * RSA-2048 with OAEP (SHA-256) for hybrid encryption.
  * ECC P-256 with ECIES-style hybrid encryption (ECDH + HKDF + AES-GCM).

Keys are serialized in PEM for storage and exchange. Fingerprints are
computed as SHA-256 over the DER-encoded SubjectPublicKeyInfo and
displayed as uppercase hex groups of 4 characters.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KeyType = Literal["rsa", "ec"]


# --------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------- #


class KeyExchangeError(Exception):
    """Base error for key exchange failures."""


class DecryptionError(KeyExchangeError):
    """Raised when a ciphertext cannot be decrypted."""


# --------------------------------------------------------------------- #
# Fingerprint
# --------------------------------------------------------------------- #


def fingerprint_public_key(public_key_pem: bytes) -> str:
    """
    Compute a human-readable fingerprint of a PEM-encoded public key.

    Returns a string of 16 hex groups separated by colons, derived from
    SHA-256 over the DER-encoded public key.
    """
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:
        raise KeyExchangeError(f"Invalid public key: {exc}") from exc

    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    # Group into 16 blocks of 4 chars: "ABCD:EF01:..."
    return ":".join(digest[i:i + 4] for i in range(0, 64, 4))


# --------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------- #


@dataclass
class KeyPair:
    private_pem: bytes
    public_pem: bytes
    key_type: KeyType
    fingerprint: str


def generate_keypair(key_type: KeyType = "rsa") -> KeyPair:
    """Generate a fresh RSA-2048 or ECC P-256 key pair."""
    if key_type == "rsa":
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif key_type == "ec":
        private = ec.generate_private_key(ec.SECP256R1())
    else:
        raise KeyExchangeError(f"Unsupported key type: {key_type}")

    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return KeyPair(
        private_pem=private_pem,
        public_pem=public_pem,
        key_type=key_type,
        fingerprint=fingerprint_public_key(public_pem),
    )


# --------------------------------------------------------------------- #
# Hybrid encryption (RSA-OAEP + AES-256-GCM)
# --------------------------------------------------------------------- #


@dataclass
class HybridCiphertext:
    """Serialized hybrid ciphertext."""

    encrypted_key: bytes   # RSA-OAEP encrypted AES key
    nonce: bytes           # 12-byte AES-GCM nonce
    ciphertext: bytes      # AES-GCM ciphertext (includes tag)

    def to_bytes(self) -> bytes:
        """
        Pack into a single blob: [4-byte ek_len][ek][12-byte nonce][ct].
        """
        ek_len = len(self.encrypted_key).to_bytes(4, "big")
        return ek_len + self.encrypted_key + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, blob: bytes) -> "HybridCiphertext":
        if len(blob) < 4 + 12:
            raise DecryptionError("Hybrid ciphertext too short.")
        ek_len = int.from_bytes(blob[:4], "big")
        if len(blob) < 4 + ek_len + 12:
            raise DecryptionError("Hybrid ciphertext malformed.")
        ek = blob[4:4 + ek_len]
        nonce = blob[4 + ek_len:4 + ek_len + 12]
        ct = blob[4 + ek_len + 12:]
        return cls(encrypted_key=ek, nonce=nonce, ciphertext=ct)


def encrypt_with_public_key(
    data: bytes,
    public_key_pem: bytes,
) -> bytes:
    """
    Encrypt data with a public key using hybrid encryption.

    Works for both RSA and ECC:
      * RSA:  random AES key, RSA-OAEP encrypts it.
      * ECC:  ephemeral ECDH to derive AES key (ECIES-style).
    """
    pub = serialization.load_pem_public_key(public_key_pem)

    if isinstance(pub, rsa.RSAPublicKey):
        return _encrypt_rsa(data, pub)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return _encrypt_ec(data, pub)
    raise KeyExchangeError(f"Unsupported public key type: {type(pub).__name__}")


def decrypt_with_private_key(
    blob: bytes,
    private_key_pem: bytes,
    password: bytes | None = None,
) -> bytes:
    """
    Decrypt a hybrid ciphertext with a private key.

    `password` is used if the private key PEM is password-protected.
    """
    try:
        priv = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
        )
    except Exception as exc:
        raise DecryptionError(f"Invalid private key: {exc}") from exc

    if isinstance(priv, rsa.RSAPrivateKey):
        return _decrypt_rsa(blob, priv)
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        return _decrypt_ec(blob, priv)
    raise KeyExchangeError(f"Unsupported private key type: {type(priv).__name__}")


# --------------------------------------------------------------------- #
# RSA internals
# --------------------------------------------------------------------- #


_RSA_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _encrypt_rsa(data: bytes, pub: rsa.RSAPublicKey) -> bytes:
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, data, None)
    ek = pub.encrypt(aes_key, _RSA_OAEP)
    return HybridCiphertext(ek, nonce, ct).to_bytes()


def _decrypt_rsa(blob: bytes, priv: rsa.RSAPrivateKey) -> bytes:
    hc = HybridCiphertext.from_bytes(blob)
    try:
        aes_key = priv.decrypt(hc.encrypted_key, _RSA_OAEP)
    except Exception as exc:
        raise DecryptionError(f"RSA decrypt failed: {exc}") from exc
    try:
        return AESGCM(aes_key).decrypt(hc.nonce, hc.ciphertext, None)
    except Exception as exc:
        raise DecryptionError(f"AES-GCM decrypt failed: {exc}") from exc


# --------------------------------------------------------------------- #
# ECC internals (ECIES-style: ephemeral ECDH + HKDF + AES-GCM)
# --------------------------------------------------------------------- #


_ECIES_INFO = b"cryptosafe-ecies"


def _derive_ec_aes_key(shared: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_ECIES_INFO,
    ).derive(shared)


def _encrypt_ec(data: bytes, pub: ec.EllipticCurvePublicKey) -> bytes:
    ephemeral = ec.generate_private_key(pub.curve)
    shared = ephemeral.exchange(ec.ECDH(), pub)
    aes_key = _derive_ec_aes_key(shared)

    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, data, None)

    ephemeral_pub_pem = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return HybridCiphertext(ephemeral_pub_pem, nonce, ct).to_bytes()


def _decrypt_ec(blob: bytes, priv: ec.EllipticCurvePrivateKey) -> bytes:
    hc = HybridCiphertext.from_bytes(blob)
    try:
        ephemeral_pub = serialization.load_pem_public_key(hc.encrypted_key)
    except Exception as exc:
        raise DecryptionError(f"Invalid ephemeral key: {exc}") from exc
    if not isinstance(ephemeral_pub, ec.EllipticCurvePublicKey):
        raise DecryptionError("Ephemeral key is not EC.")
    try:
        shared = priv.exchange(ec.ECDH(), ephemeral_pub)
    except Exception as exc:
        raise DecryptionError(f"ECDH failed: {exc}") from exc
    aes_key = _derive_ec_aes_key(shared)
    try:
        return AESGCM(aes_key).decrypt(hc.nonce, hc.ciphertext, None)
    except Exception as exc:
        raise DecryptionError(f"AES-GCM decrypt failed: {exc}") from exc