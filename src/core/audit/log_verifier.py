"""
Audit log integrity verification.

Given the vault's log-encryption key and (optionally) the public key,
walks the audit_log table in sequence order, decrypts each entry,
verifies its Ed25519 signature, and checks that the hash chain is
continuous.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.audit.audit_logger import GENESIS_HASH, NONCE_SIZE
from src.core.audit.log_signer import LogSigner
from src.database.db import Database

if TYPE_CHECKING:
    from src.core.key_manager import KeyManager


# --------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------- #


@dataclass
class VerificationError:
    sequence_number: int
    reason: str


@dataclass
class VerificationReport:
    total_entries: int = 0
    valid_entries: int = 0
    errors: list[VerificationError] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return not self.errors and self.total_entries == self.valid_entries

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    def summary(self) -> str:
        if self.verified:
            return f"OK: {self.total_entries} entries verified."
        return (
            f"FAILED: {len(self.errors)} errors out of "
            f"{self.total_entries} entries."
        )


# --------------------------------------------------------------------- #
# Verifier
# --------------------------------------------------------------------- #


class LogVerifier:
    """
    Verifies signatures and hash-chain continuity of audit_log entries.

    Requires the vault to be unlocked (the log-encryption key is needed
    to read the entries; the public key is used for signature checks).
    """

    def __init__(self, key_manager: "KeyManager") -> None:
        self._km = key_manager

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def verify_all(self) -> VerificationReport:
        """Verify every entry in the log."""
        log_enc_key = self._km.derive_audit_log_encryption_key()
        if log_enc_key is None:
            raise RuntimeError("Vault must be unlocked to verify the audit log.")

        public_key_hex = self._load_public_key()
        public_key = bytes.fromhex(public_key_hex) if public_key_hex else None

        rows = self._km._db.fetch_all(
            """
            SELECT sequence_number, previous_hash, entry_data, signature
            FROM audit_log
            ORDER BY sequence_number
            """
        )

        report = VerificationReport(total_entries=len(rows))
        previous_expected_hash: str | None = None

        for row in rows:
            seq = row["sequence_number"]
            blob = bytes(row["entry_data"])
            signature_hex = row["signature"]
            stored_prev_hash = row["previous_hash"]

            # 1. Decrypt.
            try:
                plaintext = self._decrypt(blob, log_enc_key)
            except InvalidTag:
                report.errors.append(
                    VerificationError(seq, "decryption failed (tampered blob)")
                )
                continue
            except Exception as exc:
                report.errors.append(
                    VerificationError(seq, f"decryption error: {exc}")
                )
                continue

            # 2. Verify signature.
            if public_key is None:
                report.errors.append(
                    VerificationError(seq, "public key not available")
                )
                continue
            try:
                sig = bytes.fromhex(signature_hex)
            except ValueError:
                report.errors.append(
                    VerificationError(seq, "signature is not valid hex")
                )
                continue

            if not LogSigner.verify_with_public_key(plaintext, sig, public_key):
                report.errors.append(
                    VerificationError(seq, "invalid signature")
                )
                continue

            # 3. Verify chain.
            if previous_expected_hash is None:
                # First entry: previous_hash must be GENESIS_HASH.
                if stored_prev_hash != GENESIS_HASH:
                    report.errors.append(
                        VerificationError(
                            seq,
                            f"first entry previous_hash is not GENESIS "
                            f"(got {stored_prev_hash[:16]}...)",
                        )
                    )
                    continue
            else:
                if stored_prev_hash != previous_expected_hash:
                    report.errors.append(
                        VerificationError(
                            seq,
                            f"hash chain broken: expected "
                            f"{previous_expected_hash[:16]}..., "
                            f"got {stored_prev_hash[:16]}...",
                        )
                    )
                    continue

            # Entry passed all checks.
            report.valid_entries += 1
            previous_expected_hash = hashlib.sha256(plaintext).hexdigest()

        return report

    def verify_range(
        self,
        start: int,
        end: int,
    ) -> VerificationReport:
        """
        Verify a range of entries (inclusive). Used for periodic
        verification of recent entries (VER-2).
        """
        log_enc_key = self._km.derive_audit_log_encryption_key()
        if log_enc_key is None:
            raise RuntimeError("Vault must be unlocked to verify the audit log.")

        public_key_hex = self._load_public_key()
        public_key = bytes.fromhex(public_key_hex) if public_key_hex else None

        rows = self._km._db.fetch_all(
            """
            SELECT sequence_number, previous_hash, entry_data, signature
            FROM audit_log
            WHERE sequence_number BETWEEN ? AND ?
            ORDER BY sequence_number
            """,
            (start, end),
        )

        report = VerificationReport(total_entries=len(rows))
        # We do not know the expected previous hash for the first row in
        # a partial range without looking at the row just before `start`.
        # So we only verify signatures within the range, not the chain.
        for row in rows:
            seq = row["sequence_number"]
            blob = bytes(row["entry_data"])
            signature_hex = row["signature"]

            try:
                plaintext = self._decrypt(blob, log_enc_key)
            except Exception as exc:
                report.errors.append(
                    VerificationError(seq, f"decryption error: {exc}")
                )
                continue

            if public_key is None:
                report.errors.append(
                    VerificationError(seq, "public key not available")
                )
                continue

            try:
                sig = bytes.fromhex(signature_hex)
            except ValueError:
                report.errors.append(
                    VerificationError(seq, "signature is not valid hex")
                )
                continue

            if not LogSigner.verify_with_public_key(plaintext, sig, public_key):
                report.errors.append(VerificationError(seq, "invalid signature"))
                continue

            report.valid_entries += 1

        return report

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _load_public_key(self) -> str | None:
        row = self._km._db.fetch_one(
            "SELECT public_key FROM audit_public_key WHERE id = 1"
        )
        return row["public_key"] if row is not None else None

    @staticmethod
    def _decrypt(blob: bytes, log_enc_key: bytes) -> bytes:
        nonce = blob[:NONCE_SIZE]
        ct_and_tag = blob[NONCE_SIZE:]
        aesgcm = AESGCM(bytes(log_enc_key))
        return aesgcm.decrypt(nonce, ct_and_tag, None)