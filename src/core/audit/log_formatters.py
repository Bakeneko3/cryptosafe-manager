"""
Audit log export formatters.

Three formats are supported:

  * Signed JSON -- complete log with signatures, public key, and export
    metadata; can be independently verified (EXP-2).
  * CSV         -- flat view for spreadsheet analysis (EXP-1).
  * PDF         -- human-readable report with summary (EXP-1).

All formatters decrypt audit entries using the log-encryption key from
the KeyManager. The resulting files contain plaintext event data, so
the caller is responsible for handling them securely.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.audit.audit_logger import NONCE_SIZE
from src.database.db import Database

if TYPE_CHECKING:
    from src.core.key_manager import KeyManager


# --------------------------------------------------------------------- #
# Entry model
# --------------------------------------------------------------------- #


@dataclass
class DecryptedEntry:
    sequence_number: int
    timestamp: str
    event_type: str
    severity: str
    source: str
    user_id: str
    entry_id: str | None
    previous_hash: str
    payload: dict[str, Any]
    signature: str


# --------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------- #


class AuditExporter:
    """
    Reads and decrypts audit entries, then renders them in the
    requested format.
    """

    def __init__(self, database: Database, key_manager: "KeyManager") -> None:
        self._db = database
        self._km = key_manager

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def export_signed_json(self, path: str | Path) -> None:
        """Export a complete signed JSON document (EXP-2)."""
        entries = self._load_entries()
        public_key = self._load_public_key()

        document = {
            "format": "cryptosafe-audit-log",
            "format_version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(entries),
            "public_key_hex": public_key,
            "entries": [
                {
                    "sequence_number": e.sequence_number,
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "source": e.source,
                    "user_id": e.user_id,
                    "entry_id": e.entry_id,
                    "previous_hash": e.previous_hash,
                    "payload": e.payload,
                    "signature": e.signature,
                }
                for e in entries
            ],
        }

        Path(path).write_text(
            json.dumps(document, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def export_csv(self, path: str | Path) -> None:
        """Export a flat CSV for spreadsheet analysis (EXP-1)."""
        entries = self._load_entries()

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                [
                    "sequence_number",
                    "timestamp",
                    "event_type",
                    "severity",
                    "source",
                    "user_id",
                    "entry_id",
                    "previous_hash",
                    "details_json",
                ]
            )
            for e in entries:
                writer.writerow(
                    [
                        e.sequence_number,
                        e.timestamp,
                        e.event_type,
                        e.severity,
                        e.source,
                        e.user_id,
                        e.entry_id or "",
                        e.previous_hash,
                        json.dumps(e.payload.get("details", {}), ensure_ascii=False),
                    ]
                )

    def export_pdf(self, path: str | Path) -> None:
        """Export a human-readable PDF report (EXP-1)."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
        from reportlab.lib import colors

        entries = self._load_entries()

        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=1.5 * cm,
            rightMargin=1.5 * cm,
            topMargin=1.5 * cm,
            bottomMargin=1.5 * cm,
            title="CryptoSafe Audit Log",
        )

        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Title"],
            fontSize=16,
            spaceAfter=12,
        )

        story = []
        story.append(Paragraph("CryptoSafe Manager — Audit Log", title_style))
        story.append(
            Paragraph(
                f"Exported: {datetime.now(timezone.utc).isoformat()}",
                normal,
            )
        )
        story.append(
            Paragraph(f"Total entries: {len(entries)}", normal)
        )
        story.append(Spacer(1, 0.5 * cm))

        # Summary counts.
        by_severity: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for e in entries:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1

        story.append(Paragraph("<b>By severity</b>", normal))
        story.append(
            Paragraph(
                ", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items())),
                normal,
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("<b>By event type</b>", normal))
        for k, v in sorted(by_type.items()):
            story.append(Paragraph(f"&nbsp;&nbsp;{k}: {v}", normal))
        story.append(Spacer(1, 0.5 * cm))

        # Table of entries.
        story.append(Paragraph("<b>Entries</b>", normal))
        story.append(Spacer(1, 0.2 * cm))

        table_data = [["#", "Timestamp", "Type", "Severity", "Source"]]
        for e in entries:
            table_data.append(
                [
                    str(e.sequence_number),
                    e.timestamp,
                    e.event_type,
                    e.severity,
                    e.source,
                ]
            )

        table = Table(
            table_data,
            colWidths=[1.2 * cm, 6 * cm, 4.5 * cm, 2.2 * cm, 3.5 * cm],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

        doc.build(story)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _load_entries(self) -> list[DecryptedEntry]:
        log_enc_key = self._km.derive_audit_log_encryption_key()
        if log_enc_key is None:
            raise RuntimeError("Vault must be unlocked to export the audit log.")

        rows = self._db.fetch_all(
            """
            SELECT sequence_number, timestamp, event_type, severity,
                   source, user_id, entry_id, previous_hash,
                   entry_data, signature
            FROM audit_log
            ORDER BY sequence_number
            """
        )

        result: list[DecryptedEntry] = []
        for row in rows:
            try:
                payload = self._decrypt(row["entry_data"], log_enc_key)
            except (InvalidTag, ValueError):
                payload = {"error": "decryption failed"}

            result.append(
                DecryptedEntry(
                    sequence_number=row["sequence_number"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    severity=row["severity"],
                    source=row["source"],
                    user_id=row["user_id"],
                    entry_id=row["entry_id"],
                    previous_hash=row["previous_hash"],
                    payload=payload,
                    signature=row["signature"],
                )
            )
        return result

    def _load_public_key(self) -> str | None:
        row = self._db.fetch_one(
            "SELECT public_key FROM audit_public_key WHERE id = 1"
        )
        return row["public_key"] if row is not None else None

    @staticmethod
    def _decrypt(blob: bytes, log_enc_key: bytes) -> dict:
        nonce = blob[:NONCE_SIZE]
        ct_and_tag = blob[NONCE_SIZE:]
        aesgcm = AESGCM(bytes(log_enc_key))
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
        return json.loads(plaintext.decode("utf-8"))