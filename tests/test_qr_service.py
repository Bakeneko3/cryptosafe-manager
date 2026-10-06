"""Tests for src/core/import_export/qr_service.py (QR-1, QR-2, QR-4)."""

import os
from pathlib import Path

import pytest

from src.core.import_export.qr_service import (
    QRDecodeError,
    QRError,
    QRExpiredError,
    QRService,
)


@pytest.fixture
def service() -> QRService:
    return QRService(validity_seconds=300, chunk_size=350)


# --------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------- #


def test_generate_single_chunk(service: QRService) -> None:
    chunks = service.generate(b"hello world")
    assert len(chunks) == 1
    assert chunks[0].index == 1
    assert chunks[0].total == 1
    assert chunks[0].png_bytes[:8] == b"\x89PNG\r\n\x1a\n"


def test_generate_multiple_chunks(service: QRService) -> None:
    payload = os.urandom(1000)  # incompressible, > 350
    chunks = service.generate(payload)
    assert len(chunks) > 1
    assert all(c.total == len(chunks) for c in chunks)
    assert [c.index for c in chunks] == list(range(1, len(chunks) + 1))


def test_generate_empty_payload(service: QRService) -> None:
    chunks = service.generate(b"")
    assert len(chunks) == 1


# --------------------------------------------------------------------- #
# Round-trip
# --------------------------------------------------------------------- #


def test_roundtrip_small(service: QRService, tmp_path: Path) -> None:
    payload = b"a small payload"
    paths = service.generate_to_files(payload, tmp_path)
    assert len(paths) == 1
    decoded = service.decode_files(paths)
    assert decoded == payload


def test_roundtrip_large_multichunk(service: QRService, tmp_path: Path) -> None:
    payload = os.urandom(1000)  # ~3 chunks at 350
    paths = service.generate_to_files(payload, tmp_path)
    assert len(paths) > 1
    decoded = service.decode_files(paths)
    assert decoded == payload


def test_roundtrip_in_memory(service: QRService) -> None:
    payload = b"data for in-memory test"
    chunks = service.generate(payload)
    doc = service.decode_bytes(chunks[0].png_bytes)
    assert doc["cryptosafe_qr"] is True
    assert doc["total"] == 1


# --------------------------------------------------------------------- #
# QR-4: expiry & metadata
# --------------------------------------------------------------------- #


def test_qr_expires(service: QRService, tmp_path: Path) -> None:
    fast = QRService(validity_seconds=1, chunk_size=350)
    paths = fast.generate_to_files(b"tick", tmp_path)
    import time
    time.sleep(1.2)
    with pytest.raises(QRExpiredError):
        fast.decode_files(paths)


def test_qr_contains_nonce_and_timestamp(service: QRService) -> None:
    chunks = service.generate(b"x")
    doc = service.decode_bytes(chunks[0].png_bytes)
    assert "nonce" in doc
    assert "created_at" in doc
    assert "expires_at" in doc
    assert len(doc["nonce"]) == 16


def test_two_qr_sets_have_different_nonces(service: QRService) -> None:
    a = service.generate(b"x")
    b = service.generate(b"x")
    doc_a = service.decode_bytes(a[0].png_bytes)
    doc_b = service.decode_bytes(b[0].png_bytes)
    assert doc_a["nonce"] != doc_b["nonce"]


# --------------------------------------------------------------------- #
# QR-2: error handling
# --------------------------------------------------------------------- #


def test_decode_nonexistent_file(service: QRService, tmp_path: Path) -> None:
    with pytest.raises(QRDecodeError):
        service.decode_files([tmp_path / "nope.png"])


def test_decode_not_a_qr(service: QRService, tmp_path: Path) -> None:
    p = tmp_path / "blank.png"
    from PIL import Image
    Image.new("RGB", (100, 100), "white").save(p)
    with pytest.raises(QRDecodeError):
        service.decode_files([p])


def test_decode_missing_chunk(service: QRService, tmp_path: Path) -> None:
    payload = os.urandom(1000)
    paths = service.generate_to_files(payload, tmp_path)
    assert len(paths) > 1
    with pytest.raises(QRDecodeError):
        service.decode_files(paths[:-1])


# --------------------------------------------------------------------- #
# Validation of parameters
# --------------------------------------------------------------------- #


def test_invalid_validity() -> None:
    with pytest.raises(QRError):
        QRService(validity_seconds=0)


def test_invalid_chunk_size() -> None:
    with pytest.raises(QRError):
        QRService(chunk_size=10)