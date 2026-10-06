"""
QR code generation and decoding.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import qrcode
from qrcode.constants import ERROR_CORRECT_L

try:
    import cv2
    import numpy as np
    _CV2_AVAILABLE = True
except Exception:
    _CV2_AVAILABLE = False


DEFAULT_VALIDITY_SECONDS = 300
DEFAULT_CHUNK_SIZE = 800  # conservative: OpenCV handles smaller QR codes reliably


class QRError(Exception):
    pass


class QRDecodeError(QRError):
    pass


class QRExpiredError(QRError):
    pass


@dataclass
class QRPngChunk:
    index: int
    total: int
    png_bytes: bytes


class QRService:
    def __init__(
        self,
        *,
        validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if validity_seconds < 1:
            raise QRError("validity_seconds must be > 0")
        if chunk_size < 100:
            raise QRError("chunk_size must be >= 100")
        self._validity = validity_seconds
        self._chunk_size = chunk_size

    # ------------------------------------------------------------------ #
    # Generation
    # ------------------------------------------------------------------ #

    def generate(self, payload: bytes) -> list[QRPngChunk]:
        compressed = zlib.compress(payload)

        chunks_raw: list[bytes] = []
        for i in range(0, len(compressed), self._chunk_size):
            chunks_raw.append(compressed[i:i + self._chunk_size])
        if not chunks_raw:
            chunks_raw = [b""]

        total = len(chunks_raw)
        nonce = os.urandom(8).hex()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=self._validity)

        result: list[QRPngChunk] = []
        for idx, chunk in enumerate(chunks_raw, start=1):
            doc = {
                "cryptosafe_qr": True,
                "version": "1.0",
                "created_at": now.isoformat(),
                "expires_at": expires.isoformat(),
                "nonce": nonce,
                "chunk": idx,
                "total": total,
                "checksum": hashlib.sha256(chunk).hexdigest()[:16],
                "data": base64.b64encode(chunk).decode("ascii"),
            }
            blob = json.dumps(doc, separators=(",", ":")).encode("utf-8")
            result.append(
                QRPngChunk(
                    index=idx,
                    total=total,
                    png_bytes=self._encode_png(blob),
                )
            )
        return result

    def generate_to_files(self, payload: bytes, directory: str | Path) -> list[Path]:
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        paths: list[Path] = []
        for chunk in self.generate(payload):
            name = f"qr_{chunk.index:03d}_of_{chunk.total:03d}.png"
            p = out_dir / name
            p.write_bytes(chunk.png_bytes)
            paths.append(p)
        return paths

    @staticmethod
    def _encode_png(blob: bytes) -> bytes:
        qr = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_L,
            box_size=8,
            border=4,
        )
        qr.add_data(blob)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    # ------------------------------------------------------------------ #
    # Decoding
    # ------------------------------------------------------------------ #

    def decode_file(self, path: str | Path) -> bytes:
        return self.decode_files([path])

    def decode_files(self, paths: Iterable[str | Path]) -> bytes:
        if not _CV2_AVAILABLE:
            raise QRError("OpenCV is not installed; QR decoding is unavailable.")

        docs: dict[int, dict] = {}
        total: int | None = None

        for path in paths:
            doc = self._decode_single(Path(path))
            if total is None:
                total = doc["total"]
            elif doc["total"] != total:
                raise QRDecodeError("Chunks belong to different payloads.")
            docs[doc["chunk"]] = doc

        if total is None:
            raise QRDecodeError("No QR codes provided.")

        if sorted(docs.keys()) != list(range(1, total + 1)):
            raise QRDecodeError(
                f"Missing chunks: have {sorted(docs.keys())}, "
                f"expected 1..{total}."
            )

        first = docs[1]
        expires = datetime.fromisoformat(first["expires_at"])
        if datetime.now(timezone.utc) > expires:
            raise QRExpiredError("QR code has expired.")

        parts: list[bytes] = []
        for i in range(1, total + 1):
            doc = docs[i]
            raw = base64.b64decode(doc["data"])
            expected = doc["checksum"]
            actual = hashlib.sha256(raw).hexdigest()[:16]
            if actual != expected:
                raise QRDecodeError(f"Checksum mismatch on chunk {i}.")
            parts.append(raw)

        compressed = b"".join(parts)
        try:
            return zlib.decompress(compressed)
        except zlib.error as exc:
            raise QRDecodeError(f"Decompression failed: {exc}") from exc

    def decode_bytes(self, png_bytes: bytes) -> dict:
        if not _CV2_AVAILABLE:
            raise QRError("OpenCV is not installed; QR decoding is unavailable.")
        arr = np.frombuffer(png_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            raise QRDecodeError("Could not read image data.")
        return self._extract_from_image(img)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _decode_single(self, path: Path) -> dict:
        if not path.exists():
            raise QRDecodeError(f"File not found: {path}")
        raw = path.read_bytes()
        arr = np.frombuffer(raw, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            raise QRDecodeError(f"Could not read image: {path}")
        return self._extract_from_image(img)

    def _extract_from_image(self, img) -> dict:
        """
        Try multiple preprocessing strategies to decode the QR payload.

        OpenCV's QRCodeDetector is sensitive to size and binarization.
        We attempt:
            * grayscale as-is
            * grayscale downscaled to <=1000 px
            * binary threshold
        """
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img

        candidates: list = [gray]

        h, w = gray.shape[:2]
        # Downscale very large images.
        if max(h, w) > 1000:
            scale = 1000 / max(h, w)
            candidates.append(
                cv2.resize(
                    gray, (int(w * scale), int(h * scale)),
                    interpolation=cv2.INTER_AREA,
                )
            )

        # Upscale small images.
        if max(h, w) < 300:
            scale = 300 / max(h, w)
            candidates.append(
                cv2.resize(
                    gray, (int(w * scale), int(h * scale)),
                    interpolation=cv2.INTER_NEAREST,
                )
            )

        # Binarized versions.
        for base in list(candidates):
            _, binary = cv2.threshold(base, 127, 255, cv2.THRESH_BINARY)
            candidates.append(binary)

        detector = cv2.QRCodeDetector()
        data = ""
        for candidate in candidates:
            try:
                data, _points, _ = detector.detectAndDecode(candidate)
            except Exception:
                data = ""
            if data:
                break

        if not data:
            raise QRDecodeError("No QR code detected in image.")

        try:
            doc = json.loads(data)
        except json.JSONDecodeError as exc:
            raise QRDecodeError(f"QR payload is not valid JSON: {exc}") from exc

        if not doc.get("cryptosafe_qr"):
            raise QRDecodeError("QR payload is not a CryptoSafe code.")

        for key in ("chunk", "total", "checksum", "data", "expires_at"):
            if key not in doc:
                raise QRDecodeError(f"QR payload missing field: {key}")

        return doc