"""Embed authenticated secrets by shifting the middle glyph of text triples.

Opposing TJ adjustments preserve later glyph positions. Extraction supports strict
carriers and authenticated compatibility reads of older geometry.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from threading import Lock

import pymupdf as fitz
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from reedsolo import ReedSolomonError, RSCodec

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

from .pdf_text import Carrier, UnsupportedText, carriers, collect_runs, replace_runs

MAX_SECRET_BYTES = 48
PARITY_BYTES = 16
TAG_BYTES = 16
STEP_PT = 0.16
_AAD = [b"tatou:text-gap:v2"]
_CODEC = RSCodec(PARITY_BYTES)
_CODEC_LOCK = Lock()  # Reedsolo uses module-level Galois-field tables.


def _keys(key: str) -> tuple[bytes, bytes, bytes]:
    if not key:
        raise InvalidKeyError("Key must not be empty")
    material = HKDF(
        algorithm=hashes.SHA512(),
        length=128,
        salt=None,
        info=b"tatou:text-gap:v2:keys",
    ).derive(key.encode("utf-8"))
    return material[:64], material[64:96], material[96:]


def _ordered(items: list[Carrier], order_key: bytes) -> list[Carrier]:
    return sorted(items, key=lambda item: (
        hmac.new(order_key, item.identity, hashlib.sha256).digest(),
        item.identity,
    ))


def _dither(key: bytes, carrier: Carrier) -> float:
    digest = hmac.new(key, carrier.identity, hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") / 2**64 * (2 * STEP_PT)


def _bits(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _pack(bits: list[int]) -> bytes:
    return bytes(sum(bits[i + j] << (7 - j) for j in range(8))
                 for i in range(0, len(bits), 8))


def _difference(item: Carrier) -> float:
    run = item.run
    left, right = run.gaps[item.middle - 1:item.middle + 1]
    return (right - left) * run.font_size / 1000.0


def _nearest_lattice(value: float, dither: float, bit: int) -> float:
    center = (value - dither) / STEP_PT
    low = math.floor(center)
    indices = (low - 2, low - 1, low, low + 1, low + 2, low + 3)
    index = min((index for index in indices if index % 2 == bit),
                key=lambda index: (abs(index - center), index))
    return dither + index * STEP_PT


def _read_bit(item: Carrier, dither_key: bytes) -> int:
    index = round((_difference(item) - _dither(dither_key, item)) / STEP_PT)
    return index & 1


def _visible_text(doc: fitz.Document) -> tuple[str, ...]:
    return tuple(page.get_text("text", sort=False) for page in doc)


class KhaledTextSpacingWatermark(WatermarkingMethod):
    """Embed a full authenticated secret in live PDF glyph positioning."""

    name = "khaled-text-spacing-watermark"

    @staticmethod
    def get_usage() -> str:
        return ("Blind text-gap watermark for simple, selectable PDF text; "
                "position is auto and secrets are at most 48 UTF-8 bytes")

    @staticmethod
    def capacity_bits(pdf: PdfSource, tolerant: bool = False) -> int:
        """Count structurally stable one-bit carriers before embedding."""
        with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            if doc.is_encrypted or doc.get_sigflags() > 0:
                return 0
            return len(carriers(collect_runs(doc, tolerant)))

    @classmethod
    def _capacity(cls, pdf: PdfSource, tolerant: bool) -> int:
        try:
            return cls.capacity_bits(pdf, tolerant)
        except (ValueError, RuntimeError, OSError, fitz.FileDataError, UnsupportedText):
            return 0

    @classmethod
    def is_watermark_applicable(cls, pdf: PdfSource, position: str | None = None,
                                *, tolerant: bool = True) -> bool:
        """Collect strict carriers unless tolerant fallback is explicitly enabled."""
        if position not in (None, "", "auto"):
            return False
        needed = (MAX_SECRET_BYTES + TAG_BYTES + PARITY_BYTES) * 8
        return cls._capacity(pdf, False) >= needed or (tolerant and cls._capacity(pdf, True) >= needed)

    @classmethod
    def add_watermark(cls, pdf: PdfSource, secret: str, key: str,
                      position: str | None = None) -> bytes:
        if position not in (None, "", "auto"):
            raise ValueError("khaled-text-spacing-watermark supports only automatic placement")
        if not isinstance(secret, str):
            raise TypeError("Secret must be text")
        plain = secret.encode("utf-8")
        if not 1 <= len(plain) <= MAX_SECRET_BYTES:
            raise ValueError(f"Secret must be 1-{MAX_SECRET_BYTES} UTF-8 bytes")
        cipher_key, order_key, dither_key = _keys(key)
        ciphertext = AESSIV(cipher_key).encrypt(plain, _AAD)
        with _CODEC_LOCK:
            packet = bytes(_CODEC.encode(bytearray(ciphertext)))
        source = load_pdf_bytes(pdf)
        # Strict parsing whenever it fits, so documents it handled are unchanged.
        tolerant = cls._capacity(source, False) < len(packet) * 8

        try:
            with fitz.open(stream=source, filetype="pdf") as doc:
                if doc.is_encrypted:
                    raise WatermarkingError("Encrypted PDFs are unsupported")
                if doc.get_sigflags() > 0:
                    raise WatermarkingError("Signed PDFs are unsupported")
                original_text = _visible_text(doc)
                runs = collect_runs(doc, tolerant)
                selected = _ordered(carriers(runs), order_key)
                if len(selected) < len(packet) * 8:
                    raise WatermarkingError(
                        f"Insufficient text capacity: {len(selected)} bits available, "
                        f"{len(packet) * 8} required"
                    )
                original_ids = [item.identity for item in selected]
                changed: dict[int, object] = {}
                for item, bit in zip(selected, _bits(packet), strict=False):
                    run = item.run
                    current = _difference(item)
                    target = _nearest_lattice(current, _dither(dither_key, item), bit)
                    shift_pt = (target - current) / 2
                    if abs(shift_pt) > STEP_PT / 2 + 1e-8:
                        raise WatermarkingError("Text displacement exceeds the limit")
                    adjustment = shift_pt * 1000 / run.font_size
                    run.gaps[item.middle - 1] -= adjustment
                    run.gaps[item.middle] += adjustment
                    changed[id(run)] = run
                replace_runs(doc, list(changed.values()))
                if _visible_text(doc) != original_text:
                    raise WatermarkingError("Watermark changed extracted text")
                after_ids = [item.identity for item in
                             _ordered(carriers(collect_runs(doc, tolerant)), order_key)]
                if after_ids != original_ids:
                    raise WatermarkingError("Text carrier order changed after embedding")
                output = doc.tobytes(garbage=3, deflate=True, no_new_id=True,
                                     encryption=fitz.PDF_ENCRYPT_NONE)
        except (RuntimeError, fitz.FileDataError, UnsupportedText) as exc:
            raise WatermarkingError("PDF text could not be watermarked") from exc

        with fitz.open(stream=output, filetype="pdf") as saved:
            if _visible_text(saved) != original_text:
                raise WatermarkingError("Saved PDF changed extracted text")
        if cls.read_secret(output, key) != secret:
            raise WatermarkingError("Final PDF did not verify")
        return output

    @classmethod
    def read_secret(cls, pdf: PdfSource, key: str) -> str:
        cipher_key, order_key, dither_key = _keys(key)
        data = load_pdf_bytes(pdf)
        # The legacy geometry is read-only and still requires AES-SIV authentication.
        for tolerant, legacy in ((False, False), (True, False), (True, True)):
            try:
                with fitz.open(stream=data, filetype="pdf") as doc:
                    if doc.is_encrypted:
                        raise SecretNotFoundError("No readable text watermark")
                    runs = collect_runs(doc, tolerant, legacy_horizontal_scale=legacy)
                    selected = _ordered(carriers(runs), order_key)
                    bits = [_read_bit(item, dither_key) for item in selected[:
                        (MAX_SECRET_BYTES + TAG_BYTES + PARITY_BYTES) * 8]]
            except (RuntimeError, fitz.FileDataError, UnsupportedText):
                continue
            secret = _decode(bits, cipher_key)
            if secret is not None:
                return secret
        raise SecretNotFoundError("No readable text watermark")


def _decode(bits: list[int], cipher_key: bytes) -> str | None:
    """Return a secret from the carrier prefix, or None when no length authenticates."""
    for length in range(1, MAX_SECRET_BYTES + 1):
        needed = (length + TAG_BYTES + PARITY_BYTES) * 8
        if len(bits) < needed:
            break
        packet = _pack(bits[:needed])
        try:
            with _CODEC_LOCK:
                corrected = bytes(_CODEC.decode(bytearray(packet))[0])
            plain = AESSIV(cipher_key).decrypt(corrected, _AAD)
            if len(plain) == length:
                return plain.decode("utf-8")
        except (ReedSolomonError, InvalidTag, UnicodeDecodeError, ValueError, IndexError):
            continue
    return None
