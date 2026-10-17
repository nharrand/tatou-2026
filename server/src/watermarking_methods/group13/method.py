"""Combine image, text-spacing, and QR watermarks using shared recipient secrets.

At least one invisible carrier must fit. Optional layers may be skipped, and extraction
accepts any surviving authenticated component layer.
"""

from __future__ import annotations

import logging

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)
from watermarking_methods.davide import DavideWatermark
from watermarking_methods.francesco import FrancescoWatermark
from watermarking_methods.khaled import KhaledTextSpacingWatermark
from watermarking_methods.khaled.method import MAX_SECRET_BYTES as KHALED_MAX_SECRET_BYTES

logger = logging.getLogger(__name__)

# Keep Group13 carrier selection strict; component fallbacks apply only to standalone methods.

DAVIDE = DavideWatermark()
KHALED = KhaledTextSpacingWatermark()
FRANCESCO = FrancescoWatermark()
_FRANCESCO_MAX_PAGES = 10  # Group13 limits the QR layer to ten pages.

# Use the smallest component secret limit so the payload fits every layer.
MAX_SECRET_BYTES = KHALED_MAX_SECRET_BYTES

# Errors of a layer that is missing or damaged: the other layers still count.
_LAYER_ERRORS = (WatermarkingError, ValueError, RuntimeError, OSError)


class Group13Watermark(WatermarkingMethod):
    name = "group13-watermark"

    # Use Davide fingerprint scores when the secret is unreadable.
    ATTRIBUTION_THRESHOLD = DavideWatermark.ATTRIBUTION_THRESHOLD

    @staticmethod
    def get_usage() -> str:
        return ("davide + khaled + francesco watermarks with the same encrypted secret "
                f"(at most {MAX_SECRET_BYTES} UTF-8 bytes); position is ignored")

    @classmethod
    def is_watermark_applicable(cls, pdf: PdfSource, position: str | None = None) -> bool:
        # At least one invisible layer must fit: a large image or enough simple text.
        try:
            data = load_pdf_bytes(pdf)
        except (TypeError, ValueError, OSError):
            return False
        return (DAVIDE.is_watermark_applicable(data, scans=False)
                or KHALED.is_watermark_applicable(data, tolerant=False))

    @classmethod
    def add_watermark(
        cls,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
        intended_for: str | None = None,
    ) -> bytes:
        if not key:
            raise InvalidKeyError("Key must not be empty")
        if not isinstance(secret, str) or not 0 < len(secret.encode("utf-8")) <= MAX_SECRET_BYTES:
            raise ValueError(f"Secret must be 1-{MAX_SECRET_BYTES} UTF-8 bytes")
        data = load_pdf_bytes(pdf)
        applied: list[WatermarkingMethod] = []

        if DAVIDE.is_watermark_applicable(data, scans=False):
            data = DAVIDE.add_watermark(data, secret, key)
            applied.append(DAVIDE)

        if KHALED.is_watermark_applicable(data, tolerant=False):
            data = KHALED.add_watermark(data, secret, key)
            applied.append(KHALED)

        if not applied:
            raise WatermarkingError("PDF has neither a large enough image nor enough simple text")

        if FRANCESCO.is_watermark_applicable(data, max_pages=_FRANCESCO_MAX_PAGES):
            try:
                data = FRANCESCO.add_watermark(data, secret, key, intended_for=intended_for)
                applied.append(FRANCESCO)
            except ValueError as error:
                logger.warning("group13-watermark: %s skipped: %s", FRANCESCO.name, type(error).__name__)

        for layer in applied:
            if layer.read_secret(data, key) != secret:
                raise WatermarkingError(f"{layer.name} did not survive the other layers")
        return data

    @classmethod
    def read_secret(cls, pdf: PdfSource, key: str) -> str:
        if not key:
            raise InvalidKeyError("Key must not be empty")
        data = load_pdf_bytes(pdf)

        # Cheapest first: text (instant), images, QR codes (slowest). Nobody can forge AES-SIV
        # without the key, so the first secret found is a real recipient, even when a leak mixes
        # pages of two copies.
        for layer in (KHALED, DAVIDE, FRANCESCO):
            try:
                return layer.read_secret(data, key)
            except _LAYER_ERRORS as error:
                logger.debug("group13-watermark: %s not read: %s", layer.name, type(error).__name__)
        raise SecretNotFoundError("No watermark found")

    @classmethod
    def score_recipients(cls, pdf: PdfSource, original: PdfSource, key: str,
                         secrets: list[str]) -> dict[str, float]:
        return DAVIDE.score_recipients(pdf, original, key, secrets, scans=False)

    @classmethod
    def embedded_layers(cls, pdf: PdfSource, key: str, secret: str) -> list[str]:
        """Return the component names whose layer authenticates the expected secret."""
        data = load_pdf_bytes(pdf)
        found = []
        for layer in (DAVIDE, KHALED, FRANCESCO):
            try:
                if layer.read_secret(data, key) == secret:
                    found.append(layer.name)
            except _LAYER_ERRORS:
                pass
        return found
