"""Embed independently salted AES-SIV payloads in QR codes and visible labels.

The shared position argument is accepted for interface compatibility and ignored.
"""

from __future__ import annotations

import logging
from typing import Final

import pymupdf as fitz
import zxingcpp

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
    validate_secret_string,
)

from . import crypto
from . import pdf as pdf_ops
from . import rendering as render_ops
from . import visible as visible_ops

logger = logging.getLogger(__name__)


class FrancescoWatermark(WatermarkingMethod):
    """An AES-SIV QR payload and repeated visible labels with encrypted secrets."""

    name: Final[str] = "francesco-watermark"
    MAX_SECRET_BYTES: Final[int] = 64

    @staticmethod
    def get_usage() -> str:
        return (
            "Native PDF overlay with an authenticated opaque QR code and visible "
            "AES-SIV-encrypted secret labels; preserves original text streams. "
            "Supports any passphrase or hex key."
        )

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None,
                                *, max_pages: int = pdf_ops.MAX_PAGES) -> bool:
        try:
            return pdf_ops.is_document_applicable(load_pdf_bytes(pdf), max_pages)
        except (OSError, TypeError, ValueError):
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
        intended_for: str | None = None,
    ) -> bytes:
        crypto.derive_aes_key(key)
        validate_secret_string(secret, self.MAX_SECRET_BYTES)

        data = load_pdf_bytes(pdf)
        if not pdf_ops.is_document_applicable(data):
            raise ValueError("PDF is not applicable to francesco-watermark")

        qr_image = render_ops.build_opaque_qr_bytes(crypto.encrypt_qr_payload(secret, key))
        visible_payload = crypto.encrypt_visible_payload(secret, key)
        recipient = " ".join((intended_for or "").split())[:60]
        if recipient and not recipient.lower().startswith(("group ", "group_")):
            recipient = f"Group {recipient}"
        visible_group = f"{recipient or 'Group UNKNOWN'} - "
        seed_material = (secret + ":" + key).encode("utf-8")

        with fitz.open(stream=data, filetype="pdf") as doc:
            for page in doc:
                qr_rect = self._place_qr_code(page, seed_material)
                pdf_ops.stamp_qr_on_page(page, qr_image, qr_rect)
                render_ops.stamp_random_native_visible_text(
                    page=page,
                    label=visible_group + visible_payload,
                    placed_boxes=[qr_rect],
                    seed_material=seed_material,
                )

            return doc.tobytes(garbage=0, deflate=True, encryption=fitz.PDF_ENCRYPT_NONE)

    @staticmethod
    def _place_qr_code(page: fitz.Page, seed_material: bytes) -> tuple[float, float, float, float]:
        """Place a QR code in a free border area or fall back to a page corner."""
        width, height = page.rect.width, page.rect.height
        try:
            return render_ops.random_qr_rect(
                width, height, render_ops.collect_page_content_boxes(page), seed_material,
            )
        except ValueError:
            return render_ops.corner_qr_rect(width, height, seed_material)

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        crypto.derive_aes_key(key)
        data = load_pdf_bytes(pdf)
        if not pdf_ops.is_document_applicable(data):
            raise ValueError("PDF is not applicable to francesco-watermark")

        found: set[str] = set()
        with fitz.open(stream=data, filetype="pdf") as document:
            for page in document:
                image = pdf_ops.rasterize_page(page, dpi=pdf_ops.DEFAULT_DPI)
                for barcode in zxingcpp.read_barcodes(image, formats=zxingcpp.BarcodeFormat.QRCode):
                    if not crypto.is_candidate_payload(barcode.text):
                        continue
                    # A QR that does not authenticate (wrong key, or a decoy pasted by the
                    # leaker) must not hide the real ones.
                    try:
                        found.add(crypto.decrypt_qr_payload(barcode.text, key))
                    except InvalidKeyError:
                        logger.debug("Ignoring a QR code that does not authenticate")

        if not found:
            with fitz.open(stream=data, filetype="pdf") as document:
                found.update(visible_ops.read_visible_secrets(document, key))

        if len(found) > 1:
            raise WatermarkingError("Conflicting francesco-watermark copy identifiers")
        if not found:
            raise SecretNotFoundError("No valid francesco-watermark QR code found")
        return found.pop()
