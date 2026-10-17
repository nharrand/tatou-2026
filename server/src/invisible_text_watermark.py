"""invisible_text_watermark.py

Watermarking method that embeds a secret as invisible white text
drawn directly onto the first page of the PDF using PyMuPDF.

The text is rendered in font size 1, white color, at a fixed position
in the bottom-left corner — invisible to readers but extractable
programmatically. The secret is authenticated with HMAC-SHA256 using
the provided key, then Base64-encoded and written as the invisible text.

Author: Yomal Moderage — Group 17
"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import hmac
import json

import pymupdf as fitz  # PyMuPDF

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)

MARKER = "WM-INVISIBLE-V1:"


class InvisibleTextWatermark(WatermarkingMethod):
    """Embeds secret as invisible white text on the first PDF page.

    The payload written into the PDF is:
        WM-INVISIBLE-V1:<base64url(json)>

    JSON schema: {"v":1,"alg":"HMAC-SHA256","mac":"<hex>","secret":"<b64>"}
    """

    name: Final[str] = "invisible-text"
    _CONTEXT: Final[bytes] = b"wm:invisible-text:v1:"

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds secret as invisible white text on the first page. "
            "Key is used for HMAC-SHA256 authentication. Position is ignored."
        )

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not key:
            raise ValueError("Key must be a non-empty string")

        # Build authenticated payload
        secret_bytes = secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        text_to_embed = MARKER + payload_b64

        # Open PDF and draw invisible text on page 0
        doc = fitz.open(stream=data, filetype="pdf")
        if doc.page_count == 0:
            doc.close()
            raise ValueError("PDF has no pages — cannot apply invisible-text watermark")
        page = doc[0]

        # White text, font size 1, bottom-left corner — invisible to human readers
        page.insert_text(
            fitz.Point(1, page.rect.height - 1),
            text_to_embed,
            fontsize=1,
            color=(1, 1, 1),   # RGB white
            overlay=False,
        )

        out = doc.tobytes(garbage=4, deflate=True)
        doc.close()
        return out

    def is_watermark_applicable(self, pdf, position=None) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            count = doc.page_count
            doc.close()
            return count > 0
        except Exception:
            return False

    def read_secret(self, pdf, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not key:
            raise ValueError("Key must be a non-empty string")

        doc = fitz.open(stream=data, filetype="pdf")
        page = doc[0]

        # Extract all text including invisible
        text = page.get_text("text")
        doc.close()

        # Find our marker
        idx = text.find(MARKER)
        if idx == -1:
            raise SecretNotFoundError("No invisible-text watermark found")

        payload_b64 = text[idx + len(MARKER):].strip().split()[0]

        try:
            obj = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:
            raise SecretNotFoundError("Malformed watermark payload") from e

        if not (isinstance(obj, dict) and obj.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version")
        if obj.get("alg") != "HMAC-SHA256":
            raise SecretNotFoundError("Unsupported algorithm")

        try:
            mac_hex = str(obj["mac"])
            secret_bytes = base64.b64decode(obj["secret"].encode("ascii"))
        except Exception as e:
            raise SecretNotFoundError("Invalid payload fields") from e

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")

    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        hm = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + secret_bytes,
            hashlib.sha256,
        )
        return hm.hexdigest()


__all__ = ["InvisibleTextWatermark"]
