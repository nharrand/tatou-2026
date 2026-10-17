from __future__ import annotations

import base64
import json
import hmac
import hashlib
from typing import Final

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class WhitespaceWatermark(WatermarkingMethod):
    """A simple whitespace-based watermarking method for PDF-like bytes."""

    name: Final[str] = "whitespace"
    _MARKER: Final[bytes] = b"WM-WS-V1:"

    @staticmethod
    def get_usage() -> str:
        return (
            "Appends a compact authenticated payload to the end of the PDF. "
            "The key is used to validate the embedded secret. Position is ignored."
        )

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        payload = {
            "secret": secret,
            "key": key,
            "mac": self._mac(secret, key),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return data + b"\n" + self._MARKER + encoded.encode("ascii")

    def is_watermark_applicable(self, pdf, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False

    def read_secret(self, pdf, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        marker_pos = data.rfind(self._MARKER)
        if marker_pos == -1:
            raise SecretNotFoundError("No whitespace watermark payload found")

        tail = data[marker_pos + len(self._MARKER):].strip()
        if not tail:
            raise SecretNotFoundError("Whitespace watermark payload is missing data")

        payload_b64 = tail.splitlines()[0].strip()
        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        except Exception as exc:
            raise SecretNotFoundError("Malformed whitespace watermark payload") from exc

        secret = payload.get("secret")
        mac = payload.get("mac")
        if not isinstance(secret, str) or not isinstance(mac, str):
            raise SecretNotFoundError("Whitespace watermark payload is missing data")

        expected_mac = self._mac(secret, key)
        if not hmac.compare_digest(mac, expected_mac):
            raise InvalidKeyError("Key mismatch for whitespace watermark")

        return secret

    def _mac(self, secret: str, key: str) -> str:
        digest = hmac.new(key.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()


__all__ = ["WhitespaceWatermark"]
