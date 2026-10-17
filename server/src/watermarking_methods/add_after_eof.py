"""Append a Base64-encoded secret authenticated with HMAC after the PDF EOF.

This educational method preserves the original PDF bytes and does not encrypt the
secret. It is excluded from the production method registry.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Final

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class AddAfterEOF(WatermarkingMethod):
    """Append a versioned HMAC record without changing existing PDF bytes.

    The record contains version, algorithm, hex MAC, and Base64 secret fields. The MAC
    authenticates b"wm:add-after-eof:v1:" followed by UTF-8 secret bytes.
    """

    name: Final[str] = "toy-eof"

    _MAGIC: Final[bytes] = b"\n%%WM-ADD-AFTER-EOF:v1\n"
    _CONTEXT: Final[bytes] = b"wm:add-after-eof:v1:"

    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position is ignored."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but ignored by this
        method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        payload = self._build_payload(secret, key)

        # Preserve the original bytes and xref offsets by appending the record.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf, key: str) -> str:
        """Read the final watermark record and verify its HMAC.

        Reject missing, malformed, or unauthenticated records with the method errors.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF.
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # Broad: malformed or tampered.
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: {!r}".format(payload.get("alg")))

        try:
            mac_hex = str(payload["mac"])  # Stored as hex string.
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")

    def _build_payload(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""
        secret_bytes = secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism.
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

__all__ = ["AddAfterEOF"]
