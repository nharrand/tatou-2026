"""Define the watermarking interface, input types, validation helpers, and errors."""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import IO, ClassVar, TypeAlias

PdfSource: TypeAlias = bytes | str | os.PathLike[str] | IO[bytes]
"""Accept PDF bytes, paths, or binary streams; normalize with load_pdf_bytes."""


class WatermarkingError(Exception):
    """Base class for all watermarking-related errors."""


class SecretNotFoundError(WatermarkingError):
    """Raised when a watermark/secret cannot be found in the PDF."""


class InvalidKeyError(WatermarkingError):
    """Raised when the provided key does not validate/decrypt correctly."""


def load_pdf_bytes(src: PdfSource) -> bytes:
    """Read PDF bytes from bytes, a filesystem path, or a binary stream.

    Raise TypeError for unsupported sources and ValueError for a missing PDF header.
    Filesystem errors propagate to the caller.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not is_pdf_bytes(data):
        raise ValueError("Input does not look like a valid PDF (missing %PDF header)")
    return data


def is_pdf_bytes(data: bytes) -> bool:
    """Check the PDF header without requiring a complete or valid document."""
    return data.startswith(b"%PDF-")


def validate_secret_string(secret: str, max_bytes: int = 64) -> str:
    """Validate that secret is a non-empty string and does not exceed max_bytes UTF-8."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("Secret must be a non-empty string")
    if len(secret.encode("utf-8")) > max_bytes:
        raise ValueError(f"Secret must be 1-{max_bytes} UTF-8 bytes")
    return secret


class WatermarkingMethod(ABC):
    """Define the common interface for embedding and extracting PDF watermarks."""

    # Subclasses provide a stable registry identifier.
    name: ClassVar[str] = "abstract"

    @staticmethod
    @abstractmethod
    def get_usage() -> str:
        """Describe method usage and supported placement options."""
        raise NotImplementedError

    @abstractmethod
    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return PDF bytes containing a secret recoverable with the supplied key.

        Embedding may be randomized. Position hints and capacity limits depend on the
        method. Reject invalid inputs with ValueError or a watermarking error.
        """
        raise NotImplementedError

    @abstractmethod
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """Return whether the PDF has a supported carrier at the requested position.

        Applicability does not validate a particular secret or key; their limits are checked
        when embedding.
        """
        raise NotImplementedError

    @abstractmethod
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Return an authenticated secret from the candidate PDF.

        Raise SecretNotFoundError when no recognizable mark is found, InvalidKeyError for
        key failures where distinguishable, or WatermarkingError for other failures.
        """
        raise NotImplementedError

__all__ = [
    "InvalidKeyError",
    "PdfSource",
    "SecretNotFoundError",
    "WatermarkingError",
    "WatermarkingMethod",
    "is_pdf_bytes",
    "load_pdf_bytes",
    "validate_secret_string",
]
