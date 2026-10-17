"""PDF geometry validation and native overlay helpers."""

from __future__ import annotations

import math
from typing import Final

import pymupdf as fitz
from PIL import Image

DEFAULT_DPI: Final[int] = 300
MAX_INPUT_BYTES: Final[int] = 64 * 1024 * 1024
MAX_PAGES: Final[int] = 64
MAX_PIXELS_PER_PAGE: Final[int] = 16_000_000


def is_document_applicable(data: bytes, max_pages: int = MAX_PAGES) -> bool:
    """Validate document limits: page count, unencrypted status, and DPI pixel bounds."""
    if len(data) > MAX_INPUT_BYTES:
        return False
    try:
        with fitz.open(stream=data, filetype="pdf") as document:
            if document.is_encrypted or not 1 <= document.page_count <= max_pages:
                return False
            for page in document:
                width = math.ceil(page.rect.width * DEFAULT_DPI / 72)
                height = math.ceil(page.rect.height * DEFAULT_DPI / 72)
                if width < 500 or height < 500 or width * height > MAX_PIXELS_PER_PAGE:
                    return False
    except (fitz.FileDataError, ValueError, RuntimeError):
        return False
    return True


def rasterize_page(page: fitz.Page, dpi: int = DEFAULT_DPI) -> Image.Image:
    """Rasterize a single PDF page into an RGB PIL Image at the specified DPI."""
    pixmap = page.get_pixmap(dpi=dpi, colorspace=fitz.csRGB, alpha=False)
    return Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)


def stamp_qr_on_page(
    page: fitz.Page,
    qr_bytes: bytes,
    rect: fitz.Rect | tuple[float, float, float, float],
) -> None:
    """Stamp an opaque QR PNG onto a PDF page without modifying existing streams."""
    target_rect = rect if isinstance(rect, fitz.Rect) else fitz.Rect(*rect)
    page.insert_image(target_rect, stream=qr_bytes, keep_proportion=True, overlay=True)
