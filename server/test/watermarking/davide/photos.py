"""Synthetic photos and PDFs for the watermark tests."""

from __future__ import annotations

import io

import numpy as np
import pymupdf as fitz
from PIL import Image


def make_photo(width: int, height: int, seed: int = 1234, smooth: bool = False) -> Image.Image:
    """Generate multiscale texture and noise for a synthetic photo.

    Use smooth=True to retain only large features and limit fixture size.
    """
    rng = np.random.default_rng(seed)
    light = np.zeros((height, width))
    for cell in ((64,) if smooth else (64, 16, 4)):
        blobs = rng.normal(0, 1, (height // cell + 2, width // cell + 2)).astype(np.float32)
        noise = Image.fromarray(blobs).resize((width + 2 * cell, height + 2 * cell), Image.BICUBIC)
        light += np.sqrt(cell) * np.asarray(noise)[:height, :width]
    light = 110 + 45 * light / light.std()
    pixels = light[..., None] + np.array([10, 40, -20])  # Use a green-biased color distribution.
    if not smooth:
        pixels = pixels + rng.normal(0, 6, pixels.shape)
    return Image.fromarray(np.clip(pixels, 0, 255).astype(np.uint8), "RGB")


def photo_pdf(images: list[Image.Image], text: str | None = None) -> bytes:
    """Create a page containing vertically stacked JPEG images."""
    doc = fitz.open()
    page = doc.new_page()
    if text:
        page.insert_text((72, 60), text)
    top = 80
    height = (page.rect.height - 100) / len(images)
    for img in images:
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=90)
        page.insert_image(fitz.Rect(72, top, 522, top + height - 10), stream=buf.getvalue())
        top += height
    return doc.tobytes()
