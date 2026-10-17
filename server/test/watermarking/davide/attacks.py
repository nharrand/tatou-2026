"""Apply image and page transformations to synthetic watermarked PDFs."""

from __future__ import annotations

import io

import numpy as np
import pymupdf as fitz
from PIL import Image, ImageFilter, ImageOps

from watermarking_methods.davide.method import _replace_image


def edit_image(pdf: bytes, change) -> bytes:
    """Transform the first image in place and discard its unmarked stream."""
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        xref = doc[0].get_images()[0][0]
        img = Image.open(io.BytesIO(doc.extract_image(xref)["image"])).convert("RGB")
        _replace_image(doc, xref, change(img))
        return doc.tobytes(garbage=3)


def jpeg(quality: int):
    def change(img):
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=quality)
        return Image.open(buf).convert("RGB")

    return lambda pdf: edit_image(pdf, change)


def resize(factor: float):
    return lambda pdf: edit_image(
        pdf, lambda img: img.resize((round(img.width * factor), round(img.height * factor)), Image.BICUBIC)
    )


def blur(radius: float):
    return lambda pdf: edit_image(pdf, lambda img: img.filter(ImageFilter.GaussianBlur(radius)))


def noise(sigma: float, seed: int = 0):
    def change(img):
        pixels = np.asarray(img, dtype=np.float64)
        pixels = pixels + np.random.default_rng(seed).normal(0, sigma, pixels.shape)
        return Image.fromarray(np.clip(pixels, 0, 255).round().astype(np.uint8))

    return lambda pdf: edit_image(pdf, change)


def crop(keep: float):
    """Keep the central `keep` fraction of each side."""
    def change(img):
        dx, dy = round(img.width * (1 - keep) / 2), round(img.height * (1 - keep) / 2)
        return img.crop((dx, dy, img.width - dx, img.height - dy))

    return lambda pdf: edit_image(pdf, change)


def crop_then_resize(keep: float, factor: float):
    return lambda pdf: resize(factor)(crop(keep)(pdf))


def flip():
    return lambda pdf: edit_image(pdf, ImageOps.mirror)


def everything():
    """Mirror, rotate 2 degrees, crop and shrink together."""
    def change(img):
        img = ImageOps.mirror(img).rotate(2, Image.BICUBIC, fillcolor="white")
        img = img.crop((40, 30, img.width - 80, img.height - 40))
        return img.resize((img.width * 6 // 10, img.height * 6 // 10), Image.BICUBIC)

    return lambda pdf: edit_image(pdf, change)


def rotate(degrees: float):
    return lambda pdf: edit_image(pdf, lambda img: img.rotate(degrees, Image.BICUBIC, fillcolor="white"))


def screenshot(dpi: int, quality: int = 90):
    """Render the whole page and wrap the picture in a new PDF."""
    def attack(pdf):
        with fitz.open(stream=pdf, filetype="pdf") as doc, fitz.open() as out:
            page = doc[0]
            pix = page.get_pixmap(dpi=dpi)
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            buf = io.BytesIO()
            img.save(buf, "JPEG", quality=quality)
            out.new_page(width=page.rect.width, height=page.rect.height).insert_image(page.rect, stream=buf.getvalue())
            return out.tobytes()

    return attack

# KNOWN_FAILURES are the limits of the method.
ATTACKS = {
    "none": lambda pdf: pdf,
    "jpeg-q90": jpeg(90),
    "jpeg-q75": jpeg(75),
    "jpeg-q50": jpeg(50),
    "jpeg-q30": jpeg(30),
    "jpeg-q20": jpeg(20),
    "resize-75%": resize(0.75),
    "resize-50%": resize(0.5),
    "resize-25%": resize(0.25),
    "blur-0.8": blur(0.8),
    "blur-1.5": blur(1.5),
    "noise-3": noise(3),
    "noise-8": noise(8),
    "screenshot-150dpi": screenshot(150),
    "screenshot-96dpi": screenshot(96),
    "crop-80%": crop(0.8),
    "crop-50%": crop(0.5),
    "crop-70%+resize-60%": crop_then_resize(0.7, 0.6),
    "rotate-1deg": rotate(1),
    "rotate-3deg": rotate(3),
    "flip": flip(),
    "flip+rotate+crop+resize": everything(),
}

KNOWN_FAILURES = {
    "rotate-10deg": rotate(10),  # The search stops at 6 degrees.
    "blur-3": blur(3),           # Strong blur exceeds the supported fingerprint recovery range.
}
