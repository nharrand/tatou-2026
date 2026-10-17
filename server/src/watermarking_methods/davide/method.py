"""Watermark PDF images without changing text, fonts, or page layout.

AES-SIV protects the recoverable secret. Recipient fingerprints support attribution
after image transformations. Extraction tries supported payload lengths and accepts only
authenticated ciphertext.
"""

from __future__ import annotations

import hashlib
import io
import logging
from collections.abc import Iterator

import numpy as np
import pymupdf as fitz
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from PIL import Image

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

from .image import (
    capacity,
    embed_fingerprint,
    embed_payload,
    fingerprint_scores,
    read_votes,
    vote,
)

logger = logging.getLogger(__name__)

# The server runs a single worker: bigger images are skipped and every document has a total
# budget of pixels.
_MAX_PIXELS = 2048 * 2048
_MAX_TOTAL_PIXELS = 4 * _MAX_PIXELS
# Fallback for scanned pages (about 9 MP at 300 DPI): bigger images are used only when no image
# within the limits above can be marked.
_MAX_SCAN_PIXELS = 12_000_000
_MAX_SCAN_TOTAL_PIXELS = 2 * _MAX_SCAN_PIXELS

MAX_SECRET_BYTES = 128
TAG_BYTES = 16        # Added by AES-SIV.
MIN_REPETITIONS = 8   # Every bit is written at least this many times.
JPEG_QUALITY = 92


def _cipher(key: str) -> AESSIV:
    # AES-SIV needs a 64 byte key, the configured key can be any string.
    return AESSIV(hashlib.sha512(key.encode("utf-8")).digest())


def encrypt(secret: str, key: str) -> bytes:
    data = secret.encode("utf-8")
    if not 0 < len(data) <= MAX_SECRET_BYTES:
        raise ValueError(f"Secret must be 1-{MAX_SECRET_BYTES} bytes")
    return _cipher(key).encrypt(data, None)


def decrypt(ciphertext: bytes, key: str) -> str | None:
    """Return the authenticated secret, or None for an invalid key or payload."""
    try:
        return _cipher(key).decrypt(ciphertext, None).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError):
        return None


def _images(doc) -> Iterator[tuple[int, Image.Image]]:
    """Yield eligible image xrefs and decoded images within the normal limits."""
    return _pass(doc, _MAX_PIXELS, _MAX_TOTAL_PIXELS, set())


def _scan_images(doc) -> Iterator[tuple[int, Image.Image]]:
    """Yield remaining images that fit the scanned-page limits."""
    return _pass(doc, _MAX_SCAN_PIXELS, _MAX_SCAN_TOTAL_PIXELS,
                 {xref for xref, _ in _images(doc)})


def _pass(doc, max_pixels: int, budget: int, skip: set[int]) -> Iterator[tuple[int, Image.Image]]:
    seen = set(skip)
    for page in doc:
        for info in page.get_images(full=True):
            xref, width, height = info[0], info[2], info[3]
            if xref in seen or width * height > min(max_pixels, budget):
                continue
            seen.add(xref)

            # Stencil masks are 1-bit shapes: nothing to mark, and RGB would break them.
            if doc.xref_get_key(xref, "ImageMask")[1] == "true":
                continue
            try:
                img = Image.open(io.BytesIO(doc.extract_image(xref)["image"]))
                # Validate embedded dimensions before decoding pixel data.
                pixels = max(width * height, img.width * img.height)
                if pixels > min(max_pixels, budget):
                    continue
                if doc.xref_get_key(xref, "Decode")[0] != "null":
                    # Extracted samples alone do not include the PDF's Decode transformation.
                    # Apply it before replacing the dictionary.
                    pix = fitz.Pixmap(doc, xref)
                    if pix.colorspace != fitz.csRGB:
                        pix = fitz.Pixmap(fitz.csRGB, pix)
                    if pix.alpha:
                        pix = fitz.Pixmap(pix, 0)
                    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
                else:
                    img = img.convert("RGB")
            except (KeyError, OSError, RuntimeError, ValueError,
                    Image.DecompressionBombError, fitz.mupdf.FzErrorBase) as error:
                # Native exception messages can contain private PDF values.
                logger.debug("Skipping unreadable PDF image %s: %s", xref, type(error).__name__)
                continue

            budget -= pixels
            yield xref, img


def _read_image(img: Image.Image, key: str) -> str | None:
    votes = read_votes(img, key)
    # The length is not stored: only the right one passes AES-SIV.
    for length in range(1, MAX_SECRET_BYTES + 1):
        secret = decrypt(np.packbits(vote(votes, (length + TAG_BYTES) * 8)).tobytes(), key)
        if secret is not None:
            return secret
    return None


def _page_box(doc, xref: int) -> tuple[float, float, float, float] | None:
    """Return the image placement as fractions of its page dimensions."""
    for page in doc:
        rects = page.get_image_rects(xref)
        if rects:
            r, p = rects[0], page.rect
            return r.x0 / p.width, r.y0 / p.height, r.x1 / p.width, r.y1 / p.height
    return None


def _replace_image(doc, xref: int, img: Image.Image) -> None:
    """Overwrite the image object, so no unmarked copy stays in the file."""
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=JPEG_QUALITY, subsampling=0)
    doc.update_stream(xref, buf.getvalue(), compress=False)
    for name, value in (("Filter", "/DCTDecode"), ("DecodeParms", "null"), ("Decode", "null"),
                        ("ColorSpace", "/DeviceRGB"), ("BitsPerComponent", "8"),
                        ("Width", str(img.width)), ("Height", str(img.height))):
        doc.xref_set_key(xref, name, value)


class DavideWatermark(WatermarkingMethod):
    name = "davide-watermark"

    # Innocent scores follow N(0, 1): with 64 recipients and 4 comparisons each, a threshold of
    # 6 accuses an innocent less than once in 10^6 reads.
    ATTRIBUTION_THRESHOLD = 6.0

    @classmethod
    def get_usage(cls) -> str:
        return "Embed an encrypted watermark and a recipient fingerprint in the PDF's images"

    @classmethod
    def is_watermark_applicable(cls, pdf: PdfSource, position: str | None = None,
                                *, scans: bool = True) -> bool:
        # Require a normal image that holds the longest supported secret; ignore placement
        # hints.
        needed = (MAX_SECRET_BYTES + TAG_BYTES) * 8 * MIN_REPETITIONS
        try:
            with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
                return not doc.is_encrypted and (
                    any(capacity(img) >= needed for _, img in _images(doc))
                    or (scans and any(capacity(img) >= needed for _, img in _scan_images(doc))))
        except (OSError, RuntimeError, TypeError, ValueError):
            return False

    @classmethod
    def add_watermark(cls, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        if not key:
            raise InvalidKeyError("Key must not be empty")
        bits = np.unpackbits(np.frombuffer(encrypt(secret, key), dtype=np.uint8))

        with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            marked = 0
            # Scanned pages only when no normal image fits.
            for images in (_images, _scan_images):
                for xref, img in images(doc):
                    if capacity(img) < len(bits) * MIN_REPETITIONS:
                        continue
                    img = embed_fingerprint(embed_payload(img, bits, key), key, secret)
                    _replace_image(doc, xref, img)
                    marked += 1
                if marked:
                    break

            if not marked:
                raise WatermarkingError("PDF does not contain a large enough image")
            # garbage=3 drops the old unmarked image streams.
            return doc.tobytes(garbage=3, deflate=True, encryption=fitz.PDF_ENCRYPT_NONE)

    @classmethod
    def read_secret(cls, pdf: PdfSource, key: str) -> str:
        if not key:
            raise InvalidKeyError("Key must not be empty")

        with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            found = {secret for _, img in _images(doc) if (secret := _read_image(img, key)) is not None}
            if not found:
                found = {secret for _, img in _scan_images(doc)
                         if (secret := _read_image(img, key)) is not None}

        # Images taken from two different copies: better no answer than a wrong one.
        if len(found) > 1:
            raise WatermarkingError("Conflicting watermarks: the images come from different copies")
        if not found:
            raise SecretNotFoundError("No watermark found")
        return found.pop()

    @classmethod
    def score_recipients(cls, pdf: PdfSource, original: PdfSource, key: str, secrets: list[str],
                         *, scans: bool = True) -> dict[str, float]:
        """Return recipient fingerprint scores by comparing the leaked and original PDFs."""
        if not key:
            raise InvalidKeyError("Key must not be empty")

        scores = _scores(pdf, original, key, secrets, _images)
        # Secrets that add_watermark had to put in scanned pages.
        with fitz.open(stream=load_pdf_bytes(original), filetype="pdf") as doc:
            caps = [capacity(img) for _, img in _images(doc)]
        scanned = [secret for secret in secrets
                   if not any(c >= (len(secret.encode("utf-8")) + TAG_BYTES) * 8 * MIN_REPETITIONS
                              for c in caps)]
        if scans and scanned:
            scores.update(_scores(pdf, original, key, scanned, _scan_images))
        return scores


def _scores(pdf: PdfSource, original: PdfSource, key: str, secrets: list[str], images) -> dict[str, float]:
    with fitz.open(stream=load_pdf_bytes(original), filetype="pdf") as doc:
        originals = [(img, _page_box(doc, xref)) for xref, img in images(doc)]

    scores = {secret: float("-inf") for secret in secrets}
    with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
        # Images may have been reordered, so every pair is tried.
        for _, leak in images(doc):
            for source, box in originals:
                candidates = [leak]
                # The leak may be a screenshot of the whole page.
                if box is not None:
                    x0, y0, x1, y1 = box
                    candidates.append(leak.crop((round(x0 * leak.width), round(y0 * leak.height),
                                                 round(x1 * leak.width), round(y1 * leak.height))))
                for candidate in candidates:
                    for secret, z in fingerprint_scores(candidate, source, key, secrets).items():
                        scores[secret] = max(scores[secret], z)
    return scores
