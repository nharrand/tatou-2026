"""Register watermarking methods and inspect PDF objects.

PDF exploration uses PyMuPDF first and a limited regex fallback when native inspection
fails. The fallback cannot inspect compressed object streams.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Final

from watermarking_method import (
    PdfSource,
    WatermarkingMethod,
    load_pdf_bytes,
)
from watermarking_methods.davide import DavideWatermark
from watermarking_methods.francesco import FrancescoWatermark
from watermarking_methods.group13 import Group13Watermark
from watermarking_methods.khaled import KhaledTextSpacingWatermark

logger = logging.getLogger(__name__)

# Register production methods only. The removable EOF method is reserved for tests.
METHODS: dict[str, WatermarkingMethod] = {
    DavideWatermark.name: DavideWatermark(),
    KhaledTextSpacingWatermark.name: KhaledTextSpacingWatermark(),
    FrancescoWatermark.name: FrancescoWatermark(),
    Group13Watermark.name: Group13Watermark(),
}
"""Map stable method names to instantiated implementations."""


def register_method(method: WatermarkingMethod) -> None:
    """Register (or replace) a watermarking method instance by name."""
    METHODS[method.name] = method


def get_method(method: str | WatermarkingMethod) -> WatermarkingMethod:
    """Return an existing method instance or look up its name.

    Raise KeyError for an unregistered name.
    """
    if isinstance(method, WatermarkingMethod):
        return method
    try:
        return METHODS[method]
    except KeyError as exc:
        raise KeyError(
            f"Unknown watermarking method: {method!r}. Known: {sorted(METHODS)}"
        ) from exc


def apply_watermark(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
    intended_for: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    if m.name in (FrancescoWatermark.name, Group13Watermark.name):
        return m.add_watermark(
            pdf=pdf,
            secret=secret,
            key=key,
            position=position,
            intended_for=intended_for,
        )
    return m.add_watermark(pdf=pdf, secret=secret, key=key, position=position)

def is_watermarking_applicable(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bool:
    """Return whether the method can watermark the PDF at the given position."""
    m = get_method(method)
    return m.is_watermark_applicable(pdf=pdf, position=position)


def read_watermark(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = get_method(method)
    return m.read_secret(pdf=pdf, key=key)

# Pre-compiled regex for the fallback parser (very permissive):
_OBJ_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"(?m)^(\d+)\s+(\d+)\s+obj\b"
)
_ENDOBJ_RE: Final[re.Pattern[bytes]] = re.compile(rb"\bendobj\b")
_TYPE_RE: Final[re.Pattern[bytes]] = re.compile(rb"/Type\s*/([A-Za-z]+)")


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b, usedforsecurity=False).hexdigest()


def explore_pdf(pdf: PdfSource) -> dict[str, Any]:
    """Return a deterministic tree of document, page, and object metadata.

    Each node has a stable id and type. Document nodes contain size and children; page and
    object nodes include available geometry, references, or content hashes. Use the regex
    fallback only when native object inspection fails.
    """
    data = load_pdf_bytes(pdf)

    root: dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")

        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1].
            }
            root["children"].append(node)

        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except (RuntimeError, ValueError, AttributeError):
                s = ""
            # Preserve the native object's text, including escaped PDF names decoded to lone
            # surrogates by the backend. Replacement encoding would give distinct objects the
            # same content fingerprint.
            s_bytes = s.encode("utf-8", "surrogatepass") if isinstance(s, str) else b""

            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except (ImportError, RuntimeError, ValueError, AttributeError) as exc:
        # Fallback: regex-based object scanning (no third-party deps).
        logger.warning(
            "PyMuPDF exploration failed; using regex fallback (%s)",
            type(exc).__name__,
        )

    # Regex fallback: enumerate uncompressed objects.
    children: list[dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]

        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'.
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers.
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root

__all__ = [
    "METHODS",
    "apply_watermark",
    "explore_pdf",
    "get_method",
    "is_watermarking_applicable",
    "read_watermark",
    "register_method"
]
