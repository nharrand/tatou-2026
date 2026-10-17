"""QR decoding across random salts and dense-page placement fallbacks."""

from __future__ import annotations

import pymupdf as fitz
import zxingcpp

from watermarking_methods.francesco import FrancescoWatermark, crypto
from watermarking_methods.francesco import pdf as pdf_ops

KEY = "0123456789abcdef" * 4
SECRET = "Group_07:da0bb583c432fbfd078959ecc9b62902"


def test_qr_roundtrip_is_independent_of_random_salt(pdf_bytes):
    # Exercise several salts because payload patterns affect QR decoding.
    method = FrancescoWatermark()
    for _ in range(6):
        marked = method.add_watermark(pdf_bytes, SECRET, KEY)
        with fitz.open(stream=marked, filetype="pdf") as doc:
            image = pdf_ops.rasterize_page(doc[0], dpi=pdf_ops.DEFAULT_DPI)
        codes = zxingcpp.read_barcodes(image, formats=zxingcpp.BarcodeFormat.QRCode)
        assert [crypto.decrypt_qr_payload(code.text, KEY) for code in codes] == [SECRET]


def _dense_page(doc: fitz.Document) -> None:
    page = doc.new_page(width=595, height=842)
    for row in range(84):  # Text from edge to edge: no free border.
        page.insert_text((2, 10 + row * 10), "busy " * 40, fontsize=9)


def test_dense_page_falls_back_to_fixed_size_edge_codes(pdf_bytes):
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        _dense_page(doc)
        mixed = doc.tobytes()
    method = FrancescoWatermark()
    marked = method.add_watermark(mixed, SECRET, KEY)
    with fitz.open(stream=marked, filetype="pdf") as doc:
        found = [len(zxingcpp.read_barcodes(pdf_ops.rasterize_page(page, dpi=pdf_ops.DEFAULT_DPI),
                                            formats=zxingcpp.BarcodeFormat.QRCode)) for page in doc]
    assert found == [1, 1]
    assert method.read_secret(marked, KEY) == SECRET


def test_no_room_on_any_page_uses_edge_codes():
    with fitz.open() as doc:
        _dense_page(doc)
        dense = doc.tobytes()
    method = FrancescoWatermark()
    marked = method.add_watermark(dense, SECRET, KEY)
    with fitz.open(stream=marked, filetype="pdf") as doc:
        codes = zxingcpp.read_barcodes(
            pdf_ops.rasterize_page(doc[0], dpi=pdf_ops.DEFAULT_DPI),
            formats=zxingcpp.BarcodeFormat.QRCode,
        )
    assert len(codes) == 1
    assert method.read_secret(marked, KEY) == SECRET
