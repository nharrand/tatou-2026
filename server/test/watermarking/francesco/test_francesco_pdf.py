"""PDF geometry validation and native PyMuPDF overlay tests."""

from __future__ import annotations

import pymupdf as fitz
import pytest

from watermarking_methods.francesco import pdf as pdf_ops
from watermarking_methods.francesco.method import FrancescoWatermark

KEY = "0123456789abcdef" * 4


def test_document_applicability_rejects_invalid_content_and_geometry(pdf_bytes):
    assert pdf_ops.is_document_applicable(pdf_bytes)

    assert not pdf_ops.is_document_applicable(b"not-a-pdf")

    huge_bytes = b"0" * (pdf_ops.MAX_INPUT_BYTES + 1)
    assert not pdf_ops.is_document_applicable(huge_bytes)

    empty_pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    assert not pdf_ops.is_document_applicable(empty_pdf_bytes)

    with fitz.open() as huge_doc:
        huge_doc.new_page(width=3500, height=3500)
        assert not pdf_ops.is_document_applicable(huge_doc.tobytes())


def test_long_documents_are_applicable_and_readable():
    # Course papers are often 12-45 pages.
    with fitz.open() as doc:
        for number in range(45):
            doc.new_page(width=595, height=842).insert_text((72, 72), f"Page {number}")
        long_pdf = doc.tobytes()
    assert pdf_ops.is_document_applicable(long_pdf)

    method = FrancescoWatermark()
    marked = method.add_watermark(long_pdf, "long-copy", KEY, intended_for="Group_13")
    assert method.read_secret(marked, KEY) == "long-copy"


def test_document_applicability_rejects_excess_pages():
    with fitz.open() as doc:
        for _ in range(pdf_ops.MAX_PAGES + 1):
            doc.new_page()
        assert not pdf_ops.is_document_applicable(doc.tobytes())


@pytest.mark.parametrize(
    "width,height,expected",
    [(120, 120, True), (119.7, 120, False), (120, 119.7, False), (960, 960, True), (960.01, 960, False)],
)
def test_document_applicability_enforces_page_dimension_limits(width, height, expected):
    with fitz.open() as document:
        document.new_page(width=width, height=height)
        assert pdf_ops.is_document_applicable(document.tobytes()) is expected


@pytest.mark.parametrize("pages,expected", [(2, True), (3, False)])
def test_document_applicability_respects_configured_page_limit(pages, expected):
    with fitz.open() as document:
        for _ in range(pages):
            document.new_page()
        assert pdf_ops.is_document_applicable(document.tobytes(), max_pages=2) is expected


def test_encrypted_document_is_rejected():
    with fitz.open() as document:
        document.new_page()
        data = document.tobytes(
            encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="synthetic-owner", user_pw="synthetic-user"
        )
    assert not pdf_ops.is_document_applicable(data)


def test_rasterization_preserves_color_and_dimensions():
    with fitz.open() as document:
        page = document.new_page(width=144, height=216)
        page.draw_rect(page.rect, color=None, fill=(1, 0, 0))
        image = pdf_ops.rasterize_page(page, dpi=72)
        assert image.mode == "RGB"
        assert image.size == (144, 216)
        assert image.getpixel((72, 108)) == (255, 0, 0)


@pytest.mark.parametrize("extra,expected", [(0, True), (1, False)])
def test_input_byte_budget_is_inclusive(monkeypatch, extra, expected):
    with fitz.open() as document:
        document.new_page()
        data = document.tobytes()
    monkeypatch.setattr(pdf_ops, "MAX_INPUT_BYTES", len(data))
    assert pdf_ops.is_document_applicable(data + b" " * extra) is expected


@pytest.mark.parametrize("source", [None, 42, b"invalid-pdf"])
def test_method_applicability_rejects_invalid_sources(source):
    assert not FrancescoWatermark().is_watermark_applicable(source)
