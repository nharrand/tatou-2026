"""Shared contract checks for every registered watermarking method."""
from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import fitz
import pytest

try:
    wm = importlib.import_module("watermarking_utils")
    METHODS = getattr(wm, "METHODS", {})
except ModuleNotFoundError:  # Registry/module missing.
    METHODS = {}

CASES: list[tuple[str, object]] = []
for name, impl in (METHODS or {}).items():
    CASES.append((str(name), impl))

if not CASES:
    pytest.skip("No watermarking methods registered in watermarking_utils.METHODS", allow_module_level=True)


@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    """Create a one-page text PDF for applicability and path-input checks."""
    pdf = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    with fitz.open() as document:
        page = document.new_page()
        page.insert_text((72, 72), "Tatou watermark contract fixture")
        document.save(pdf)
    return pdf

@pytest.fixture(scope="session")
def secret() -> str:
    return "unit-test-secret"

@pytest.fixture(scope="session")
def key() -> str:
    return "unit-test-key"


def _as_instance(impl: object) -> object:
    """Return an instance for class objects; pass instances through."""
    if inspect.isclass(impl):
        return impl()  # Assumes zero-arg constructor.
    return impl


@pytest.mark.parametrize("method_name,impl", CASES, ids=[n for n, _ in CASES])
class TestWatermarkingMethodContracts:
    def test_method_reports_sample_applicability(self, method_name: str, impl: object, sample_pdf_path: Path):
        wm_impl = _as_instance(impl)
        ok = wm_impl.is_watermark_applicable(sample_pdf_path, position=None)
        assert isinstance(ok, bool), f"{method_name}: is_watermark_applicable must return bool"
        if not ok:
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

    def test_embedding_returns_renderable_pdf(self, method_name: str, impl: object, sample_pdf_path: Path,
                                     secret: str, key: str):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")
        out_bytes = wm_impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=None)
        assert isinstance(out_bytes, (bytes, bytearray)), f"{method_name}: add_watermark must return bytes"
        assert out_bytes.startswith(b"%PDF-"), f"{method_name}: output should still look like a PDF"
        with fitz.open(stream=out_bytes, filetype="pdf") as result:
            assert result.page_count == 1, f"{method_name}: output should preserve the page"
            result[0].get_pixmap()

    def test_method_reads_watermarked_file_path(self, method_name: str, impl: object, sample_pdf_path: Path,
                                   secret: str, key: str, tmp_path: Path):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")
        out_pdf = tmp_path / f"{method_name}_watermarked.pdf"
        out_pdf.write_bytes(wm_impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=None))
        extracted = wm_impl.read_secret(out_pdf, key=key)
        assert isinstance(extracted, str), f"{method_name}: read_secret must return str"
        assert extracted == secret, f"{method_name}: read_secret should return the exact embedded secret"
