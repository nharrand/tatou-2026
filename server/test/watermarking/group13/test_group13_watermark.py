"""Verify combined-layer preservation, extraction, and fallback behavior."""

from __future__ import annotations

import io
import logging
from types import SimpleNamespace
from unittest.mock import Mock

import numpy as np
import pymupdf as fitz
import pytest
from PIL import Image

from watermarking_method import SecretNotFoundError, WatermarkingError
from watermarking_methods.davide.method import DavideWatermark
from watermarking_methods.group13 import Group13Watermark
from watermarking_methods.group13 import method as group13_module
from watermarking_methods.group13.method import MAX_SECRET_BYTES
from watermarking_methods.khaled import KhaledTextSpacingWatermark
from watermarking_utils import METHODS, apply_watermark, read_watermark

SECRET = "Group_07:da0bb583c432fbfd078959ecc9b62902"
OTHER = "Group_09:0123456789abcdef0123456789abcdef"
KEY = "test-only-group13-watermark-key"
ALL_LAYERS = ["davide-watermark", "khaled-text-spacing-watermark", "francesco-watermark"]

G13 = Group13Watermark()


def _photo() -> bytes:
    rng = np.random.default_rng(13)
    y, x = np.mgrid[0:700, 0:900]
    pixels = np.stack([128 + 60 * np.sin(x / 37), 128 + 60 * np.cos(y / 29),
                       128 + 40 * np.sin((x + y) / 53)], -1) + rng.normal(0, 12, (700, 900, 3))
    buf = io.BytesIO()
    Image.fromarray(pixels.clip(0, 255).astype(np.uint8)).save(buf, "JPEG", quality=92)
    return buf.getvalue()


def _pdf(image: bool = True, text: bool = True) -> bytes:
    with fitz.open() as doc:
        if image:
            doc.new_page().insert_image(fitz.Rect(100, 150, 495, 457), stream=_photo())
        if text:
            page = doc.new_page()
            sentence = "Tatou carries a traceable secret in selectable letters here."
            for row in range(40):
                page.insert_text((70, 110 + row * 16), sentence, fontsize=10)
        if not image and not text:
            doc.new_page()
        return doc.tobytes()


@pytest.fixture(scope="module")
def source() -> bytes:
    return _pdf()


@pytest.fixture(scope="module")
def marked(source) -> bytes:
    return G13.add_watermark(source, SECRET, KEY)


@pytest.fixture(scope="module")
def blank_pdf() -> bytes:
    return _pdf(image=False, text=False)


@pytest.fixture
def layer_mocks(monkeypatch, blank_pdf):
    """Isolate composition decisions; real carrier/crypto tests stay separate."""
    layers = {}
    for name in ("DAVIDE", "KHALED", "FRANCESCO"):
        layer = Mock()
        layer.name = name.lower()
        layer.is_watermark_applicable.return_value = name == "DAVIDE"
        layer.add_watermark.return_value = blank_pdf + b"\n%" + name.encode("ascii")
        layer.read_secret.return_value = SECRET
        monkeypatch.setattr(group13_module, name, layer)
        layers[name.lower()] = layer
    return SimpleNamespace(**layers)


@pytest.fixture(scope="module")
def tolerant_only_pdf() -> bytes:
    """Create scaled text and inline images accepted only by tolerant parsing."""
    sentence = "Tatou carries a traceable secret in selectable letters on scaled text"
    with fitz.open() as doc:
        page = doc.new_page()
        page.insert_text((30, 40), "x", fontsize=10)
        font = page.get_fonts()[0][4]
        lines = [f"BT /{font} 1 Tf 0.01 Tc 10 0 0 10.4 30 {40 + row * 18} Tm ({sentence}) Tj ET"
                 for row in range(42)]
        content = "q 0.1 0 0 0.1 0 0 cm q 10 0 0 10 0 0 cm " + " ".join(lines) + " Q Q"
        doc.update_stream(page.get_contents()[0], content.encode("ascii"))
        inline = doc.new_page()
        inline.insert_text((30, 40), "x", fontsize=10)
        doc.update_stream(inline.get_contents()[0],
                          b"q 10 0 0 10 50 50 cm BI /W 1 /H 1 /BPC 8 /CS /G ID \x80 EI Q")
        return doc.tobytes()


def test_registered_and_every_layer_readable(source, marked):
    assert isinstance(METHODS["group13-watermark"], Group13Watermark)
    assert G13.is_watermark_applicable(source)
    assert G13.embedded_layers(marked, KEY, SECRET) == ALL_LAYERS
    assert read_watermark("group13-watermark", marked, KEY) == SECRET
    assert G13.read_secret(io.BytesIO(marked), KEY) == SECRET
    with fitz.open(stream=source, filetype="pdf") as a, fitz.open(stream=marked, filetype="pdf") as b:
        assert [p.get_text() for p in a] == [p.get_text() for p in b]


def test_distinct_recipients_get_distinct_copies(source, marked):
    other = apply_watermark("group13-watermark", source, OTHER, KEY)
    assert other != marked
    assert G13.read_secret(other, KEY) == OTHER


def test_wrong_key_and_unmarked_pdf_find_nothing(source, marked):
    with pytest.raises(SecretNotFoundError):
        G13.read_secret(marked, "another-key")
    with pytest.raises(SecretNotFoundError):
        G13.read_secret(source, KEY)


@pytest.mark.parametrize("secret", [None, 7, b"secret", "", "x" * (MAX_SECRET_BYTES + 1), "\u00e9" * 25])
def test_invalid_secret_is_rejected_before_layer_processing(blank_pdf, layer_mocks, secret):
    with pytest.raises(ValueError):
        G13.add_watermark(blank_pdf, secret, KEY)

    for layer in vars(layer_mocks).values():
        layer.is_watermark_applicable.assert_not_called()
        layer.add_watermark.assert_not_called()


@pytest.mark.parametrize("secret", ["x", "x" * MAX_SECRET_BYTES, "\u00e9" * 24])
def test_secret_boundaries_are_inclusive(blank_pdf, layer_mocks, secret):
    layer_mocks.davide.read_secret.return_value = secret

    output = G13.add_watermark(blank_pdf, secret, KEY)

    assert output == layer_mocks.davide.add_watermark.return_value
    layer_mocks.davide.add_watermark.assert_called_once_with(blank_pdf, secret, KEY)
    layer_mocks.davide.read_secret.assert_called_once_with(output, KEY)


@pytest.mark.parametrize("pdf", [None, b"not a PDF"])
def test_applicability_rejects_invalid_input(pdf):
    assert not G13.is_watermark_applicable(pdf)


@pytest.mark.parametrize("image,text", [(True, False), (False, True)])
def test_one_invisible_carrier_is_sufficient_for_applicability(image, text):
    assert G13.is_watermark_applicable(_pdf(image=image, text=text))


def test_applicability_excludes_tolerant_only_text(tolerant_only_pdf):
    assert KhaledTextSpacingWatermark.is_watermark_applicable(tolerant_only_pdf)
    assert not KhaledTextSpacingWatermark.is_watermark_applicable(tolerant_only_pdf, tolerant=False)
    assert not G13.is_watermark_applicable(tolerant_only_pdf)


def test_embedding_excludes_tolerant_only_text(tolerant_only_pdf):
    with pytest.raises(WatermarkingError):
        G13.add_watermark(tolerant_only_pdf, SECRET, KEY)


def test_recipient_is_forwarded_to_francesco(blank_pdf, layer_mocks):
    layer_mocks.francesco.is_watermark_applicable.return_value = True

    G13.add_watermark(blank_pdf, SECRET, KEY, intended_for="Group 13")

    layer_mocks.francesco.add_watermark.assert_called_once_with(
        layer_mocks.davide.add_watermark.return_value, SECRET, KEY, intended_for="Group 13"
    )


def test_optional_francesco_failure_preserves_other_layers(blank_pdf, layer_mocks, caplog):
    layer_mocks.francesco.is_watermark_applicable.return_value = True
    layer_mocks.francesco.add_watermark.side_effect = ValueError(f"private-layer-canary {KEY} {SECRET}")

    with caplog.at_level(logging.WARNING, logger=group13_module.__name__):
        output = G13.add_watermark(blank_pdf, SECRET, KEY)

    assert output == layer_mocks.davide.add_watermark.return_value
    layer_mocks.davide.read_secret.assert_called_once_with(output, KEY)
    layer_mocks.francesco.read_secret.assert_not_called()
    warnings = [record for record in caplog.records
                if record.name == group13_module.__name__ and record.levelno == logging.WARNING]
    assert warnings
    assert all(record.getMessage() for record in warnings)
    assert all(value not in caplog.text for value in ("private-layer-canary", KEY, SECRET))


@pytest.mark.parametrize("error", [SecretNotFoundError, ValueError, RuntimeError, OSError])
def test_reading_falls_back_with_valid_debug_diagnostic(blank_pdf, layer_mocks, caplog, error):
    layer_mocks.khaled.read_secret.side_effect = error(f"private-layer-canary {KEY} {SECRET}")

    with caplog.at_level(logging.DEBUG, logger=group13_module.__name__):
        assert G13.read_secret(blank_pdf, KEY) == SECRET

    layer_mocks.khaled.read_secret.assert_called_once_with(blank_pdf, KEY)
    layer_mocks.davide.read_secret.assert_called_once_with(blank_pdf, KEY)
    layer_mocks.francesco.read_secret.assert_not_called()
    diagnostics = [record for record in caplog.records
                   if record.name == group13_module.__name__ and record.levelno == logging.DEBUG]
    assert diagnostics
    assert all(record.getMessage() for record in diagnostics)
    assert all(value not in caplog.text for value in ("private-layer-canary", KEY, SECRET))


def test_fingerprint_attribution_excludes_scan_fallback(monkeypatch):
    import watermarking_methods.davide.method as davide_module

    # Exercise the real fallback without allocating a multi-megapixel fixture.
    monkeypatch.setattr(davide_module, "_MAX_PIXELS", 500 * 500)
    original = _pdf(text=False)
    marked = DavideWatermark.add_watermark(original, SECRET, KEY)
    candidates = [SECRET, OTHER]

    standalone = DavideWatermark.score_recipients(marked, original, KEY, candidates)
    assert standalone[SECRET] > G13.ATTRIBUTION_THRESHOLD > standalone[OTHER]
    combined = G13.score_recipients(marked, original, KEY, candidates)
    assert set(combined) == set(candidates)
    assert all(score < G13.ATTRIBUTION_THRESHOLD for score in combined.values())


def test_missing_carriers_skip_their_layer():
    image_only = G13.add_watermark(_pdf(text=False), SECRET, KEY)
    assert G13.embedded_layers(image_only, KEY, SECRET) == ["davide-watermark", "francesco-watermark"]
    text_only = G13.add_watermark(_pdf(image=False), SECRET, KEY)
    assert G13.embedded_layers(text_only, KEY, SECRET) == ["khaled-text-spacing-watermark",
                                                           "francesco-watermark"]


def test_pdf_without_invisible_carrier_is_rejected():
    empty = _pdf(image=False, text=False)
    assert not G13.is_watermark_applicable(empty)
    with pytest.raises(WatermarkingError):
        G13.add_watermark(empty, SECRET, KEY)


def test_resave_with_garbage_collection_keeps_every_layer(marked):
    # Merged overlay streams must preserve text carriers.
    with fitz.open(stream=marked, filetype="pdf") as doc:
        resaved = doc.tobytes(garbage=4, deflate=True, clean=True)
    assert G13.embedded_layers(resaved, KEY, SECRET) == ALL_LAYERS


def test_text_layer_survives_dropping_the_cover(marked):
    with fitz.open(stream=marked, filetype="pdf") as doc:
        doc.delete_page(0)
        no_cover = doc.tobytes(garbage=3, deflate=True)
    assert KhaledTextSpacingWatermark.read_secret(no_cover, KEY) == SECRET


def test_each_layer_alone_is_enough(marked):
    with fitz.open(stream=marked, filetype="pdf") as doc:
        # Remove every image: the image and QR layers are gone, the text stays.
        for page in doc:
            for xref in {info[0] for info in page.get_images(full=True)}:
                page.delete_image(xref)
        text_left = doc.tobytes(garbage=4, deflate=True)
    assert G13.embedded_layers(text_left, KEY, SECRET) == ["khaled-text-spacing-watermark"]
    assert G13.read_secret(text_left, KEY) == SECRET

    with fitz.open(stream=marked, filetype="pdf") as doc:
        doc.delete_page(1)
        image_left = doc.tobytes(garbage=3, deflate=True)
    assert "davide-watermark" in G13.embedded_layers(image_left, KEY, SECRET)
    assert G13.read_secret(image_left, KEY) == SECRET


def test_mixed_copies_return_a_real_recipient(source, marked):
    other = G13.add_watermark(source, OTHER, KEY)
    with fitz.open(stream=marked, filetype="pdf") as a, fitz.open(stream=other, filetype="pdf") as b:
        mixed = fitz.open()
        mixed.insert_pdf(a, from_page=0, to_page=0)   # Images of SECRET.
        mixed.insert_pdf(b, from_page=1, to_page=1)   # Text of OTHER.
        leak = mixed.tobytes()
        mixed.close()
    assert G13.read_secret(leak, KEY) in {SECRET, OTHER}


def test_fingerprint_attribution_identifies_recipient(source, marked):
    scores = G13.score_recipients(marked, source, KEY, [SECRET, OTHER])
    assert scores[SECRET] > G13.ATTRIBUTION_THRESHOLD > scores[OTHER]
    assert G13.ATTRIBUTION_THRESHOLD == DavideWatermark.ATTRIBUTION_THRESHOLD


def test_layer_selection_preserves_group13_carrier_limits(monkeypatch):
    # The fallbacks of the single methods (scanned pages, long documents, tolerant text) do not
    # change which layers group13 applies.
    import watermarking_methods.davide.method as davide_module

    with fitz.open() as doc:
        for _ in range(12):  # Francesco alone accepts it, group13 keeps the 10-page limit.
            page = doc.new_page()
            for row in range(40):
                page.insert_text((70, 110 + row * 16), "Tatou carries a traceable secret here.", fontsize=10)
        long_text = doc.tobytes()
    out = G13.add_watermark(long_text, SECRET, KEY)
    assert G13.embedded_layers(out, KEY, SECRET) == ["khaled-text-spacing-watermark"]

    monkeypatch.setattr(davide_module, "_MAX_PIXELS", 600 * 600)
    scan_only = _pdf(text=False)
    assert DavideWatermark.is_watermark_applicable(scan_only)
    assert not G13.is_watermark_applicable(scan_only)
    with pytest.raises(WatermarkingError):
        G13.add_watermark(scan_only, SECRET, KEY)
