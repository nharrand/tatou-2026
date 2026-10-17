"""Contract, PDF preservation, error correction, and image composition."""

from __future__ import annotations

import io

import numpy as np
import pymupdf as fitz
import pytest
from PIL import Image

from watermarking_method import SecretNotFoundError, WatermarkingError
from watermarking_methods.khaled import KhaledTextSpacingWatermark
from watermarking_methods.khaled.method import STEP_PT, _keys, _ordered
from watermarking_methods.khaled.pdf_text import (
    carriers,
    collect_runs,
    replace_runs,
)

SECRET = "Group_13:" + "a" * 32
OTHER = "Group_13:" + "b" * 32
KEY = "test-only-high-entropy-watermark-key"


@pytest.fixture(scope="module")
def mixed_pdf() -> bytes:
    rng = np.random.default_rng(913)
    pixels = rng.integers(0, 256, size=(640, 640, 3), dtype=np.uint8)
    image = io.BytesIO()
    Image.fromarray(pixels, "RGB").save(image, format="JPEG", quality=92)

    with fitz.open() as doc:
        cover = doc.new_page()
        cover.insert_image(fitz.Rect(80, 80, 500, 500), stream=image.getvalue())
        text = doc.new_page()
        sentence = ("Tatou carries a traceable secret in selectable letters "
                    "while preserving every word on this document.")
        for row in range(42):
            text.insert_text((30, 35 + row * 18), sentence, fontsize=10)
        return doc.tobytes()


def _page_text(pdf: bytes) -> list[str]:
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        return [page.get_text() for page in doc]


def test_khaled_watermark_roundtrip_preserves_text_and_image(mixed_pdf):
    assert KhaledTextSpacingWatermark.capacity_bits(mixed_pdf) >= 640
    assert KhaledTextSpacingWatermark.is_watermark_applicable(mixed_pdf)

    marked = KhaledTextSpacingWatermark.add_watermark(mixed_pdf, SECRET, KEY)
    assert KhaledTextSpacingWatermark.read_secret(marked, KEY) == SECRET
    assert KhaledTextSpacingWatermark.read_secret(io.BytesIO(marked), KEY) == SECRET
    assert KhaledTextSpacingWatermark.add_watermark(mixed_pdf, SECRET, KEY) == marked
    assert _page_text(marked) == _page_text(mixed_pdf)
    with fitz.open(stream=marked, filetype="pdf") as optimized:
        resaved = optimized.tobytes(garbage=3, clean=True, deflate=True,
                                   no_new_id=True)
    assert KhaledTextSpacingWatermark.read_secret(resaved, KEY) == SECRET
    another = KhaledTextSpacingWatermark.add_watermark(mixed_pdf, OTHER, KEY)
    assert another != marked
    assert KhaledTextSpacingWatermark.read_secret(another, KEY) == OTHER

    with fitz.open(stream=mixed_pdf, filetype="pdf") as original, \
         fitz.open(stream=marked, filetype="pdf") as result:
        old_xref = original[0].get_images(full=True)[0][0]
        new_xref = result[0].get_images(full=True)[0][0]
        assert original.extract_image(old_xref)["image"] == result.extract_image(new_xref)["image"]

    with pytest.raises(SecretNotFoundError):
        KhaledTextSpacingWatermark.read_secret(marked, "wrong-key")
    with pytest.raises(SecretNotFoundError):
        KhaledTextSpacingWatermark.read_secret(mixed_pdf, KEY)


def test_khaled_watermark_rejects_missing_capacity_and_oversized_secret(mixed_pdf):
    with fitz.open(stream=mixed_pdf, filetype="pdf") as doc:
        only_image = fitz.open()
        only_image.insert_pdf(doc, from_page=0, to_page=0)
        image_pdf = only_image.tobytes()
        only_image.close()
    assert not KhaledTextSpacingWatermark.is_watermark_applicable(image_pdf)
    with pytest.raises(WatermarkingError, match="Insufficient text capacity"):
        KhaledTextSpacingWatermark.add_watermark(image_pdf, "secret", KEY)
    with pytest.raises(ValueError, match="48 UTF-8 bytes"):
        KhaledTextSpacingWatermark.add_watermark(mixed_pdf, "x" * 49, KEY)
    with pytest.raises(ValueError, match="automatic placement"):
        KhaledTextSpacingWatermark.add_watermark(mixed_pdf, "secret", KEY, position="page=2")


def test_reed_solomon_repairs_one_changed_carrier(mixed_pdf):
    marked = KhaledTextSpacingWatermark.add_watermark(mixed_pdf, SECRET, KEY)
    with fitz.open(stream=marked, filetype="pdf") as doc:
        item = _ordered(carriers(collect_runs(doc)), _keys(KEY)[1])[0]
        adjustment = STEP_PT * 1000 / (2 * item.run.font_size)
        item.run.gaps[item.middle - 1] -= adjustment
        item.run.gaps[item.middle] += adjustment
        replace_runs(doc, [item.run])
        damaged = doc.tobytes(garbage=3, deflate=True, no_new_id=True)
    assert KhaledTextSpacingWatermark.read_secret(damaged, KEY) == SECRET


def test_text_inheriting_its_font_is_used_and_survives_clean():
    # The font set in one text object stays in effect in the next ones; a resave with clean=True
    # writes Tf in each of them explicitly.
    with fitz.open() as doc:
        page = doc.new_page()
        page.insert_text((70, 72), "font", fontsize=10)  # Registers /helv.
        lines = b"".join(b"BT 70 %d Td (Tatou carries a traceable secret in selectable letters) Tj ET\n"
                         % (760 - row * 16) for row in range(45))
        doc.update_stream(page.get_contents()[0], b"BT /helv 10 Tf ET\n" + lines)
        inherited = doc.tobytes()
    assert KhaledTextSpacingWatermark.capacity_bits(inherited) >= 640

    marked = KhaledTextSpacingWatermark.add_watermark(inherited, SECRET, KEY)
    with fitz.open(stream=marked, filetype="pdf") as doc:
        cleaned = doc.tobytes(garbage=4, clean=True, deflate=True)
    assert KhaledTextSpacingWatermark.read_secret(cleaned, KEY) == SECRET


def _scaled_text_pdf() -> bytes:
    """Create scaled text and an inline-image page that strict parsing rejects."""
    sentence = "Tatou carries a traceable secret in selectable letters on scaled text"
    with fitz.open() as doc:
        page = doc.new_page()
        page.insert_text((30, 40), "x", fontsize=10)  # Adds a WinAnsi Helvetica resource.
        font = page.get_fonts()[0][4]
        lines = [f"BT /{font} 1 Tf 0.01 Tc 10 0 0 10.4 30 {40 + row * 18} Tm ({sentence}) Tj ET"
                 for row in range(42)]
        content = "q 0.1 0 0 0.1 0 0 cm q 10 0 0 10 0 0 cm " + " ".join(lines) + " Q Q"
        doc.update_stream(page.get_contents()[0], content.encode())
        inline = doc.new_page()
        inline.insert_text((30, 40), "x", fontsize=10)
        doc.update_stream(inline.get_contents()[0],
                          b"q 10 0 0 10 50 50 cm BI /W 1 /H 1 /BPC 8 /CS /G ID \x80 EI Q")
        return doc.tobytes()


def test_khaled_tolerant_parsing_handles_scaled_text_and_inline_images():
    pdf = _scaled_text_pdf()
    with fitz.open(stream=pdf, filetype="pdf") as doc, pytest.raises(ValueError):
        collect_runs(doc)  # Strict: the inline image page rejects the document.
    with pytest.raises(ValueError):
        KhaledTextSpacingWatermark.capacity_bits(pdf)
    assert KhaledTextSpacingWatermark.capacity_bits(pdf, tolerant=True) >= 640
    assert KhaledTextSpacingWatermark.is_watermark_applicable(pdf)

    marked = KhaledTextSpacingWatermark.add_watermark(pdf, SECRET, KEY)
    assert KhaledTextSpacingWatermark.read_secret(marked, KEY) == SECRET
    assert _page_text(marked) == _page_text(pdf)


def test_khaled_simple_text_still_uses_strict_carriers(mixed_pdf):
    # Simple text must retain strict carrier selection.
    strict = KhaledTextSpacingWatermark.capacity_bits(mixed_pdf)
    assert strict == KhaledTextSpacingWatermark.capacity_bits(mixed_pdf, tolerant=True)
    marked = KhaledTextSpacingWatermark.add_watermark(mixed_pdf, SECRET, KEY)
    with fitz.open(stream=marked, filetype="pdf") as doc:
        selected = _ordered(carriers(collect_runs(doc)), _keys(KEY)[1])
    assert len(selected) == strict


def _capacity_pdf(count, *, scaled=False):
    with fitz.open() as document:
        page = document.new_page(width=600, height=800)
        page.insert_text((40, 40), "x", fontsize=10)
        font = page.get_fonts()[0][4]
        words = []
        left = count
        row = 0
        while left:
            group = min(left, 19)
            words.append(f"BT 40 {750-row*17} Td ({'A' * (2*group+1)}) Tj ET\n")
            row += 1
            left -= group
        prefix = f"BT /{font} 10 Tf {200 if scaled else 100} Tz ET\n"
        document.update_stream(page.get_contents()[0], (prefix + "".join(words)).encode())
        return document.tobytes()


@pytest.mark.parametrize("capacity,expected", [(639, False), (640, True), (641, True)])
@pytest.mark.parametrize("scaled", [False, True])
def test_applicability_has_reachable_inclusive_capacity_boundary(capacity, expected, scaled):
    pdf = _capacity_pdf(capacity, scaled=scaled)
    assert KhaledTextSpacingWatermark.capacity_bits(pdf, tolerant=scaled) == capacity
    assert KhaledTextSpacingWatermark.is_watermark_applicable(pdf) is expected
    assert KhaledTextSpacingWatermark.is_watermark_applicable(pdf, tolerant=False) is (expected and not scaled)


@pytest.mark.parametrize("secret", ["x", "\u00e9", "x" * 48, "\u00e9" * 24])
@pytest.mark.parametrize("scaled", [False, True])
def test_secret_byte_boundaries_fit_exact_packet_capacity(secret, scaled):
    needed = (len(secret.encode()) + 32) * 8
    pdf = _capacity_pdf(needed, scaled=scaled)
    marked = KhaledTextSpacingWatermark.add_watermark(pdf, secret, KEY)
    assert KhaledTextSpacingWatermark.read_secret(marked, KEY) == secret
    assert _page_text(marked) == _page_text(pdf)


@pytest.mark.parametrize("secret,error", [
    ("", ValueError), ("\u00e9" * 25, ValueError), (None, TypeError), (b"x", TypeError),
])
def test_invalid_secret_is_rejected_before_pdf_processing(secret, error):
    with pytest.raises(error):
        KhaledTextSpacingWatermark.add_watermark(b"not-a-pdf", secret, KEY)


@pytest.mark.parametrize("position", [None, "", "auto"])
def test_supported_placement_aliases(position):
    pdf = _capacity_pdf(640)
    assert KhaledTextSpacingWatermark.is_watermark_applicable(pdf, position)
    marked = KhaledTextSpacingWatermark.add_watermark(pdf, "x", KEY, position)
    assert KhaledTextSpacingWatermark.read_secret(marked, KEY) == "x"


@pytest.mark.parametrize("signed", [False, True])
def test_protected_documents_do_not_offer_capacity(signed):
    with fitz.open(stream=_capacity_pdf(640), filetype="pdf") as document:
        if signed:
            acroform = document.get_new_xref()
            document.update_object(acroform, "<< /SigFlags 1 >>")
            document.xref_set_key(document.pdf_catalog(), "AcroForm", f"{acroform} 0 R")
            pdf = document.tobytes()
        else:
            pdf = document.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256,
                                  owner_pw="synthetic-owner", user_pw="synthetic-user")
    assert KhaledTextSpacingWatermark.capacity_bits(pdf) == 0
    assert not KhaledTextSpacingWatermark.is_watermark_applicable(pdf)
    with pytest.raises(WatermarkingError):
        KhaledTextSpacingWatermark.add_watermark(pdf, "x", KEY)


@pytest.mark.parametrize("value", [-.31, -.16, -.08, -.001, 0, .08, .16, .31])
@pytest.mark.parametrize("bit", [0, 1])
def test_nearest_lattice_preserves_bit_with_bounded_movement(value, bit):
    from watermarking_methods.khaled import method

    dither = .037
    target = method._nearest_lattice(value, dither, bit)
    assert abs(target - value) / 2 <= .08 + 1e-8
    assert round((target - dither) / .16) & 1 == bit
    alternatives = [dither + index * .16 for index in range(-8, 9) if index % 2 == bit]
    assert abs(target - value) == pytest.approx(min(abs(candidate - value) for candidate in alternatives))


def test_authentication_follows_error_correction():
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    from watermarking_methods.khaled import method

    key = method._keys(KEY)[0]
    ciphertext = AESSIV(key).encrypt(b"x", [b"tatou:text-gap:v2"])
    packet = bytearray(method._CODEC.encode(ciphertext))
    assert method._decode(list(method._bits(packet)), key) == "x"
    packet[0] ^= 1
    assert method._decode(list(method._bits(packet)), key) == "x"
    assert method._decode(list(method._bits(packet)), method._keys("unrelated-key")[0]) is None
    forged = method._CODEC.encode(bytes(len(ciphertext)))
    assert method._decode(list(method._bits(forged)), key) is None


@pytest.mark.parametrize("position", ["AUTO", "page=2"])
def test_unsupported_placement_is_rejected(position):
    pdf = _capacity_pdf(640)
    assert not KhaledTextSpacingWatermark.is_watermark_applicable(pdf, position)
    with pytest.raises(ValueError):
        KhaledTextSpacingWatermark.add_watermark(pdf, "x", KEY, position)


def test_unsigned_form_keeps_text_capacity():
    with fitz.open(stream=_capacity_pdf(640), filetype="pdf") as document:
        form = document.get_new_xref()
        document.update_object(form, "<< /SigFlags 0 >>")
        document.xref_set_key(document.pdf_catalog(), "AcroForm", f"{form} 0 R")
        pdf = document.tobytes()
    assert KhaledTextSpacingWatermark.capacity_bits(pdf) == 640
    assert KhaledTextSpacingWatermark.is_watermark_applicable(pdf)
    marked = KhaledTextSpacingWatermark.add_watermark(pdf, "x", KEY)
    assert KhaledTextSpacingWatermark.read_secret(marked, KEY) == "x"


def test_visible_text_keeps_native_operation_order():
    from watermarking_methods.khaled import method

    with fitz.open() as document:
        page = document.new_page()
        page.insert_text((40, 100), "lower")
        page.insert_text((40, 40), "upper")
        assert method._visible_text(document) == ("lower\nupper\n",)


def test_embedding_preserves_existing_gap_sums_and_glyph_movement():
    key = "synthetic-limit-15"
    with fitz.open(stream=_capacity_pdf(640), filetype="pdf") as document:
        runs = collect_runs(document)
        for run in runs:
            run.gaps[:] = [2.5 if i % 2 else -1.25 for i in range(len(run.gaps))]
        replace_runs(document, runs)
        source = document.tobytes()
        before = [[c["origin"] for b in page.get_text("rawdict")["blocks"] if "lines" in b
                   for line in b["lines"] for span in line["spans"] for c in span["chars"]]
                  for page in document]
        sums = [sum(run.gaps) for run in runs]
    marked = KhaledTextSpacingWatermark.add_watermark(source, "gap-check", key)
    assert KhaledTextSpacingWatermark.read_secret(marked, key) == "gap-check"
    with fitz.open(stream=marked, filetype="pdf") as document:
        assert [sum(run.gaps) for run in collect_runs(document)] == pytest.approx(sums, abs=1e-5)
        after = [[c["origin"] for b in page.get_text("rawdict")["blocks"] if "lines" in b
                  for line in b["lines"] for span in line["spans"] for c in span["chars"]]
                 for page in document]
        assert [len(page) for page in before] == [len(page) for page in after]
        movements = [abs(a[0] - b[0]) for old, new in zip(before, after, strict=True)
                     for a, b in zip(old, new, strict=True)]
        assert max(movements) <= .08004
        assert max(movements) > 0


def test_partial_capacity_is_rejected_before_writing_a_packet():
    with pytest.raises(WatermarkingError, match="Insufficient text capacity"):
        KhaledTextSpacingWatermark.add_watermark(_capacity_pdf(100), "x", KEY)


def test_tolerant_fallback_fits_packet_when_strict_has_only_partial_capacity():
    with fitz.open(stream=_capacity_pdf(100), filetype="pdf") as document:
        with fitz.open(stream=_capacity_pdf(540, scaled=True), filetype="pdf") as scaled:
            document.insert_pdf(scaled)
        source = document.tobytes()
    marked = KhaledTextSpacingWatermark.add_watermark(source, "x" * 48, KEY)
    assert KhaledTextSpacingWatermark.read_secret(marked, KEY) == "x" * 48


def test_gap_difference_uses_pdf_text_units():
    from watermarking_methods.khaled.method import _difference

    with fitz.open(stream=_capacity_pdf(1), filetype="pdf") as document:
        item = carriers(collect_runs(document))[0]
        item.run.gaps[:] = [10, 30]
        assert _difference(item) == pytest.approx(.2, abs=1e-9)
