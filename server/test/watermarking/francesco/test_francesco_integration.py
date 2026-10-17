"""Verify PDF watermark embedding, extraction, and layer composition."""

from __future__ import annotations

import io

import pymupdf as fitz
import pytest
import zxingcpp
from PIL import Image

from watermarking_method import SecretNotFoundError, WatermarkingError
from watermarking_methods.davide.method import DavideWatermark as StructuralWatermark
from watermarking_methods.francesco import crypto, rendering
from watermarking_methods.francesco.method import FrancescoWatermark

KEY = "0123456789abcdef" * 4
OTHER_KEY = "fedcba9876543210" * 4
GROUP_POSITION = "group=Group_13"


def test_roundtrip_preserves_page_and_text(pdf_bytes):
    method = FrancescoWatermark()
    watermarked = method.add_watermark(
        pdf_bytes, "unique-copy-id", KEY, position=GROUP_POSITION
    )
    assert method.read_secret(watermarked, KEY) == "unique-copy-id"

    with fitz.open(stream=watermarked, filetype="pdf") as doc:
        assert doc.page_count == 1
        assert "A document with a table and a photograph" in doc[0].get_text()
        assert len(doc[0].get_images()) >= 1


def test_reading_rejects_wrong_key_and_unmarked_pdf(pdf_bytes):
    method = FrancescoWatermark()
    watermarked = method.add_watermark(pdf_bytes, "copy-42", KEY, position=GROUP_POSITION)

    with pytest.raises(SecretNotFoundError):
        method.read_secret(watermarked, OTHER_KEY)
    with pytest.raises(SecretNotFoundError):
        method.read_secret(pdf_bytes, KEY)


def test_conflicting_valid_copies_rejected(pdf_bytes):
    method = FrancescoWatermark()
    first = method.add_watermark(pdf_bytes, "copy-one", KEY, GROUP_POSITION)
    second = method.add_watermark(pdf_bytes, "copy-two", KEY, GROUP_POSITION)

    # Stitch two different watermarked pages together.
    with (
        fitz.open(stream=first, filetype="pdf") as left,
        fitz.open(stream=second, filetype="pdf") as right,
    ):
        right.insert_pdf(left)
        stitched = right.tobytes()

    with pytest.raises(WatermarkingError, match="Conflicting"):
        method.read_secret(stitched, KEY)


@pytest.mark.parametrize("decoy", ["other-key", "random", "malformed"])
def test_decoy_qr_does_not_hide_the_real_one(pdf_bytes, decoy, monkeypatch):
    method = FrancescoWatermark()
    watermarked = method.add_watermark(pdf_bytes, "real-copy", KEY)
    payload = (
        crypto.encrypt_qr_payload("fake-copy", OTHER_KEY)
        if decoy == "other-key"
        else "A" * 60 if decoy == "random" else "not a watermark!"
    )

    # The leaker pastes a QR code of their own in the middle of the page.
    with fitz.open(stream=watermarked, filetype="pdf") as doc:
        doc[0].insert_image(fitz.Rect(220, 350, 380, 510),
                            stream=rendering.build_opaque_qr_bytes(payload))
        with_decoy = doc.tobytes()

    original_read = zxingcpp.read_barcodes

    def decoy_first(*args, **kwargs):
        barcodes = original_read(*args, **kwargs)
        assert any(barcode.text == payload for barcode in barcodes)
        return sorted(barcodes, key=lambda barcode: barcode.text != payload)

    from watermarking_methods.francesco import visible

    monkeypatch.setattr(visible.shutil, "which", lambda name: None)
    monkeypatch.setattr(zxingcpp, "read_barcodes", decoy_first)
    assert method.read_secret(with_decoy, KEY) == "real-copy"


def test_survives_jpeg_raster_roundtrip(pdf_bytes):
    method = FrancescoWatermark()
    watermarked = method.add_watermark(
        pdf_bytes, "copy-through-jpeg", KEY, GROUP_POSITION
    )

    # Simulate scan / raster conversion to JPEG 85% quality.
    with (
        fitz.open(stream=watermarked, filetype="pdf") as source,
        fitz.open() as rebuilt,
    ):
        pix = source[0].get_pixmap(dpi=220, colorspace=fitz.csRGB, alpha=False)
        image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=85)
        page = rebuilt.new_page(
            width=source[0].rect.width, height=source[0].rect.height
        )
        page.insert_image(page.rect, stream=buffer.getvalue())
        candidate = rebuilt.tobytes()

    assert method.read_secret(candidate, KEY) == "copy-through-jpeg"


@pytest.mark.parametrize("recipient,heading", [
    ("Group_07", "Group_07"), ("  Alice   Smith  ", "Group Alice Smith"), ("Group A - B", "Group A - B"),
])
def test_qr_and_label_encode_the_secret(pdf_bytes, monkeypatch, recipient, heading):
    method = FrancescoWatermark()
    secret = "Group_07:da0bb583c432fbfd078959ecc9b62902"
    labels: list[str] = []
    original_stamp = rendering.stamp_random_native_visible_text

    def capture_label(**kwargs):
        labels.append(kwargs["label"])
        return original_stamp(**kwargs)

    monkeypatch.setattr(rendering, "stamp_random_native_visible_text", capture_label)
    watermarked = method.add_watermark(pdf_bytes, secret, KEY, intended_for=recipient)

    with fitz.open(stream=watermarked, filetype="pdf") as document:
        pixmap = document[0].get_pixmap(dpi=300, colorspace=fitz.csRGB, alpha=False)
        qr_payloads = [
            result.text
            for result in zxingcpp.read_barcodes(
                Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples),
                formats=zxingcpp.BarcodeFormat.QRCode,
            )
        ]

    assert len(labels) == 1
    assert labels[0].startswith(f"{heading} - ")
    label_payload = labels[0].rsplit(" - ", maxsplit=1)[1]
    assert secret not in label_payload
    assert crypto.decrypt_visible_payload(label_payload, KEY) == secret
    assert len(qr_payloads) == 1
    assert secret not in qr_payloads[0]
    assert crypto.decrypt_qr_payload(qr_payloads[0], KEY) == secret


def test_encrypted_visible_label_recovers_secret_when_qr_is_unavailable(pdf_bytes, monkeypatch):
    from watermarking_methods.francesco import method as method_module

    method = FrancescoWatermark()
    secret = "visible-label-copy-id"
    watermarked = method.add_watermark(pdf_bytes, secret, KEY, intended_for="Group 13")
    with fitz.open(stream=watermarked, filetype="pdf") as document:
        pixmap = document[0].get_pixmap(dpi=300, alpha=False)
        with fitz.open() as flattened_document:
            page = flattened_document.new_page(
                width=document[0].rect.width,
                height=document[0].rect.height,
            )
            page.insert_image(page.rect, stream=pixmap.tobytes("png"))
            flattened = flattened_document.tobytes()
    monkeypatch.setattr(method_module.zxingcpp, "read_barcodes", lambda *args, **kwargs: [])

    assert method.read_secret(flattened, KEY) == secret


def test_visible_label_recovers_from_common_ocr_digit_confusions(monkeypatch):
    from watermarking_methods.francesco import visible

    secret = "visible-label-copy-id"
    monkeypatch.setattr(crypto.os, "urandom", lambda size: b"\x01" * size)
    payload = crypto.encrypt_visible_payload(secret, KEY)

    for letter, digit in (("o", "0"), ("l", "1"), ("b", "8"), ("g", "9")):
        assert letter in payload
        scanned_label = f"Group 13 - {payload.replace(letter, digit, 1)}"
        candidates = visible._candidate_payloads(scanned_label)
        assert any(
            crypto.decrypt_visible_payload(candidate, KEY) == secret
            for candidate in candidates
        )


@pytest.mark.parametrize("secret", ["x", "xy", "\u00e9", "x" * 64, "\u00e9" * 32])
@pytest.mark.parametrize("recipient", ["Group_13", "Group A - " + "B" * 40])
def test_wrapped_visible_label_recovers_long_encrypted_secret(secret, recipient):
    from watermarking_methods.francesco import visible

    payload = crypto.encrypt_visible_payload(secret, KEY)
    label = rendering._wrap_visible_label(f"{recipient} - {payload}", 8, 200)

    assert "\n" in label
    assert payload in visible._candidate_payloads(label)
    assert crypto.decrypt_visible_payload(payload, KEY) == secret


def test_long_visible_label_recovers_after_flattening(monkeypatch):
    from watermarking_methods.francesco import method as method_module

    salts = iter((b"\x01", b"\x02"))
    monkeypatch.setattr(crypto.os, "urandom", lambda size: next(salts) * size)
    with fitz.open() as document:
        page = document.new_page(width=595, height=842)
        for row in range(20):
            page.insert_text(
                (75, 95 + row * 24),
                "This is a synthetic Group 13 document for layout and OCR testing.",
                fontsize=10,
            )
        source = document.tobytes()

    secret = "x" * 64
    marked = FrancescoWatermark().add_watermark(
        source, secret, KEY, intended_for="Group_" + "A" * 54,
    )
    with fitz.open(stream=marked, filetype="pdf") as document:
        pixmap = document[0].get_pixmap(dpi=300, alpha=False)
        with fitz.open() as flattened_document:
            page = flattened_document.new_page(width=595, height=842)
            page.insert_image(page.rect, stream=pixmap.tobytes("png"))
            flattened = flattened_document.tobytes()

    monkeypatch.setattr(method_module.zxingcpp, "read_barcodes", lambda *args, **kwargs: [])
    assert FrancescoWatermark().read_secret(flattened, KEY) == secret


@pytest.mark.parametrize("position", [None, "group=Group_13", "group=Group_13;no-qr"])
def test_position_is_ignored(pdf_bytes, position):
    method = FrancescoWatermark()
    watermarked = method.add_watermark(pdf_bytes, "copy-options", KEY, position)

    with fitz.open(stream=watermarked, filetype="pdf") as doc:
        images = doc[0].get_images(full=True)
        assert any(image[2] == image[3] for image in images)

    assert method.read_secret(watermarked, KEY) == "copy-options"


def test_non_ascii_secret_roundtrip(pdf_bytes):
    method = FrancescoWatermark()
    secret = "group-13-copy-\u00e9"
    watermarked = method.add_watermark(
        pdf_bytes, secret, KEY, position="group=Group_13"
    )
    assert method.read_secret(watermarked, KEY) == secret


def test_combined_structural_and_visual_watermarks(structural_carrier_pdf):
    structural_secret = "structural-secret-42"
    visual_secret = "Group_01:visual-secret-99"

    structurally_marked = StructuralWatermark.add_watermark(
        structural_carrier_pdf, structural_secret, KEY
    )

    visual_method = FrancescoWatermark()
    combined_pdf = visual_method.add_watermark(
        structurally_marked, visual_secret, KEY
    )

    recovered_structural = StructuralWatermark.read_secret(combined_pdf, KEY)
    recovered_visual = visual_method.read_secret(combined_pdf, KEY)

    assert recovered_structural == structural_secret
    assert recovered_visual == visual_secret
