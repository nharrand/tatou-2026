"""OCR candidate recovery and subprocess boundary contracts."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import numpy as np
import pytest
from PIL import Image

from watermarking_method import InvalidKeyError, WatermarkingError
from watermarking_methods.francesco import crypto, visible

KEY = "synthetic-francesco-review-key"


@pytest.mark.parametrize("secret", ["x", "xy", "\u00e9", "x" * 64])
@pytest.mark.parametrize("damage", ["missing", "extra"])
def test_visible_payload_recovers_missing_or_extra_character(monkeypatch, secret, damage):
    monkeypatch.setattr(crypto.os, "urandom", lambda size: b"\x01" * size)
    payload = crypto.encrypt_visible_payload(secret, KEY)
    damaged = payload[1:] if damage == "missing" else "a" + payload
    candidates = visible._candidate_payloads(f"Group 13 - {damaged}")
    assert visible._authenticated_secrets(candidates, KEY) == {secret}


def test_repaired_candidates_preserve_conflicts(monkeypatch):
    monkeypatch.setattr(crypto.os, "urandom", lambda size: b"\x02" * size)
    secrets = {"recipient-alpha", "recipient-bravo"}
    candidates = [crypto.encrypt_visible_payload(secret, KEY)[1:] for secret in sorted(secrets)]
    assert visible._authenticated_secrets(candidates, KEY) == secrets


@pytest.mark.parametrize("copies", [2, 3])
def test_consensus_authenticates_complementary_damage(monkeypatch, copies):
    monkeypatch.setattr(crypto.os, "urandom", lambda size: b"\x03" * size)
    payload = crypto.encrypt_visible_payload("x" * 64, KEY)
    candidates = []
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for start in range(copies):
        damaged = list(payload)
        # Nine distinct byte errors exceed the eight-symbol Reed-Solomon correction budget.
        for index in range(start, start + 144, 16):
            damaged[index] = alphabet[alphabet.index(payload[index]) ^ 1]
        candidates.append("".join(damaged))
        with pytest.raises(InvalidKeyError):
            crypto.decrypt_visible_payload(candidates[-1], KEY)
    assert visible._authenticated_secrets(candidates, KEY) == {"x" * 64}


@pytest.mark.parametrize("failure", [OSError, subprocess.TimeoutExpired])
def test_ocr_failures_do_not_disclose_input(monkeypatch, caplog, capsys, failure):
    canary = "synthetic-private-ocr-canary"
    monkeypatch.setattr(visible.shutil, "which", lambda name: "/synthetic/tesseract" if name == "tesseract" else None)

    def fail(*args, **kwargs):
        if failure is subprocess.TimeoutExpired:
            raise failure(canary, 30, output=canary, stderr=canary)
        raise failure(canary)

    monkeypatch.setattr(visible.subprocess, "run", fail)
    with pytest.raises(WatermarkingError) as raised:
        visible._ocr(Image.new("RGB", (8, 8)))
    assert canary not in str(raised.value)
    captured = capsys.readouterr()
    assert canary not in captured.out + captured.err + caplog.text


@pytest.mark.parametrize("returncode,output,expected", [(0, b"Group 13\xff", "Group 13"), (1, b"private-output", "")])
def test_ocr_passes_safe_tesseract_options_and_decodes_output(monkeypatch, returncode, output, expected):
    monkeypatch.setattr(visible.shutil, "which", lambda name: "/synthetic/tesseract" if name == "tesseract" else None)

    def run(args, **kwargs):
        assert args[3:9] == ["--psm", "6", "-l", "eng", "-c", f"tessedit_char_whitelist={visible._OCR_WHITELIST}"]
        assert kwargs["check"] is False
        assert args[:3] == ["/synthetic/tesseract", "stdin", "stdout"]
        assert kwargs["input"].startswith(b"\x89PNG")
        assert kwargs["timeout"] == 30
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert not kwargs.get("shell", False)
        return SimpleNamespace(returncode=returncode, stdout=output)

    monkeypatch.setattr(visible.subprocess, "run", run)
    assert visible._ocr(Image.new("RGB", (8, 8))) == expected


def test_ocr_raises_watermarking_error_without_tesseract(monkeypatch):
    monkeypatch.setattr(visible.shutil, "which", lambda name: None)
    with pytest.raises(WatermarkingError, match="Tesseract"):
        visible._ocr(Image.new("RGB", (8, 8)))


def test_ink_isolation_uses_signed_color_differences():
    pixels = np.array([[
        [220, 225, 235], [200, 220, 10], [200, 10, 220], [80, 80, 80],
        [250, 252, 255], [200, 215, 220], [200, 201, 220], [210, 230, 215],
    ]], dtype=np.uint8)
    isolated = visible._isolated_watermark_ink(Image.fromarray(pixels), 10)
    assert np.asarray(isolated).tolist() == [[0, 255, 255, 255, 255, 0, 255, 255]]


def test_payload_repair_respects_candidate_limits():
    candidates = [char * 80 for char in "abcde"]
    repairs = list(visible._single_character_repairs(candidates))
    assert len(repairs) <= 3 * (81 * 32 + 80)
    assert len(visible._ocr_confusable_variants(["I" * 8 + "a" * 72])) <= 128
    payload = crypto.encrypt_visible_payload("variant-budget", KEY)
    alternative = list(payload)
    for index in range(0, 60, 5):
        alternative[index] = "a" if payload[index] != "a" else "b"
    assert len(visible._consensus_candidates([payload, "".join(alternative)])) <= 2 * 128


def test_confusable_variants_preserve_authentication(monkeypatch):
    monkeypatch.setattr(crypto.os, "urandom", lambda size: b"\x01" * size)
    secret = "x" * 64
    payload = crypto.encrypt_visible_payload(secret, KEY)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    damaged = list(payload)
    assert payload[24] == "l"
    for index in (0, 8, 16, 32, 40, 48, 56, 64):
        damaged[index] = alphabet[alphabet.index(payload[index]) ^ 1]
    corrected_confusion = "".join(damaged)
    assert crypto.decrypt_visible_payload(corrected_confusion, KEY) == secret
    damaged[24] = "I"
    scanned = "".join(damaged)
    with pytest.raises(InvalidKeyError):
        crypto.decrypt_visible_payload(scanned, KEY)
    assert corrected_confusion in visible._ocr_confusable_variants(["short", scanned])
    assert visible._authenticated_secrets([scanned], KEY) == {secret}


@pytest.mark.parametrize("uppercase", [False, True])
def test_wrapped_candidates_ignore_ocr_whitespace(uppercase):
    payload = crypto.encrypt_visible_payload("wrapped-recipient", KEY)
    if uppercase:
        payload = payload.upper()
    chunks = [payload[index:index + 26] for index in range(0, len(payload), 26)]
    text = "Group 13 -\n" + "\n".join(
        " ".join(chunk[index:index + 4] for index in range(0, len(chunk), 4)) for chunk in chunks
    )
    assert payload in visible._candidate_payloads(text)


def test_visible_reader_continues_to_label_crops(monkeypatch):
    import io

    import pymupdf as fitz

    payload = crypto.encrypt_visible_payload("crop-recipient", KEY)
    color = (50, 100, 180)
    buffer = io.BytesIO()
    Image.new("RGB", (160, 40), color).save(buffer, format="PNG")
    crop_reads = []
    monkeypatch.setattr(visible.shutil, "which", lambda name: "/synthetic/tesseract" if name == "tesseract" else None)

    def run(args, **kwargs):
        with Image.open(io.BytesIO(kwargs["input"])) as image:
            is_crop = image.mode == "RGB" and image.width < 1000
            if is_crop and image.getpixel((image.width // 2, image.height // 2)) == color:
                crop_reads.append(image.size)
                output = f"Group 13 - {payload}".encode()
            else:
                output = b""
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setattr(visible.subprocess, "run", run)
    with fitz.open() as document:
        page = document.new_page(width=300, height=400)
        page.insert_image(fitz.Rect(10, 10, 50, 50), stream=buffer.getvalue(), keep_proportion=False)
        xref = page.insert_image(fitz.Rect(80, 200, 240, 240), stream=buffer.getvalue())
        page.insert_image(fitz.Rect(80, 280, 240, 320), xref=xref)
        assert visible.read_visible_secrets(document, KEY) == {"crop-recipient"}
    assert len(crop_reads) == 2


def test_rotated_label_crop_with_real_ocr(monkeypatch):
    import io

    import pymupdf as fitz

    from watermarking_methods.francesco import rendering

    monkeypatch.setattr(crypto.os, "urandom", lambda size: b"\x01" * size)
    payload = crypto.encrypt_visible_payload("x", KEY)
    original_run = subprocess.run
    crop_calls = []

    def cropped_ocr_only(args, **kwargs):
        with Image.open(io.BytesIO(kwargs["input"])) as image:
            if image.width >= 2000:
                return SimpleNamespace(returncode=0, stdout=b"")
            crop_calls.append(image.size)
        return original_run(args, **kwargs)

    monkeypatch.setattr(visible.subprocess, "run", cropped_ocr_only)
    with fitz.open() as document:
        page = document.new_page(width=595, height=842)
        rendering.stamp_random_native_visible_text(
            page, f"Group 13 - {payload}", [], count=1, seed_material=b"crop-ocr",
        )
        assert visible.read_visible_secrets(document, KEY) == {"x"}
    assert crop_calls


def test_visible_reader_authenticates_color_isolation_fallback(monkeypatch):
    import io

    import pymupdf as fitz

    payload = crypto.encrypt_visible_payload("isolated-recipient", KEY)
    monkeypatch.setattr(visible.shutil, "which", lambda name: "/synthetic/tesseract" if name == "tesseract" else None)

    def run(args, **kwargs):
        with Image.open(io.BytesIO(kwargs["input"])) as image:
            output = f"Group 13 - {payload}".encode() if image.mode == "L" and image.getextrema() == (0, 255) else b""
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setattr(visible.subprocess, "run", run)
    with fitz.open() as document:
        page = document.new_page(width=200, height=300)
        page.draw_rect(fitz.Rect(30, 40, 150, 100), color=None, fill=(.2, .3, .5))
        assert visible.read_visible_secrets(document, KEY) == {"isolated-recipient"}


def test_visible_reader_respects_raster_pixel_budget(monkeypatch):
    import pymupdf as fitz

    from watermarking_methods.francesco import pdf as pdf_ops

    payload = crypto.encrypt_visible_payload("raster-budget", KEY)
    original_rasterize = fitz.Page.get_pixmap

    def bounded_rasterize(page, *args, **kwargs):
        pixmap = original_rasterize(page, *args, **kwargs)
        assert pixmap.width * pixmap.height <= pdf_ops.MAX_PIXELS_PER_PAGE
        return pixmap

    monkeypatch.setattr(fitz.Page, "get_pixmap", bounded_rasterize)
    monkeypatch.setattr(visible.shutil, "which", lambda name: "/synthetic/tesseract" if name == "tesseract" else None)
    monkeypatch.setattr(visible.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=f"Group 13 - {payload}".encode(),
    ))
    with fitz.open() as document:
        document.new_page(width=960, height=960)
        assert pdf_ops.is_document_applicable(document.tobytes())
        assert visible.read_visible_secrets(document, KEY) == {"raster-budget"}
