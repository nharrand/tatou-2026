"""Verify encrypted payloads, PDF preservation, and recipient fingerprint attribution."""

from __future__ import annotations

import io
import shutil
import subprocess
from statistics import NormalDist

import numpy as np
import pymupdf as fitz
import pytest
from attacks import ATTACKS, KNOWN_FAILURES, edit_image
from photos import make_photo, photo_pdf
from PIL import Image

import watermarking_methods.davide.method as method_module
from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError
from watermarking_methods.davide.image import embed_payload, read_votes, vote
from watermarking_methods.davide.method import (
    DavideWatermark,
    _images,
    _replace_image,
    encrypt,
)
from watermarking_utils import METHODS, apply_watermark, read_watermark

KEY = "rmap-server-key"
LEAKER = "Group_07:da0bb583c432fbfd078959ecc9b62902"
OTHER = "Group_01:0123456789abcdef0123456789abcdef"
INNOCENTS = [f"Group_{i % 100:02d}:{i:032x}" for i in range(50)]
THRESHOLD = DavideWatermark.ATTRIBUTION_THRESHOLD

# Attacks the encrypted secret must survive.
PAYLOAD_SURVIVES = ["none", "jpeg-q90", "jpeg-q75", "jpeg-q50", "blur-0.8", "noise-3", "noise-8"]

needs_ghostscript = pytest.mark.skipif(shutil.which("gs") is None, reason="Ghostscript not installed")


def _image(pdf: bytes) -> Image.Image:
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        return next(_images(doc))[1]


def _ghostscript(pdf: bytes, tmp_path, *options: str) -> bytes:
    src, dst = tmp_path / "in.pdf", tmp_path / "out.pdf"
    src.write_bytes(pdf)
    subprocess.run(["gs", "-q", "-o", str(dst), "-sDEVICE=pdfwrite", *options, str(src)], check=True)
    return dst.read_bytes()


def _average(a: bytes, b: bytes) -> bytes:
    """Average two recipient copies to simulate collusion."""
    mix = (np.asarray(_image(a), dtype=np.float64) + np.asarray(_image(b), dtype=np.float64)) / 2
    return edit_image(a, lambda _: Image.fromarray(mix.round().astype(np.uint8)))


def _raw_images(pdf: bytes) -> list[tuple[str, bytes]]:
    """Return first-page image dictionaries without Length and their raw streams."""
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        result = []
        for info in doc[0].get_images(full=True):
            obj = "\n".join(line for line in doc.xref_object(info[0]).splitlines() if "/Length" not in line)
            result.append((obj, doc.xref_stream_raw(info[0])))
        return result


def _accused(leak: bytes, original: bytes, key: str = KEY) -> set[str]:
    scores = DavideWatermark.score_recipients(leak, original, key, [LEAKER, OTHER, *INNOCENTS])
    return {secret for secret, z in scores.items() if z >= THRESHOLD}


@pytest.fixture(scope="module")
def original() -> bytes:
    return photo_pdf([make_photo(640, 640)], text="Confidential photo")


@pytest.fixture(scope="module")
def leaked(original) -> bytes:
    return DavideWatermark.add_watermark(original, LEAKER, KEY)


@pytest.fixture(scope="module")
def other_copy(original) -> bytes:
    return DavideWatermark.add_watermark(original, OTHER, KEY)


def test_registered_under_its_name():
    assert isinstance(METHODS["davide-watermark"], DavideWatermark)


def test_embedding_and_reading_reject_invalid_secrets_or_keys(original):
    with pytest.raises(ValueError):
        DavideWatermark.add_watermark(original, "", KEY)
    with pytest.raises(ValueError):
        DavideWatermark.add_watermark(original, "x" * 129, KEY)
    with pytest.raises(InvalidKeyError):
        DavideWatermark.add_watermark(original, "secret", "")
    with pytest.raises(InvalidKeyError):
        DavideWatermark.read_secret(original, "")
    with pytest.raises(InvalidKeyError):
        DavideWatermark.score_recipients(original, original, "", [LEAKER])


@pytest.mark.parametrize("secret", [
    LEAKER, "Nicolas:" + "5a" * 16, "x", "Secret \U0001f510 \u65e5\u672c\u8a9e", "x" * 128,
])
def test_roundtrip_through_registry(original, tmp_path, secret):
    marked = apply_watermark("davide-watermark", original, secret, KEY)
    assert read_watermark("davide-watermark", marked, KEY) == secret
    path = tmp_path / "wm.pdf"
    path.write_bytes(marked)
    assert read_watermark("davide-watermark", path, KEY) == secret
    assert read_watermark("davide-watermark", io.BytesIO(marked), KEY) == secret


def test_each_recipient_gets_a_distinct_copy(leaked, other_copy):
    assert leaked != other_copy
    assert DavideWatermark.read_secret(leaked, KEY) == LEAKER
    assert DavideWatermark.read_secret(other_copy, KEY) == OTHER


def test_wrong_key_or_unmarked_pdf_reads_nothing(original, leaked):
    with pytest.raises(SecretNotFoundError):
        DavideWatermark.read_secret(leaked, "wrong-key")
    with pytest.raises(SecretNotFoundError):
        DavideWatermark.read_secret(original, KEY)


def test_tampered_payload_is_rejected_not_misread(original):
    # Flip one ciphertext bit while preserving valid QIM encoding.
    bits = np.unpackbits(np.frombuffer(encrypt(LEAKER, KEY), dtype=np.uint8))
    bits[5] ^= 1
    tampered = edit_image(original, lambda img: embed_payload(img, bits, KEY))
    with pytest.raises(SecretNotFoundError):
        DavideWatermark.read_secret(tampered, KEY)


def test_only_the_ciphertext_is_embedded(leaked):
    # Voting with the ciphertext length gives back exactly AES-SIV(secret), so no header or
    # plaintext is embedded.
    ciphertext = encrypt(LEAKER, KEY)
    assert len(ciphertext) == len(LEAKER) + 16
    bits = vote(read_votes(_image(leaked), KEY), len(ciphertext) * 8)
    assert np.packbits(bits).tobytes() == ciphertext

    identity, link = LEAKER.split(":")
    with fitz.open(stream=leaked, filetype="pdf") as doc:
        blobs = [leaked, str(doc.metadata).encode()]
        for xref in range(1, doc.xref_length()):
            blobs += [doc.xref_object(xref).encode(), doc.xref_stream(xref) or b""]
    assert not any(needle in blob for blob in blobs for needle in (identity.encode(), link.encode()))


def test_averaged_copies_never_read_as_a_wrong_secret(leaked, other_copy):
    try:
        secret = DavideWatermark.read_secret(_average(leaked, other_copy), KEY)
    except SecretNotFoundError:
        return
    assert secret in {LEAKER, OTHER}


@pytest.mark.parametrize("name", PAYLOAD_SURVIVES)
def test_secret_survives_mild_attacks(leaked, name):
    assert DavideWatermark.read_secret(ATTACKS[name](leaked), KEY) == LEAKER


@needs_ghostscript
def test_secret_survives_ghostscript_rewrite(leaked, tmp_path):
    assert DavideWatermark.read_secret(_ghostscript(leaked, tmp_path), KEY) == LEAKER


def test_image_is_replaced_in_place_and_page_kept(original):
    leaked = DavideWatermark.add_watermark(original, LEAKER, KEY)
    with fitz.open(stream=leaked, filetype="pdf") as doc:
        assert len(doc[0].get_images()) == 1  # No unmarked copy left.
        assert "Confidential photo" in doc[0].get_text()
    before = np.asarray(_image(original), dtype=np.float64)
    after = np.asarray(_image(leaked), dtype=np.float64)
    assert 10 * np.log10(255 ** 2 / np.mean((before - after) ** 2)) > 32


def test_pdf_without_usable_image_is_rejected():
    with fitz.open() as doc:
        doc.new_page().insert_text((72, 72), "Text only")
        text_only = doc.tobytes()
    for pdf in (text_only, photo_pdf([make_photo(64, 64)])):
        assert not DavideWatermark.is_watermark_applicable(pdf)
        with pytest.raises(WatermarkingError):
            DavideWatermark.add_watermark(pdf, LEAKER, KEY)


def test_images_above_the_pixel_limit_are_left_untouched():
    side = int(method_module._MAX_PIXELS ** 0.5) + 8
    big = make_photo(side, side, smooth=True)
    # Only as a scanned-page fallback, never next to a normal image.
    assert not DavideWatermark.is_watermark_applicable(photo_pdf([big]), scans=False)

    mixed = photo_pdf([big, make_photo(640, 640)])
    out = DavideWatermark.add_watermark(mixed, LEAKER, KEY)
    before, after = _raw_images(mixed), _raw_images(out)
    assert after[0] == before[0]
    assert after[1][1] != before[1][1]
    assert DavideWatermark.read_secret(out, KEY) == LEAKER


def test_images_above_the_scan_limit_are_never_used(monkeypatch):
    monkeypatch.setattr(method_module, "_MAX_PIXELS", 500 * 500)
    monkeypatch.setattr(method_module, "_MAX_SCAN_PIXELS", 900 * 900)
    pdf = photo_pdf([make_photo(960, 960)])
    assert not DavideWatermark.is_watermark_applicable(pdf)
    with pytest.raises(WatermarkingError):
        DavideWatermark.add_watermark(pdf, LEAKER, KEY)


def test_scanned_pages_are_a_fallback_only(monkeypatch):
    # A smaller limit keeps the test fast: 640x640 is "normal", 800x800 a "scan".
    monkeypatch.setattr(method_module, "_MAX_PIXELS", 700 * 700)
    scan = make_photo(800, 800)
    only_scan = photo_pdf([scan])
    assert not DavideWatermark.is_watermark_applicable(only_scan, scans=False)
    assert DavideWatermark.is_watermark_applicable(only_scan)
    out = DavideWatermark.add_watermark(only_scan, LEAKER, KEY)
    assert DavideWatermark.read_secret(out, KEY) == LEAKER
    scores = DavideWatermark.score_recipients(out, only_scan, KEY, [LEAKER, OTHER])
    assert scores[LEAKER] > THRESHOLD > scores[OTHER]
    # Group13 excludes scan-only carriers.
    assert DavideWatermark.score_recipients(out, only_scan, KEY, [LEAKER], scans=False)[LEAKER] < THRESHOLD

    # Prefer a normal image and leave scan-only images untouched.
    mixed = photo_pdf([scan, make_photo(640, 640)])
    out = DavideWatermark.add_watermark(mixed, LEAKER, KEY)
    before, after = _raw_images(mixed), _raw_images(out)
    assert after[0] == before[0]
    assert after[1][1] != before[1][1]


def test_real_image_size_is_checked_before_decoding():
    # The PDF says 640x640, the JPEG inside is bigger than the pixel limit.
    side = int(method_module._MAX_PIXELS ** 0.5) + 8
    buf = io.BytesIO()
    Image.new("RGB", (side, side)).save(buf, "JPEG")
    pdf = photo_pdf([make_photo(640, 640), make_photo(320, 288)])
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        xref = doc[0].get_images()[0][0]
        doc.update_stream(xref, buf.getvalue(), compress=False)
        doc.xref_set_key(xref, "Filter", "/DCTDecode")
        assert doc[0].get_images()[0][2:4] == (640, 640)
        assert [img.size for _, img in _images(doc)] == [(320, 288)]


def test_total_pixel_budget_bounds_the_work(monkeypatch):
    monkeypatch.setattr(method_module, "_MAX_TOTAL_PIXELS", 2 * 640 * 640)
    pdf = photo_pdf([make_photo(640, 640, seed=s) for s in (1, 2, 3)])
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        assert len(list(_images(doc))) == 2


def test_every_image_carries_the_whole_watermark():
    pdf = photo_pdf([make_photo(640, 640, seed=1), make_photo(512, 512, seed=2)])
    out = DavideWatermark.add_watermark(pdf, LEAKER, KEY)
    for (_, before), (_, after) in zip(_raw_images(pdf), _raw_images(out), strict=True):
        assert before != after

    with fitz.open(stream=out, filetype="pdf") as doc:
        doc[0].delete_image(doc[0].get_images()[0][0])
        second_only = doc.tobytes(garbage=3)
    assert DavideWatermark.read_secret(second_only, KEY) == LEAKER
    assert _accused(second_only, pdf) == {LEAKER}


def test_images_from_two_copies_are_reported_as_conflicting():
    pdf = photo_pdf([make_photo(640, 640, seed=1), make_photo(512, 512, seed=2)])
    copy_a = DavideWatermark.add_watermark(pdf, LEAKER, KEY)
    copy_b = DavideWatermark.add_watermark(pdf, OTHER, KEY)

    # The leaker takes the first picture from A and the second from B.
    with fitz.open(stream=copy_a, filetype="pdf") as doc, fitz.open(stream=copy_b, filetype="pdf") as other:
        (_, _), (xref_a, _) = list(_images(doc))
        (_, _), (_, img_b) = list(_images(other))
        _replace_image(doc, xref_a, img_b)
        mixed = doc.tobytes(garbage=3)

    with pytest.raises(WatermarkingError, match="Conflicting"):
        DavideWatermark.read_secret(mixed, KEY)


@pytest.mark.parametrize("mask_first", [False, True])
def test_stencil_masks_are_not_modified(mask_first):
    pdf = photo_pdf([make_photo(640, 640)])
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        page = doc[0]
        mask = doc.get_new_xref()
        doc.update_object(mask, "<< /Type /XObject /Subtype /Image /Width 640 /Height 640 "
                                "/ImageMask true /BitsPerComponent 1 >>")
        doc.update_stream(mask, np.packbits(np.random.default_rng(0).random((640, 640)) > 0.5, axis=1).tobytes())
        kind, value = doc.xref_get_key(page.xref, "Resources")
        resources = int(value.split()[0]) if kind == "xref" else page.xref
        kind, value = doc.xref_get_key(resources, "XObject")
        if kind == "xref":
            doc.xref_set_key(int(value.split()[0]), "Msk", f"{mask} 0 R")
        else:
            doc.xref_set_key(resources, "XObject/Msk", f"{mask} 0 R")
        if mask_first:
            photo = page.get_images()[0][0]
            dictionary = f"<< /Msk {mask} 0 R /fzImg0 {photo} 0 R >>"
            doc.xref_set_key(resources, "XObject", dictionary)
        contents = page.get_contents()[0]
        doc.update_stream(contents, doc.xref_stream(contents) + b"\nq 200 0 0 200 72 100 cm /Msk Do Q\n")
        pdf = doc.tobytes()

    out = DavideWatermark.add_watermark(pdf, LEAKER, KEY)
    assert DavideWatermark.read_secret(out, KEY) == LEAKER

    # The photo is marked, the stencil keeps its type and pixels.
    with fitz.open(stream=pdf, filetype="pdf") as src, fitz.open(stream=out, filetype="pdf") as dst:
        (photo_before, mask_before), (photo_after, mask_after) = (
            [info[0] for info in sorted(d[0].get_images(full=True),
                                      key=lambda info: d.xref_get_key(info[0], "ImageMask")[1] == "true")]
            for d in (src, dst)
        )
        assert src.xref_stream_raw(photo_before) != dst.xref_stream_raw(photo_after)
        for key, value in (("ImageMask", "true"), ("BitsPerComponent", "1"), ("ColorSpace", "null")):
            assert dst.xref_get_key(mask_after, key)[1] == value
        assert dst.xref_stream(mask_after) == src.xref_stream(mask_before)


@pytest.mark.parametrize("name", list(ATTACKS))
def test_fingerprint_attribution_identifies_only_watermarked_recipient(original, leaked, name):
    assert _accused(ATTACKS[name](leaked), original) == {LEAKER}


@needs_ghostscript
def test_fingerprint_survives_ghostscript_screen(original, leaked, tmp_path):
    assert _accused(_ghostscript(leaked, tmp_path, "-dPDFSETTINGS=/screen"), original) == {LEAKER}


@pytest.mark.xfail(strict=True, reason="large rotation or very strong blur")
@pytest.mark.parametrize("name", list(KNOWN_FAILURES))
def test_fingerprint_attribution_fails_after_large_rotation_or_blur(original, leaked, name):
    assert _accused(KNOWN_FAILURES[name](leaked), original) == {LEAKER}


def test_averaged_copies_attribute_only_colluding_recipients(original, leaked, other_copy):
    assert _accused(_average(leaked, other_copy), original) == {LEAKER, OTHER}


def test_unmarked_pdf_has_no_fingerprint_attribution(original):
    for pdf in (original, photo_pdf([make_photo(640, 640, seed=99)])):
        assert _accused(pdf, original) == set()


def test_fingerprint_needs_the_key(original, leaked):
    assert _accused(leaked, original, key="wrong-key") == set()


def test_innocent_scores_follow_the_threshold_model(original, other_copy):
    # An innocent score is the best of 4 comparisons of N(0, 1) values, so P(score >= t) <= 4 *
    # Q(t).
    innocents = [f"Group_{i % 100:02d}:{i:032x}" for i in range(1000)]
    scores = DavideWatermark.score_recipients(ATTACKS["jpeg-q50"](other_copy), original, KEY, innocents)
    values = np.array(list(scores.values()))
    assert np.mean(values >= 3) <= 2 * 4 * (1 - NormalDist().cdf(3))
    assert values.max() < THRESHOLD


@pytest.mark.parametrize("decode", ["[1 0 1 0 1 0]", "[0 1 0 1 0 1]"])
def test_pdf_decode_preserves_rendered_appearance(decode):
    pdf = photo_pdf([make_photo(320, 288)])
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        doc.xref_set_key(doc[0].get_images()[0][0], "Decode", decode)
        pdf = doc.tobytes()
        pix = doc[0].get_pixmap()
        before = np.asarray(Image.frombytes("RGB", (pix.width, pix.height), pix.samples), dtype=float)
    marked = DavideWatermark.add_watermark(pdf, "abcde", KEY)
    with fitz.open(stream=marked, filetype="pdf") as doc:
        pix = doc[0].get_pixmap()
        after = np.asarray(Image.frombytes("RGB", (pix.width, pix.height), pix.samples), dtype=float)
    assert 10 * np.log10(255 ** 2 / np.mean((before - after) ** 2)) > 32
    assert DavideWatermark.read_secret(marked, KEY) == "abcde"


def test_unreadable_image_does_not_hide_later_carrier_or_log_document_data(caplog):
    marker = "synthetic_private_document_marker"
    pdf = photo_pdf([make_photo(64, 64), make_photo(320, 288)])
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        doc.xref_set_key(doc[0].get_images()[0][0], "ColorSpace", "/" + marker)
        pdf = doc.tobytes()
    with caplog.at_level("DEBUG", logger=method_module.__name__):
        assert DavideWatermark.is_watermark_applicable(pdf)
        marked = DavideWatermark.add_watermark(pdf, "abcde", KEY)
        assert DavideWatermark.read_secret(marked, KEY) == "abcde"
    assert caplog.records
    assert marker not in caplog.text


@pytest.mark.parametrize("secret", ["abcde", "\u00e9abc"])
def test_exact_payload_capacity_roundtrip_and_attribution(secret, monkeypatch):
    # 128*96 provides exactly 1344 slots, for five UTF-8 bytes plus the tag.
    pdf = photo_pdf([make_photo(128, 96)])
    marked = DavideWatermark.add_watermark(pdf, secret, KEY)
    assert DavideWatermark.read_secret(marked, KEY) == secret
    # At equality the normal carrier is sufficient; scan fallback must not run.
    def no_scan(*args):
        pytest.fail("normal image has enough capacity")
    monkeypatch.setattr(method_module, "_scan_images", no_scan)
    scores = DavideWatermark.score_recipients(marked, pdf, KEY, [secret, "other"])
    assert scores[secret] > THRESHOLD > scores["other"]


def test_shared_xref_uses_budget_once(monkeypatch):
    pdf = photo_pdf([make_photo(128, 96), make_photo(128, 96)])
    monkeypatch.setattr(method_module, "_MAX_TOTAL_PIXELS", 2 * 128 * 96)
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        infos = doc[0].get_images()
        assert infos[0][0] == infos[1][0]
        assert len(list(_images(doc))) == 1


@pytest.mark.parametrize("sizes", [[(80, 300), (300, 80)], [(300, 80), (80, 300)]])
def test_image_enumeration_preserves_dimensions(sizes):
    pdf = photo_pdf([make_photo(*size, seed=i) for i, size in enumerate(sizes)])
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        assert [img.size for _, img in _images(doc)] == sizes


def test_small_image_does_not_hide_later_carrier():
    pdf = photo_pdf([make_photo(64, 64), make_photo(320, 288)])
    marked = DavideWatermark.add_watermark(pdf, "abcde", KEY)
    assert DavideWatermark.read_secret(marked, KEY) == "abcde"


def test_budget_skips_large_image_but_keeps_smaller_one(monkeypatch):
    monkeypatch.setattr(method_module, "_MAX_PIXELS", 100 * 100)
    monkeypatch.setattr(method_module, "_MAX_TOTAL_PIXELS", 2 * 100 * 100)
    sizes = [(100, 100), (160, 160), (80, 100), (80, 100)]
    pdf = photo_pdf([make_photo(*size, seed=i) for i, size in enumerate(sizes)])
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        assert [img.size for _, img in _images(doc)] == [(100, 100), (80, 100)]


@pytest.mark.parametrize("length", [0, 129])
def test_authenticated_payload_outside_supported_length_is_rejected(length):
    # Authenticate real ciphertext, bypassing only the writer's length guard.
    ciphertext = method_module._cipher(KEY).encrypt(b"x" * length, [])
    bits = np.unpackbits(np.frombuffer(ciphertext, dtype=np.uint8))
    image = embed_payload(make_photo(640, 640), bits, KEY)
    assert method_module._read_image(image, KEY) is None


@pytest.mark.parametrize("broken", [b"not a document", b"%PDF-1.7\ntruncated"])
def test_malformed_pdf_is_not_applicable(broken):
    assert not DavideWatermark.is_watermark_applicable(broken)


def test_replacement_publishes_renderable_rgb_and_clears_old_decode_parameters():
    pdf = photo_pdf([make_photo(128, 96)])
    replacement = make_photo(160, 120, seed=9)
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        xref = doc[0].get_images()[0][0]
        doc.xref_set_key(xref, "Decode", "[1 0 1 0 1 0]")
        doc.xref_set_key(xref, "DecodeParms", "<< /ColorTransform 0 >>")
        doc.xref_set_key(xref, "ColorSpace", "/DeviceGray")
        doc.xref_set_key(xref, "BitsPerComponent", "1")
        _replace_image(doc, xref, replacement)
        for name, value in [("Filter", "/DCTDecode"), ("ColorSpace", "/DeviceRGB"),
                            ("Decode", "null"), ("DecodeParms", "null"),
                            ("BitsPerComponent", "8"), ("Width", "160"), ("Height", "120")]:
            assert doc.xref_get_key(xref, name)[1] == value
        pix = fitz.Pixmap(doc, xref)
        decoded = np.asarray(Image.frombytes("RGB", (pix.width, pix.height), pix.samples), dtype=float)
        assert decoded.shape == (120, 160, 3)
        assert 10 * np.log10(255 ** 2 / np.mean((decoded - np.asarray(replacement)) ** 2)) > 32


def test_unreferenced_unmarked_image_stream_is_removed():
    pdf = photo_pdf([make_photo(320, 288)])
    orphan = b"synthetic-unreferenced-image-canary"
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        xref = doc.get_new_xref()
        doc.update_object(xref, "<< /Type /XObject /Subtype /Image /Width 1 /Height 1 "
                                "/ColorSpace /DeviceRGB /BitsPerComponent 8 >>")
        doc.update_stream(xref, orphan)
        pdf = doc.tobytes()
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        assert any(doc.xref_stream(i) == orphan for i in range(1, doc.xref_length()))
    marked = DavideWatermark.add_watermark(pdf, "abcde", KEY)
    with fitz.open(stream=marked, filetype="pdf") as doc:
        assert not any(doc.xref_stream(i) == orphan for i in range(1, doc.xref_length()))
    assert DavideWatermark.read_secret(marked, KEY) == "abcde"


@pytest.mark.parametrize("secret", ["abcdef", "\u00e9\u00e9\u00e9"])
def test_scan_attribution_when_normal_carrier_is_too_small(secret, monkeypatch):
    monkeypatch.setattr(method_module, "_MAX_PIXELS", 128 * 96)
    pdf = photo_pdf([make_photo(128, 96), make_photo(320, 288)])
    marked = DavideWatermark.add_watermark(pdf, secret, KEY)
    assert DavideWatermark.read_secret(marked, KEY) == secret
    scores = DavideWatermark.score_recipients(marked, pdf, KEY, [secret, "other"])
    assert scores[secret] > THRESHOLD > scores["other"]
    assert DavideWatermark.score_recipients(marked, pdf, KEY, [secret], scans=False)[secret] < THRESHOLD


@pytest.mark.parametrize("size", [(320, 256), (256, 320)])
def test_oversize_metadata_is_rejected_before_image_decoder(size, monkeypatch):
    pdf = photo_pdf([make_photo(*size)])
    monkeypatch.setattr(method_module, "_MAX_PIXELS", 256 * 256)
    def unexpected_decode(*args, **kwargs):
        pytest.fail("oversize PDF image reached the decoder")
    monkeypatch.setattr(method_module.Image, "open", unexpected_decode)
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        assert list(_images(doc)) == []


def test_budget_charges_larger_declared_dimensions(monkeypatch):
    pdf = photo_pdf([make_photo(128, 96), make_photo(128, 96, seed=9)])
    monkeypatch.setattr(method_module, "_MAX_TOTAL_PIXELS", 2 * 128 * 96)
    with fitz.open(stream=pdf, filetype="pdf") as doc:
        xref = doc[0].get_images()[0][0]
        doc.xref_set_key(xref, "Width", "256")
        assert len(list(_images(doc))) == 1


@pytest.mark.parametrize("size,expected", [((320, 240), False), ((352, 240), True)])
def test_applicability_reserves_capacity_for_the_longest_secret(size, expected):
    assert DavideWatermark.is_watermark_applicable(photo_pdf([make_photo(*size)])) is expected
