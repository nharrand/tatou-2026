"""Complete blocks, reconstruction and fingerprint evidence."""

import importlib

import numpy as np
import pytest
from photos import make_photo
from PIL import Image

image = importlib.import_module("watermarking_methods.davide.image")


@pytest.mark.parametrize("size", [(8, 8), (17, 25), (25, 17), (7, 17)])
def test_capacity_and_transform_use_only_complete_blocks(size):
    source = make_photo(*size)
    pixels, dct = image._dct(source)
    assert dct.shape == (size[1] // 8, size[0] // 8, 8, 8)
    slots = image.capacity(source)
    assert isinstance(slots, int)
    assert slots == (size[0] // 8) * (size[1] // 8) * 7
    reconstructed = image._to_image(pixels, dct)
    expected = source.convert("YCbCr").convert("RGB")
    assert np.array_equal(np.asarray(reconstructed), np.asarray(expected))


@pytest.mark.parametrize("luminance,expected", [(-400, 0), (400, 255), (256, 255)])
def test_reconstruction_saturates_instead_of_wrapping(luminance, expected):
    pixels = np.full((8, 8, 3), 128.0)
    dct = np.zeros((1, 1, 8, 8))
    dct[0, 0, 0, 0] = (luminance - 128) * 8
    result = np.asarray(image._to_image(pixels, dct))
    assert np.all(result == expected)


def test_zero_evidence_candidate_does_not_hide_later_fingerprint(monkeypatch):
    original = make_photo(128, 96)
    marked = image.embed_fingerprint(original, "synthetic-key", "recipient")
    monkeypatch.setattr(image, "align", lambda *args: [original, marked, original])
    scores = image.fingerprint_scores(marked, original, "synthetic-key", ["recipient", "other"])
    assert scores["recipient"] > 6 > scores["other"]


def test_unchanged_image_has_no_fingerprint_evidence(monkeypatch):
    original = make_photo(64, 64)
    monkeypatch.setattr(image, "align", lambda *args: [original])
    assert image.fingerprint_scores(original, original, "key", ["recipient"]) == {"recipient": -np.inf}


def test_outliers_and_brightness_do_not_accuse_another_recipient(monkeypatch):
    original = make_photo(256, 256)
    marked = image.embed_fingerprint(original, "synthetic-key", "recipient")
    pixels = np.asarray(marked).astype(float) + 6
    pixels[80:96, 80:96] = 255
    attacked = Image.fromarray(np.clip(pixels, 0, 255).astype(np.uint8))
    monkeypatch.setattr(image, "align", lambda *args: [attacked])
    scores = image.fingerprint_scores(attacked, original, "synthetic-key", ["recipient", "other"])
    assert scores["recipient"] > 6 > scores["other"]


def test_fingerprint_preserves_quality_with_concentrated_texture():
    pixels = np.full((96, 128, 3), 128, dtype=np.uint8)
    pixels[:8, :8] = np.random.default_rng(4).integers(0, 256, (8, 8, 3), dtype=np.uint8)
    source = Image.fromarray(pixels)
    marked = np.asarray(image.embed_fingerprint(source, "synthetic-key", "recipient"), dtype=float)
    assert 10 * np.log10(255 ** 2 / np.mean((marked - pixels) ** 2)) > 32
