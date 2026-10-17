"""Geometry and numerical contracts of image registration."""

import importlib

import numpy as np
import pytest
from photos import make_photo
from PIL import Image

alignment = importlib.import_module("watermarking_methods.davide.align")


@pytest.mark.parametrize("shift", [(0, 25), (25, 0), (-25, 0), (0, -25)])
def test_phase_correlation_returns_signed_translation(shift):
    original = np.random.default_rng(4).normal(size=(64, 64))
    piece = np.roll(original, tuple(-v for v in shift), axis=(0, 1))
    assert alignment._offset(np.fft.fft2(original - original.mean()), piece, 1.0) == shift


def test_similarity_is_brightness_and_contrast_invariant():
    original = np.random.default_rng(4).normal(80, 10, (32, 32))
    transformed = original * 1.7 + 40
    score = alignment._similarity(original, np.fft.fft2(original - original.mean()), transformed)
    assert score == pytest.approx(1.0)


@pytest.mark.parametrize("value", [0.0, 120.0])
def test_constant_images_have_no_matching_evidence(value):
    constant = np.full((32, 32), value)
    assert alignment._similarity(constant, np.fft.fft2(constant - constant.mean()), constant) == -1


def test_details_preserve_negative_edges():
    image = Image.new("L", (32, 32), 0)
    image.paste(255, (16, 0, 32, 32))
    detail = alignment._details(image)
    assert detail.min() < 0 < detail.max()
    assert np.max(np.abs(detail)) <= 255


def test_registration_preserves_original_outside_rotated_piece(monkeypatch):
    # Hold search at a known transform; exercise real resampling, FFT placement and mask
    # compositing independently of heuristic search convergence.
    original = make_photo(96, 80)
    leak = original.crop((16, 16, 80, 64))
    monkeypatch.setattr(alignment, "_best", lambda *args: (False, 3, 1.0))
    output = alignment.register(leak, original)
    piece = alignment._undo(leak, False, 3, 1.0)
    mask = alignment._undo(Image.new("L", leak.size, 255), False, 3, 1.0)
    target = alignment._gray(original)
    dy, dx = alignment._offset(np.fft.fft2(target - target.mean()), alignment._gray(piece), 1.0)
    placed_mask = Image.new("L", original.size)
    placed_mask.paste(mask, (dx, dy))
    outside = np.asarray(placed_mask) == 0
    assert outside.any()
    assert np.array_equal(np.asarray(output)[outside], np.asarray(original)[outside])
    assert np.any(np.asarray(output) != np.asarray(original))


def test_registration_bounds_downsampling_and_refinement(monkeypatch):
    original = make_photo(64, 48)
    leak = original.resize((256, 192))
    observed = []

    def choose(piece, source, size, guesses):
        observed.append(piece.size)
        assert all(abs(angle) <= 6 and 0.2 <= scale <= 1.5 for _, angle, scale in guesses)
        return min(guesses, key=lambda g: abs(g[1]) + abs(g[2] - 0.2))

    monkeypatch.setattr(alignment, "_best", choose)
    output = alignment.register(leak, original)
    assert output.size == original.size
    assert observed
    for width, height in observed:
        assert 0 < max(width, height) <= 1.5 * max(original.size)
        assert width <= leak.width and height <= leak.height
        assert width / height == pytest.approx(leak.width / leak.height, abs=1 / height)
