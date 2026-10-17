"""Embed encrypted payloads and recipient fingerprints in image DCT coefficients.

QIM repeats payload bits in mid-frequency luminance coefficients. Keyed noise in low-
frequency coefficients supports attribution against the original image.
"""

from __future__ import annotations

import hashlib
import hmac

import numpy as np
from PIL import Image

from .align import align

# (row, col) of the coefficients used in every 8x8 block.
FINGERPRINT = [(0, 1), (1, 0), (1, 1), (0, 2), (2, 0), (1, 2), (2, 1)]
PAYLOAD = [(0, 3), (3, 0), (2, 2), (1, 3), (3, 1), (2, 3), (3, 2)]

QIM_STEP = 28.0             # Grid spacing: bigger is more robust but more visible.
FINGERPRINT_STRENGTH = 5.0  # Average change of a fingerprint coefficient.

# 8x8 DCT matrix: dct = D @ block @ D.T and block = D.T @ dct @ D.
D = np.array([[np.sqrt((1 if k == 0 else 2) / 8) * np.cos((2 * n + 1) * k * np.pi / 16)
               for n in range(8)] for k in range(8)])


def _rng(key: str, label: bytes) -> np.random.Generator:
    # The writer and the reader get the same random numbers from the same key.
    seed = hmac.new(key.encode("utf-8"), label, hashlib.sha256).digest()
    return np.random.default_rng(int.from_bytes(seed, "big"))


def _dct(img: Image.Image) -> tuple[np.ndarray, np.ndarray]:
    """Return YCbCr pixels and full-block luminance DCT arrays shaped (rows, cols, 8, 8)."""
    ycc = np.asarray(img.convert("YCbCr"), dtype=np.float64).copy()
    h, w = ycc.shape[0] // 8 * 8, ycc.shape[1] // 8 * 8
    blocks = (ycc[:h, :w, 0] - 128).reshape(h // 8, 8, w // 8, 8).swapaxes(1, 2)
    return ycc, D @ blocks @ D.T


def _to_image(ycc: np.ndarray, dct: np.ndarray) -> Image.Image:
    blocks = D.T @ dct @ D
    h, w = blocks.shape[0] * 8, blocks.shape[1] * 8
    ycc[:h, :w, 0] = blocks.swapaxes(1, 2).reshape(h, w) + 128
    return Image.fromarray(np.clip(ycc, 0, 255).round().astype(np.uint8), "YCbCr").convert("RGB")


def _get(dct: np.ndarray, positions: list[tuple[int, int]]) -> np.ndarray:
    rows, cols = zip(*positions, strict=True)
    return dct[:, :, list(rows), list(cols)]


def _set(dct: np.ndarray, positions: list[tuple[int, int]], values: np.ndarray) -> None:
    rows, cols = zip(*positions, strict=True)
    dct[:, :, list(rows), list(cols)] = values


def capacity(img: Image.Image) -> int:
    """Return the number of payload coefficient slots in the image."""
    return (img.width // 8) * (img.height // 8) * len(PAYLOAD)


def _order_and_dither(n: int, key: str) -> tuple[np.ndarray, np.ndarray]:
    order = _rng(key, b"qim/order").permutation(n)
    dither = _rng(key, b"qim/dither").uniform(0, QIM_STEP, n)
    return order, dither


def embed_payload(img: Image.Image, bits: np.ndarray, key: str) -> Image.Image:
    ycc, dct = _dct(img)
    coefs = _get(dct, PAYLOAD).reshape(-1)
    order, dither = _order_and_dither(coefs.size, key)

    # The i-th slot in key order carries bit i % len(bits), so the payload is repeated.
    wanted = np.empty(coefs.size, dtype=np.int64)
    wanted[order] = bits[np.arange(coefs.size) % len(bits)]

    # Nearest point of the grid: dither + k * step for 0, half a step further for 1.
    offset = dither + wanted * QIM_STEP / 2
    coefs = QIM_STEP * np.round((coefs - offset) / QIM_STEP) + offset

    _set(dct, PAYLOAD, coefs.reshape(dct.shape[0], dct.shape[1], len(PAYLOAD)))
    return _to_image(ycc, dct)


def read_votes(img: Image.Image, key: str) -> np.ndarray:
    """Return key-ordered slot votes: positive for zero, negative for one, near zero for damage."""
    _, dct = _dct(img)
    coefs = _get(dct, PAYLOAD).reshape(-1)
    order, dither = _order_and_dither(coefs.size, key)

    # 0 on the grid of the zeros, 0.5 on the grid of the ones.
    phase = np.mod(coefs[order] - dither[order], QIM_STEP) / QIM_STEP
    return np.cos(2 * np.pi * phase)


def vote(votes: np.ndarray, n_bits: int) -> np.ndarray:
    """Recover each bit from the sum of its repeated slot votes."""
    totals = np.bincount(np.arange(votes.size) % n_bits, weights=votes, minlength=n_bits)
    return (totals < 0).astype(np.uint8)


def _noise(shape: tuple[int, ...], key: str, secret: str) -> np.ndarray:
    return _rng(key, b"fingerprint/" + secret.encode("utf-8")).choice((-1.0, 1.0), size=shape)


def embed_fingerprint(img: Image.Image, key: str, secret: str) -> Image.Image:
    ycc, dct = _dct(img)
    coefs = _get(dct, FINGERPRINT)

    # Stronger in detailed blocks, weaker in flat ones where it would be visible.
    detail = np.abs(dct[:, :, 1:, 1:]).mean(axis=(2, 3))
    strength = FINGERPRINT_STRENGTH * np.clip(detail / (detail.mean() + 1e-9), 0.4, 2.0)

    _set(dct, FINGERPRINT, coefs + strength[..., None] * _noise(coefs.shape, key, secret))
    return _to_image(ycc, dct)


def fingerprint_scores(leak: Image.Image, original: Image.Image, key: str, secrets: list[str]) -> dict[str, float]:
    """Score recipient noise in the difference between leaked and original images.

    Absent fingerprints follow the modeled N(0, 1) distribution; intact matching
    fingerprints produce substantially higher scores.
    """
    scores = {secret: float("-inf") for secret in secrets}
    reference = _get(_dct(original)[1], FINGERPRINT)

    for aligned in align(leak, original):
        diff = _get(_dct(aligned)[1], FINGERPRINT) - reference
        diff -= diff.mean()
        # Outliers (white corners of a rotation, pasted logos) carry no noise: clip them to 3
        # robust standard deviations.
        limit = 3 * 1.4826 * np.median(np.abs(diff))
        diff = np.clip(diff, -limit, limit)
        norm = np.linalg.norm(diff)
        if norm == 0:
            continue
        for secret in secrets:
            z = float((diff * _noise(diff.shape, key, secret)).sum() / norm)
            scores[secret] = max(scores[secret], z)

    return scores
