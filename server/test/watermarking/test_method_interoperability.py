"""Verify registry helpers and interoperability between component watermark layers."""

from __future__ import annotations

import io

import numpy as np
import pymupdf as fitz
import pytest
from PIL import Image

import watermarking_utils as utils
from watermarking_method import WatermarkingError
from watermarking_methods.add_after_eof import AddAfterEOF
from watermarking_utils import (
    METHODS,
    apply_watermark,
    get_method,
    is_watermarking_applicable,
    read_watermark,
    register_method,
)

SECRET = "Group_07:da0bb583c432fbfd078959ecc9b62902"
KEY = "test-only-interchangeable-key"
GROUP = ["davide-watermark", "khaled-text-spacing-watermark", "francesco-watermark", "group13-watermark"]


@pytest.fixture(scope="module")
def source() -> bytes:
    """Create a PDF with photo, text, and border carriers for every method."""
    rng = np.random.default_rng(7)
    y, x = np.mgrid[0:640, 0:800]
    pixels = np.stack([128 + 60 * np.sin(x / 37), 128 + 60 * np.cos(y / 29),
                       128 + 40 * np.sin((x + y) / 53)], -1) + rng.normal(0, 12, (640, 800, 3))
    photo = io.BytesIO()
    Image.fromarray(pixels.clip(0, 255).astype(np.uint8)).save(photo, "JPEG", quality=90)
    with fitz.open() as doc:
        doc.new_page().insert_image(fitz.Rect(100, 150, 495, 466), stream=photo.getvalue())
        page = doc.new_page()
        sentence = "Every method of the group reads the same secret in these letters."
        for row in range(40):
            page.insert_text((70, 110 + row * 16), sentence, fontsize=10)
        return doc.tobytes()


@pytest.fixture(scope="module")
def marked(source) -> dict[str, bytes]:
    return {name: apply_watermark(name, source, SECRET, KEY) for name in GROUP}


@pytest.mark.parametrize("replace_existing", [False, True])
def test_register_method_adds_or_replaces_registry_entry(monkeypatch, replace_existing):
    assert set(GROUP) <= set(METHODS)
    registry = METHODS.copy()
    if replace_existing:
        previous = AddAfterEOF()
        registry[previous.name] = previous
    monkeypatch.setattr(utils, "METHODS", registry)
    method = AddAfterEOF()

    register_method(method)

    assert get_method(method.name) is method
    assert registry == {**METHODS, method.name: method}


def test_get_method_accepts_an_existing_instance():
    method = AddAfterEOF()
    assert get_method(method) is method


def test_get_method_rejects_unknown_names_with_key_error(monkeypatch):
    monkeypatch.setattr(utils, "METHODS", METHODS.copy())
    with pytest.raises(KeyError):
        get_method("unregistered-test-method")


@pytest.mark.parametrize("name,accepts_recipient", [
    ("davide-watermark", False), ("khaled-text-spacing-watermark", False),
    ("francesco-watermark", True), ("group13-watermark", True),
])
def test_apply_helper_forwards_inputs_to_selected_method(monkeypatch, name, accepts_recipient):
    method = METHODS[name]
    calls = []

    def embed(**kwargs):
        calls.append(kwargs)
        return b"%PDF-result"

    monkeypatch.setattr(method, "add_watermark", embed)
    assert apply_watermark(name, b"%PDF-input", "secret", "key", "position", "Group_13") == b"%PDF-result"
    expected = {"pdf": b"%PDF-input", "secret": "secret", "key": "key", "position": "position"}
    if accepts_recipient:
        expected["intended_for"] = "Group_13"
    assert calls == [expected]


@pytest.mark.parametrize("applicable", [False, True])
def test_applicability_helper_forwards_input_and_position(monkeypatch, applicable):
    method = METHODS["davide-watermark"]
    calls = []

    def check(**kwargs):
        calls.append(kwargs)
        return applicable

    monkeypatch.setattr(method, "is_watermark_applicable", check)
    assert is_watermarking_applicable(method.name, b"%PDF-input", "position") is applicable
    assert calls == [{"pdf": b"%PDF-input", "position": "position"}]


@pytest.mark.parametrize("name", GROUP)
def test_each_method_reads_its_own_copy_and_rejects_the_wrong_key(name, source, marked):
    assert is_watermarking_applicable(name, source)
    assert read_watermark(name, marked[name], KEY) == SECRET
    assert METHODS[name].get_usage()
    with pytest.raises((WatermarkingError, ValueError)):
        read_watermark(name, marked[name], "another-key")


@pytest.mark.parametrize("name", GROUP[:3])
def test_group13_reads_a_copy_made_by_any_single_method(name, marked):
    assert read_watermark("group13-watermark", marked[name], KEY) == SECRET


@pytest.mark.parametrize("name", GROUP[:3])
def test_a_single_method_reads_its_layer_of_a_group13_copy(name, marked):
    assert read_watermark(name, marked["group13-watermark"], KEY) == SECRET
