"""Behavior of the toy EOF method (test-only, not registered)."""

import base64
import json
from io import BytesIO

import fitz
import pytest

from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError
from watermarking_methods.add_after_eof import AddAfterEOF
from watermarking_utils import METHODS


@pytest.fixture
def pdf_bytes() -> bytes:
    with fitz.open() as document:
        document.new_page().insert_text((72, 72), "Tatou toy EOF test")
        return document.tobytes()


def test_round_trip_unicode_secret_and_rendering(pdf_bytes):
    method = AddAfterEOF()
    secret = "watermark-\u00e8-\U0001f510"

    output = method.add_watermark(BytesIO(pdf_bytes), secret, key="private-key")

    assert method.read_secret(output, key="private-key") == secret
    with fitz.open(stream=output, filetype="pdf") as document:
        assert document.page_count == 1
        document[0].get_pixmap()


def test_wrong_key_is_rejected(pdf_bytes):
    method = AddAfterEOF()
    output = method.add_watermark(pdf_bytes, "secret", key="correct-key")

    with pytest.raises(InvalidKeyError):
        method.read_secret(output, key="wrong-key")


def test_missing_mark_is_reported(pdf_bytes):
    with pytest.raises(SecretNotFoundError):
        AddAfterEOF().read_secret(pdf_bytes, key="private-key")


def test_payload_without_marker_is_not_a_watermark(pdf_bytes):
    method = AddAfterEOF()
    output = method.add_watermark(pdf_bytes, "secret", "key")
    payload = output.rsplit(method._MAGIC, 1)[1]
    # A missing-marker index must not accidentally align with a valid payload.
    header = b"%PDF-".ljust(len(method._MAGIC) - 1, b" ")

    with pytest.raises(SecretNotFoundError):
        method.read_secret(header + payload, "key")


@pytest.mark.parametrize("key", ["", None, 0, 7, b"key", []])
def test_embedding_rejects_invalid_key(pdf_bytes, key):
    with pytest.raises(ValueError):
        AddAfterEOF().add_watermark(pdf_bytes, "secret", key)


@pytest.mark.parametrize("key", ["", None, 0, 7, b"key", []])
def test_reading_rejects_invalid_key(pdf_bytes, key):
    method = AddAfterEOF()
    output = method.add_watermark(pdf_bytes, "secret", "key")

    with pytest.raises(ValueError):
        method.read_secret(output, key)


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_embedding_preserves_pdf_content(pdf_bytes, ending):
    original = pdf_bytes.rstrip(b"\r\n") + ending
    output = AddAfterEOF().add_watermark(original, "secret", "key")

    assert output.startswith(original)
    with fitz.open(stream=original, filetype="pdf") as before, fitz.open(stream=output, filetype="pdf") as after:
        assert after.page_count == before.page_count
        assert after[0].get_text() == before[0].get_text()
        assert after[0].get_pixmap().samples == before[0].get_pixmap().samples


def test_reading_uses_last_watermark(pdf_bytes):
    method = AddAfterEOF()
    first = method.add_watermark(pdf_bytes, "first secret", "key")
    second = method.add_watermark(first, "second secret", "key")

    assert method.read_secret(second, "key") == "second secret"


@pytest.mark.parametrize("trailing", [b"", b"\n", b"\nTRAILING\n", b"\nYWJj\n"])
def test_reading_respects_payload_line_boundary(pdf_bytes, trailing):
    method = AddAfterEOF()
    output = method.add_watermark(pdf_bytes, "secret", "key")
    record = output.rstrip(b"\n")

    assert method.read_secret(record + trailing, "key") == "secret"


@pytest.mark.parametrize("payload", [[], None, {}, {"v": 2}])
def test_reading_rejects_invalid_payload_schema(pdf_bytes, payload):
    method = AddAfterEOF()
    record = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))

    with pytest.raises(SecretNotFoundError):
        method.read_secret(pdf_bytes + method._MAGIC + record + b"\n", "key")


def test_reading_reports_unsupported_mac_algorithm(pdf_bytes):
    method = AddAfterEOF()
    record = base64.urlsafe_b64encode(b'{"v":1,"alg":"unknown"}')

    with pytest.raises(WatermarkingError):
        method.read_secret(pdf_bytes + method._MAGIC + record + b"\n", "key")


def test_secret_tampering_is_rejected(pdf_bytes):
    method = AddAfterEOF()
    output = method.add_watermark(pdf_bytes, "original secret", "key")
    prefix, encoded = output.rsplit(method._MAGIC, 1)
    payload = json.loads(base64.urlsafe_b64decode(encoded))
    payload["secret"] = base64.b64encode(b"changed secret").decode("ascii")
    changed = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))

    with pytest.raises(InvalidKeyError):
        method.read_secret(prefix + method._MAGIC + changed + b"\n", "key")


def test_embedding_is_deterministic(pdf_bytes):
    method = AddAfterEOF()

    assert method.add_watermark(pdf_bytes, "secret", "key") == method.add_watermark(pdf_bytes, "secret", "key")


def test_method_is_not_registered():
    assert "toy-eof" not in METHODS
