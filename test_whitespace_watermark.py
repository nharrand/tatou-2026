

import pytest

from whitespace_watermark import WhitespaceWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError


def test_whitespace_watermark_round_trip():
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )

    method = WhitespaceWatermark()
    watermarked = method.add_watermark(pdf, secret="hello", key="mykey")
    recovered = method.read_secret(watermarked, key="mykey")

    assert recovered == "hello"


def test_whitespace_watermark_rejects_wrong_key():
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )

    method = WhitespaceWatermark()
    watermarked = method.add_watermark(pdf, secret="hello", key="mykey")

    with pytest.raises(InvalidKeyError):
        method.read_secret(watermarked, key="wrong-key")


def test_whitespace_watermark_missing_marker_raises_secret_not_found():
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )

    method = WhitespaceWatermark()

    with pytest.raises(SecretNotFoundError):
        method.read_secret(pdf, key="mykey")

def test_whitespace_watermark_rejects_non_string_secret():
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )

    method = WhitespaceWatermark()

    with pytest.raises(ValueError, match="Secret must be a non-empty string"):
        method.add_watermark(pdf, secret=123, key="mykey")

def test_whitespace_watermark_rejects_non_string_key():
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )

    method = WhitespaceWatermark()

    with pytest.raises(ValueError, match="Key must be a non-empty string"):
        method.read_secret(pdf, key=123)
