"""Cryptographic tests for key derivation and authenticated QR payloads."""

from __future__ import annotations

import pytest

from watermarking_method import InvalidKeyError
from watermarking_methods.francesco import crypto

DUMMY_KEY = "0123456789abcdef" * 4
OTHER_DUMMY_KEY = "fedcba9876543210" * 4


def test_key_derivation_is_deterministic_and_rejects_empty_keys():
    k1 = crypto.derive_aes_key(DUMMY_KEY)
    assert len(k1) == 64
    k2 = crypto.derive_aes_key("dummy-test-passphrase")
    assert len(k2) == 64
    assert k1 != k2

    assert crypto.derive_aes_key("same-key") == crypto.derive_aes_key("same-key")

    with pytest.raises(InvalidKeyError):
        crypto.derive_aes_key("")


def test_qr_payload_uses_random_salt_and_rejects_invalid_authentication():
    # Encrypting the exact same payload twice produces DIFFERENT ciphertexts due to random salt.
    dummy_payload = "dummy-copy-link-token-12345"
    p1 = crypto.encrypt_qr_payload(dummy_payload, DUMMY_KEY)
    p2 = crypto.encrypt_qr_payload(dummy_payload, DUMMY_KEY)
    assert p1 != p2
    assert crypto.is_candidate_payload(p1)
    assert crypto.is_candidate_payload(p2)

    assert crypto.decrypt_qr_payload(p1, DUMMY_KEY) == dummy_payload
    assert crypto.decrypt_qr_payload(p2, DUMMY_KEY) == dummy_payload

    with pytest.raises(InvalidKeyError):
        crypto.decrypt_qr_payload(p1, OTHER_DUMMY_KEY)

    # Tampered ciphertext fails authentication (MAC / SIV tag mismatch).
    tampered = p1[:-1] + ("A" if p1[-1] != "A" else "B")
    with pytest.raises(InvalidKeyError):
        crypto.decrypt_qr_payload(tampered, DUMMY_KEY)


def test_rmap_secret_roundtrip():
    secret = "Group_07:da0bb583c432fbfd078959ecc9b62902"
    payload = crypto.encrypt_qr_payload(secret, DUMMY_KEY)
    assert crypto.decrypt_qr_payload(payload, DUMMY_KEY) == secret


def test_visible_payload_uses_salted_aes_and_lowercase_base32():
    secret = "Group_07:da0bb583c432fbfd078959ecc9b62902"
    first = crypto.encrypt_visible_payload(secret, DUMMY_KEY)
    second = crypto.encrypt_visible_payload(secret, DUMMY_KEY)

    assert first != second
    assert first == first.lower()
    assert set(first) <= set("abcdefghijklmnopqrstuvwxyz234567")
    assert crypto.decrypt_visible_payload(first, DUMMY_KEY) == secret
    assert crypto.decrypt_visible_payload(second, DUMMY_KEY) == secret
    assert crypto.decrypt_visible_payload(first.upper(), DUMMY_KEY) == secret
    with pytest.raises(InvalidKeyError):
        crypto.decrypt_visible_payload(first, OTHER_DUMMY_KEY)


@pytest.mark.parametrize("channel,salt_number,secret", [("qr", 55, "x"), ("visible", 38, "xy"), ("visible", 55, "x")])
def test_payload_preserves_final_x(monkeypatch, channel, salt_number, secret):
    key = "synthetic-francesco-review-key"
    monkeypatch.setattr(crypto.os, "urandom", lambda size: salt_number.to_bytes(size, "big"))
    encrypt = getattr(crypto, f"encrypt_{channel}_payload")
    decrypt = getattr(crypto, f"decrypt_{channel}_payload")
    payload = encrypt(secret, key)
    if salt_number == 38 or channel == "qr":
        assert payload.upper().endswith("X")
    assert decrypt(payload, key) == secret


@pytest.mark.parametrize("secret", ["x", "\u00e9", "x" * 64, "\u00e9" * 32])
def test_both_channels_authenticate_utf8_boundaries(secret):
    for encrypt, decrypt in (
        (crypto.encrypt_qr_payload, crypto.decrypt_qr_payload),
        (crypto.encrypt_visible_payload, crypto.decrypt_visible_payload),
    ):
        payload = encrypt(secret, DUMMY_KEY)
        assert decrypt(payload, DUMMY_KEY) == secret
        with pytest.raises(InvalidKeyError):
            decrypt(payload, OTHER_DUMMY_KEY)
