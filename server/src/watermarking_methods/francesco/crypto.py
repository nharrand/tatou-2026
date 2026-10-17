"""Key derivation and the authenticated AES-SIV payload of the QR code."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from reedsolo import ReedSolomonError, RSCodec

from watermarking_method import InvalidKeyError

_VERSION: Final[bytes] = b"\x01"
_AES_KEY_DOMAIN: Final[bytes] = b"tatou/francesco-watermark/aes-siv-key/v1\0"
SALT_BYTES: Final[int] = 16
VISIBLE_RS_PARITY_BYTES: Final[int] = 16

BASE64_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]+")


def derive_aes_key(key: str) -> bytes:
    """Derive a domain-separated 64-byte AES-SIV key."""
    if not isinstance(key, str) or not key:
        raise InvalidKeyError("Invalid watermark key")
    return hashlib.sha512(_AES_KEY_DOMAIN + key.encode("utf-8")).digest()


def is_candidate_payload(payload: str) -> bool:
    """Check if a string matches the format of an encrypted QR payload (URL-safe base64)."""
    if not isinstance(payload, str):
        return False
    text = payload.strip()
    return 20 <= len(text) <= 200 and bool(BASE64_URL_PATTERN.fullmatch(text))


def encrypt_qr_payload(secret: str, key: str, salt: bytes | None = None) -> str:
    """Encrypt and authenticate the secret with AES-SIV and a random 16-byte salt."""
    if not secret:
        raise ValueError("Secret must not be empty")
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    elif len(salt) != SALT_BYTES:
        raise ValueError(f"Salt must be exactly {SALT_BYTES} bytes")

    aes_key = derive_aes_key(key)
    plaintext = salt + secret.encode("utf-8")
    ciphertext = AESSIV(aes_key).encrypt(plaintext, [_VERSION])
    return base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")


def decrypt_qr_payload(payload: str, key: str) -> str:
    """Decrypt and verify an AES-SIV QR payload, extracting the secret and discarding the salt."""
    encoded = payload.strip()
    if not encoded or len(encoded) > 200 or not BASE64_URL_PATTERN.fullmatch(encoded):
        raise InvalidKeyError("Malformed francesco-watermark QR")

    try:
        ciphertext = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii") != encoded:
            raise ValueError("Noncanonical QR encoding")
        aes_key = derive_aes_key(key)
        plaintext = AESSIV(aes_key).decrypt(ciphertext, [_VERSION])
    except (InvalidTag, ValueError, UnicodeError, binascii.Error) as exc:
        raise InvalidKeyError("Francesco-watermark QR authentication failed") from exc

    if len(plaintext) < SALT_BYTES:
        raise InvalidKeyError("Payload shorter than salt length")

    secret_bytes = plaintext[SALT_BYTES:]
    try:
        secret = secret_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidKeyError("Invalid UTF-8 secret") from exc

    if not secret:
        raise InvalidKeyError("Empty francesco-watermark QR secret")

    return secret


def encrypt_visible_payload(secret: str, key: str) -> str:
    """Encrypt a visible label payload and encode it as lowercase Base32."""
    qr_payload = encrypt_qr_payload(secret, key)
    ciphertext = base64.urlsafe_b64decode(qr_payload + "=" * (-len(qr_payload) % 4))
    protected = RSCodec(VISIBLE_RS_PARITY_BYTES).encode(ciphertext)
    return base64.b32encode(protected).decode("ascii").rstrip("=").lower()


def decrypt_visible_payload(payload: str, key: str) -> str:
    """Decode and authenticate a lowercase Base32 visible-label payload."""
    encoded = payload.strip()
    if not encoded or len(encoded) > 200 or not re.fullmatch(r"[A-Za-z2-7]+", encoded):
        raise InvalidKeyError("Malformed francesco-watermark visible label")

    try:
        protected = base64.b32decode(encoded.upper() + "=" * (-len(encoded) % 8))
        ciphertext = bytes(RSCodec(VISIBLE_RS_PARITY_BYTES).decode(protected)[0])
    except (binascii.Error, ReedSolomonError, ValueError) as exc:
        raise InvalidKeyError("Malformed francesco-watermark visible label") from exc

    qr_payload = base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")
    return decrypt_qr_payload(qr_payload, key)
