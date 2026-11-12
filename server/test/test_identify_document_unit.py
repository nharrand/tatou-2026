"""Unit-level coverage for /api/identify-document that needs no database.

Every check here is resolved by the route *before* it ever touches SQL
(authentication, parameter validation, the unknown-method guard, and the
content check on the upload), so these tests run everywhere, including
outside the compose network where test_identify_document_db.py skips itself.
"""
import io

import server


def _client():
    return server.app.test_client()


def _pdf_bytes() -> bytes:
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


# ------------------------------------------------------------- authentication

def test_identify_document_requires_authentication():
    r = _client().post(
        "/api/identify-document/1",
        data={
            "method": "toy-eof",
            "key": "k",
            "file": (io.BytesIO(_pdf_bytes()), "found.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 401


def test_identify_document_rejects_a_bad_token():
    r = _client().post(
        "/api/identify-document/1",
        data={
            "method": "toy-eof",
            "key": "k",
            "file": (io.BytesIO(_pdf_bytes()), "found.pdf"),
        },
        headers={"Authorization": "Bearer not-a-real-token"},
        content_type="multipart/form-data",
    )
    assert r.status_code == 401


# --------------------------------------------------------- parameter checks
#
# These need a token that verifies (so the request gets past @require_auth),
# but none of them require a database: every check below runs in the route
# body before any SQL is issued, against a user id that need not exist.

def _fake_auth():
    from itsdangerous import URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps({"uid": 1, "login": "someone", "email": "someone@example.com"})
    return {"Authorization": f"Bearer {token}"}


def test_identify_document_requires_method():
    r = _client().post(
        "/api/identify-document/1",
        data={"key": "k", "file": (io.BytesIO(_pdf_bytes()), "found.pdf")},
        headers=_fake_auth(),
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_identify_document_requires_key():
    r = _client().post(
        "/api/identify-document/1",
        data={"method": "toy-eof", "file": (io.BytesIO(_pdf_bytes()), "found.pdf")},
        headers=_fake_auth(),
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "error" in r.get_json()


# ------------------------------------------------------- unknown method (405)

def test_identify_document_unknown_method_is_405():
    r = _client().post(
        "/api/identify-document/1",
        data={
            "method": "this-method-does-not-exist",
            "key": "k",
            "file": (io.BytesIO(_pdf_bytes()), "found.pdf"),
        },
        headers=_fake_auth(),
        content_type="multipart/form-data",
    )
    assert r.status_code == 405
    assert "error" in r.get_json()


def test_identify_document_unknown_method_is_checked_before_the_file():
    """The method name is validated even when no file is attached at all -
    an unknown method must never reach the point of needing one."""
    r = _client().post(
        "/api/identify-document/1",
        data={"method": "this-method-does-not-exist", "key": "k"},
        headers=_fake_auth(),
        content_type="multipart/form-data",
    )
    assert r.status_code == 405


# ------------------------------------------------------------- upload checks

def test_identify_document_requires_a_file():
    r = _client().post(
        "/api/identify-document/1",
        data={"method": "toy-eof", "key": "k"},
        headers=_fake_auth(),
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_identify_document_rejects_a_non_pdf_upload():
    r = _client().post(
        "/api/identify-document/1",
        data={
            "method": "toy-eof",
            "key": "k",
            "file": (io.BytesIO(b"this is not a pdf at all"), "found.pdf"),
        },
        headers=_fake_auth(),
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_identify_document_rejects_a_pdf_disguised_by_extension_only():
    """Content is what's checked, not the filename - a .pdf name with no
    %PDF- header must still be rejected."""
    r = _client().post(
        "/api/identify-document/1",
        data={
            "method": "toy-eof",
            "key": "k",
            "file": (io.BytesIO(b"<html>not a pdf</html>"), "totally-a.pdf"),
        },
        headers=_fake_auth(),
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
