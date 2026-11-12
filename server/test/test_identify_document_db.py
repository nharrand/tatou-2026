"""End-to-end coverage for /api/identify-document, against a real database.

This mirrors the fixture and skip pattern already used in ``test_api_db.py``:
the unit-level checks that never touch SQL (auth, missing/unknown method,
missing file, non-PDF upload) live in ``test_identify_document_unit.py``;
everything here needs a real document, a real watermarked version, and a
real recovered secret to match against, so it is skipped outside the
compose network where the database port is reachable.

What this file pins down, one assertion per security requirement from
API.md#identify-document:

* the route works: a version created with ``create-watermark``'s underlying
  call is correctly identified, and a watermark that matches no stored
  version comes back with an empty ``matches`` list (not an error);
* ownership is enforced, and a document that is not the caller's gets the
  *same* 404 as a document that does not exist at all - no existence oracle;
* a failed read (wrong key) never echoes the key or the real secret back in
  the error message;
* the uploaded bytes are never written under ``STORAGE_DIR`` - the route
  processes the file in memory only.
"""
import hashlib
import io
import uuid
from pathlib import Path

import pymupdf
import pytest
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text

import server
import watermarking_utils as WMUtils


def _engine():
    c = server.app.config
    url = (
        f"mysql+pymysql://{c['DB_USER']}:{c['DB_PASSWORD']}"
        f"@{c['DB_HOST']}:{c['DB_PORT']}/{c['DB_NAME']}?charset=utf8mb4"
    )
    return create_engine(url, pool_pre_ping=True, future=True)


def _database_is_reachable() -> bool:
    try:
        with _engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _database_is_reachable(),
    reason="no database on the compose network; unit runs skip this module",
)


def _token(uid, login):
    serializer = URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
    return serializer.dumps({"uid": uid, "login": login, "email": f"{login}@example.com"})


def _auth(uid, login):
    return {"Authorization": f"Bearer {_token(uid, login)}"}


def _one_page_pdf() -> bytes:
    """A real single-page PDF, so the watermarking methods have a page to work on."""
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Group 18 - confidential")
    data = doc.tobytes()
    doc.close()
    return data


def _post(client, doc_id, auth, fields, file_bytes, filename="found.pdf"):
    data = dict(fields)
    data["file"] = (io.BytesIO(file_bytes), filename)
    return client.post(
        f"/api/identify-document/{doc_id}",
        data=data,
        headers=auth,
        content_type="multipart/form-data",
    )


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    """One owner, one other user, one document, one *real* watermarked version."""
    monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)

    tag = uuid.uuid4().hex[:10]
    pdf_path = Path(tmp_path) / f"{tag}.pdf"
    pdf_bytes = _one_page_pdf()
    pdf_path.write_bytes(pdf_bytes)
    digest = hashlib.sha256(pdf_bytes).hexdigest()

    owner_login = f"owner_{tag}"
    other_login = f"other_{tag}"
    link = f"link{tag}"

    secret = f"secret-{tag}"
    key = f"key-{tag}"
    method = "toy-eof"

    watermarked_bytes = WMUtils.apply_watermark(
        pdf=str(pdf_path), secret=secret, key=key, method=method, position=None
    )
    dest_path = Path(tmp_path) / f"{tag}__watermarked.pdf"
    dest_path.write_bytes(watermarked_bytes)

    eng = _engine()
    with eng.begin() as conn:
        uid = conn.execute(
            text("INSERT INTO Users (email, hpassword, login) VALUES (:e, :h, :l)"),
            {"e": f"{owner_login}@example.com", "h": "x" * 20, "l": owner_login},
        ).lastrowid
        other_uid = conn.execute(
            text("INSERT INTO Users (email, hpassword, login) VALUES (:e, :h, :l)"),
            {"e": f"{other_login}@example.com", "h": "x" * 20, "l": other_login},
        ).lastrowid

        doc_id = conn.execute(
            text(
                "INSERT INTO Documents (name, path, ownerid, sha256, size) "
                "VALUES (:n, :p, :o, UNHEX(:s), :z)"
            ),
            {"n": f"{tag}.pdf", "p": str(pdf_path), "o": uid, "s": digest, "z": len(pdf_bytes)},
        ).lastrowid

        version_id = conn.execute(
            text(
                "INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path) "
                "VALUES (:d, :l, :f, :s, :m, :pos, :p)"
            ),
            {
                "d": doc_id,
                "l": link,
                "f": "recipient@example.com",
                "s": secret,
                "m": method,
                "pos": "{}",
                "p": str(dest_path),
            },
        ).lastrowid

    yield {
        "uid": uid,
        "other_uid": other_uid,
        "login": owner_login,
        "other_login": other_login,
        "doc_id": doc_id,
        "version_id": version_id,
        "secret": secret,
        "key": key,
        "method": method,
        "watermarked_bytes": watermarked_bytes,
    }

    with eng.begin() as conn:
        conn.execute(text("DELETE FROM Users WHERE id IN (:a, :b)"), {"a": uid, "b": other_uid})


# ---------------------------------------------------------------- happy path

def test_identify_document_matches_the_created_version(seeded):
    client = server.app.test_client()
    r = _post(
        client,
        seeded["doc_id"],
        _auth(seeded["uid"], seeded["login"]),
        {"method": seeded["method"], "key": seeded["key"]},
        seeded["watermarked_bytes"],
    )
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["documentid"] == seeded["doc_id"]
    assert body["method"] == seeded["method"]
    assert body["secret"] == seeded["secret"]
    assert body["matches"] == [
        {"versionid": seeded["version_id"], "intended_for": "recipient@example.com"}
    ]


def test_identify_document_returns_empty_matches_when_nothing_matches(seeded):
    """A real watermark is read successfully, but no stored version has that secret."""
    client = server.app.test_client()
    unmatched_bytes = WMUtils.apply_watermark(
        pdf=seeded["watermarked_bytes"],
        secret="a-secret-nobody-stored",
        key=seeded["key"],
        method=seeded["method"],
        position=None,
    )
    r = _post(
        client,
        seeded["doc_id"],
        _auth(seeded["uid"], seeded["login"]),
        {"method": seeded["method"], "key": seeded["key"]},
        unmatched_bytes,
    )
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["matches"] == []


# -------------------------------------------------------------- ownership

def test_identify_document_for_another_user_is_404(seeded):
    client = server.app.test_client()
    r = _post(
        client,
        seeded["doc_id"],
        _auth(seeded["other_uid"], seeded["other_login"]),
        {"method": seeded["method"], "key": seeded["key"]},
        seeded["watermarked_bytes"],
    )
    assert r.status_code == 404


def test_identify_document_unowned_and_nonexistent_get_the_same_answer(seeded):
    """No existence oracle: a document that exists but isn't the caller's, and a
    document id that doesn't exist at all, must be indistinguishable."""
    client = server.app.test_client()
    auth = _auth(seeded["other_uid"], seeded["other_login"])
    fields = {"method": seeded["method"], "key": seeded["key"]}

    r_unowned = _post(client, seeded["doc_id"], auth, fields, seeded["watermarked_bytes"])
    r_missing = _post(client, 999_999_999, auth, fields, seeded["watermarked_bytes"])

    assert r_unowned.status_code == r_missing.status_code == 404
    assert r_unowned.get_json() == r_missing.get_json()


# ------------------------------------------------------ no information leakage

def test_identify_document_wrong_key_does_not_leak_key_or_secret(seeded):
    client = server.app.test_client()
    wrong_key = "definitely-not-" + seeded["key"]
    r = _post(
        client,
        seeded["doc_id"],
        _auth(seeded["uid"], seeded["login"]),
        {"method": seeded["method"], "key": wrong_key},
        seeded["watermarked_bytes"],
    )
    assert r.status_code == 400
    error = r.get_json()["error"]
    assert seeded["key"] not in error
    assert wrong_key not in error
    assert seeded["secret"] not in error


def test_identify_document_does_not_persist_the_upload(seeded, tmp_path):
    """The whole point of in-memory processing: nothing new appears on disk."""
    client = server.app.test_client()
    before = sorted(p.as_posix() for p in tmp_path.rglob("*") if p.is_file())

    r = _post(
        client,
        seeded["doc_id"],
        _auth(seeded["uid"], seeded["login"]),
        {"method": seeded["method"], "key": seeded["key"]},
        seeded["watermarked_bytes"],
    )
    assert r.status_code == 200, r.get_json()

    after = sorted(p.as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert before == after, "the uploaded file must not be written under STORAGE_DIR"
