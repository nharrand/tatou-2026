"""Verify that issued links serve only their document and reject unissued values."""

import io
import secrets
from types import SimpleNamespace

import fitz
import pytest
from sqlalchemy import create_engine, event, text

from watermarking_methods.add_after_eof import AddAfterEOF

KEY = "test-only-key"


def make_pdf():
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Tatou link access fixture")
    data = document.tobytes()
    document.close()
    return data

PDF = make_pdf()


@pytest.fixture
def link_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    import watermarking_utils
    from server import create_app

    # Toy-eof is not registered in production, only here.
    monkeypatch.setitem(watermarking_utils.METHODS, AddAfterEOF.name, AddAfterEOF())

    app = create_app()

    # In-memory sqlite db with the functions the server expects from mariadb.
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def mysql_functions(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.create_function("UNHEX", 1, bytes.fromhex)
        connection.create_function(
            "LAST_INSERT_ID", 0,
            lambda: connection.execute("SELECT last_insert_rowid()").fetchone()[0],
        )

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Users (
                id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                login TEXT NOT NULL, hpassword TEXT NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY, name TEXT, path TEXT,
                ownerid INTEGER REFERENCES Users(id), sha256 BLOB, size INTEGER,
                creation TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY,
                documentid INTEGER REFERENCES Documents(id),
                link TEXT UNIQUE, intended_for TEXT, secret TEXT,
                method TEXT, position TEXT, path TEXT
            )
        """))
    app.config.update(TESTING=True, _ENGINE=engine)
    client = app.test_client()
    csrf = {"X-CSRF-Protection": "1"}
    users = []
    try:
        for index in range(2):
            credentials = {
                "email": f"link-owner-{index}@example.test",
                "password": "test-only-password",
            }
            response = client.post(
                "/api/create-user", headers=csrf,
                json={**credentials, "login": f"link-owner-{index}"},
            )
            assert response.status_code == 201, response.get_json()

            response = client.post("/api/login", headers=csrf, json=credentials)
            assert response.status_code == 200, response.get_json()
            headers = {
                **csrf,
                "Authorization": f"Bearer {response.get_json()['token']}",
            }

            response = client.post(
                "/api/upload-document", headers=headers,
                data={"file": (io.BytesIO(PDF), f"link-owner-{index}.pdf")},
            )
            assert response.status_code == 201, response.get_json()
            document_id = response.get_json()["id"]

            # Issue one watermark link, with a different secret per user.
            secret = f"private-secret-{index}"
            response = client.post(
                f"/api/create-watermark/{document_id}", headers=headers,
                json={"method": "toy-eof", "key": KEY,
                      "secret": secret, "intended_for": f"recipient-{index}"},
            )
            assert response.status_code == 201, response.get_json()

            users.append(SimpleNamespace(
                headers=headers, document_id=document_id,
                secret=secret, version=response.get_json(),
            ))
        yield SimpleNamespace(client=client, users=users)
    finally:
        engine.dispose()


def test_issued_link_serves_pdf_without_authentication(link_app):
    link = link_app.users[0].version["link"]

    assert len(link) == 40
    assert all(char in "0123456789abcdef" for char in link)

    response = link_app.client.get(f"/api/get-version/{link}")
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF-")


@pytest.mark.parametrize("make_link", [
    # Fresh random token.
    lambda issued: secrets.token_hex(20),
    # Last character flipped.
    lambda issued: issued[:-1] + ("0" if issued[-1] != "0" else "1"),
    # Link as a number, plus one.
    lambda issued: f"{int(issued, 16) + 1:040x}"[-40:],
    # All zeros.
    lambda issued: "0" * 40,
], ids=["random", "last-char-flipped", "plus-one", "all-zero"])
def test_unissued_link_returns_404(link_app, make_link):
    issued = {user.version["link"] for user in link_app.users}
    link = make_link(link_app.users[0].version["link"])
    # Never hit the other user's real link by accident.
    assert len(link) == 40 and link not in issued

    response = link_app.client.get(f"/api/get-version/{link}")
    assert response.status_code == 404
    assert response.mimetype != "application/pdf"
    assert b"%PDF" not in response.data
    sensitive_values = [
        value
        for user in link_app.users
        for value in (
            user.secret,
            user.version["intended_for"],
            user.version["filename"],
        )
    ]
    assert all(value.encode() not in response.data for value in sensitive_values)


def test_sha1_of_known_input_is_not_an_issued_link(link_app):
    # Independently verified: SHA-1 of the UTF-8 input b"s1".
    candidate = "640d87e741e6aa4c669a82a4cd304787960513ab"
    issued = {user.version["link"] for user in link_app.users}
    assert candidate not in issued

    response = link_app.client.get(f"/api/get-version/{candidate}")
    assert response.status_code == 404
    assert response.mimetype != "application/pdf"
    assert b"%PDF" not in response.data


def read_downloaded_secret(client, user, pdf):
    response = client.post(
        "/api/upload-document", headers=user.headers,
        data={"file": (io.BytesIO(pdf), "downloaded.pdf")},
    )
    assert response.status_code == 201, response.get_json()

    response = client.post(
        f"/api/read-watermark/{response.get_json()['id']}", headers=user.headers,
        json={"method": "toy-eof", "key": KEY},
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["secret"]


def test_links_do_not_cross_documents(link_app):
    client = link_app.client
    first, second = link_app.users

    # Check 2 different documents and 2 different links.
    assert first.document_id != second.document_id
    assert first.version["link"] != second.version["link"]

    # Use each link for downloading the document.
    downloads = []
    for user in link_app.users:
        response = client.get(f"/api/get-version/{user.version['link']}")
        assert response.status_code == 200
        downloads.append(response.data)

    assert downloads[0] != downloads[1]

    # Each link carries the watermark issued for its own document only.
    for user, pdf in zip(link_app.users, downloads, strict=True):
        other = second if user is first else first

        secret = read_downloaded_secret(client, user, pdf)
        assert secret == user.secret
        assert secret != other.secret
