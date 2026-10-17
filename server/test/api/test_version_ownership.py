"""Version listings must distinguish accounts that share a login name."""

import io
import secrets
from types import SimpleNamespace

import fitz
import pytest
from sqlalchemy import create_engine, event, text

pytestmark = pytest.mark.usefixtures("toy_eof_method")


def make_pdf():
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Tatou ownership fixture")
    data = document.tobytes()
    document.close()
    return data

PDF = make_pdf()
DOCUMENT_ROUTES = [
    "/api/list-versions/{id}",
    "/api/list-versions?id={id}",
    "/api/list-versions?documentid={id}",
]


@pytest.fixture
def version_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    from server import create_app

    app = create_app()
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
        # Match production: email is unique, but login is not.
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
            email = f"owner-{index}@example.test"
            credentials = {"email": email, "password": "test-only-password"}
            response = client.post(
                "/api/create-user", headers=csrf,
                json={**credentials, "login": "shared-login"},
            )
            assert response.status_code == 201, response.get_json()
            uid = response.get_json()["id"]
            response = client.post("/api/login", headers=csrf, json=credentials)
            assert response.status_code == 200, response.get_json()
            headers = {
                **csrf,
                "Authorization": f"Bearer {response.get_json()['token']}",
            }
            response = client.post(
                "/api/upload-document", headers=headers,
                data={"file": (io.BytesIO(PDF), f"owner-{index}.pdf")},
            )
            assert response.status_code == 201, response.get_json()
            document_id = response.get_json()["id"]
            secret = f"private-secret-{index}"
            response = client.post(
                f"/api/create-watermark/{document_id}", headers=headers,
                json={"method": "toy-eof", "key": "test-only-key",
                      "secret": secret, "intended_for": f"recipient-{index}"},
            )
            assert response.status_code == 201, response.get_json()
            users.append(SimpleNamespace(
                uid=uid, headers=headers, document_id=document_id,
                secret=secret, version=response.get_json(),
            ))
        assert users[0].uid != users[1].uid
        yield SimpleNamespace(client=client, users=users)
    finally:
        engine.dispose()


@pytest.mark.parametrize("route", DOCUMENT_ROUTES)
def test_document_versions_are_private_with_duplicate_logins(version_app, route):
    for index, user in enumerate(version_app.users):
        other = version_app.users[1 - index]
        response = version_app.client.get(
            route.format(id=user.document_id), headers=user.headers,
        )
        assert response.status_code == 200
        versions = response.get_json()["versions"]
        assert len(versions) == 1
        assert versions[0]["id"] == user.version["id"]
        assert versions[0]["link"] == user.version["link"]
        assert versions[0]["secret"] == user.secret
        assert versions[0]["documentid"] == user.document_id

        response = version_app.client.get(
            route.format(id=other.document_id), headers=user.headers,
        )
        assert response.status_code == 200
        assert response.get_json() == {"versions": []}


def test_all_versions_are_private_with_duplicate_logins(version_app):
    for index, user in enumerate(version_app.users):
        other = version_app.users[1 - index]
        # Request parameters cannot override the authenticated owner's identity.
        response = version_app.client.get(
            f"/api/list-all-versions?uid={other.uid}&ownerid={other.uid}",
            headers=user.headers,
        )
        assert response.status_code == 200
        versions = response.get_json()["versions"]
        assert len(versions) == 1
        assert versions[0]["id"] == user.version["id"]
        assert versions[0]["documentid"] == user.document_id
        assert versions[0]["link"] == user.version["link"]


@pytest.mark.parametrize("route", [*DOCUMENT_ROUTES, "/api/list-all-versions"])
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid"}])
def test_version_listings_require_authentication(version_app, route, headers):
    response = version_app.client.get(
        route.format(id=version_app.users[0].document_id), headers=headers,
    )
    assert response.status_code == 401
    assert "versions" not in response.get_json()
