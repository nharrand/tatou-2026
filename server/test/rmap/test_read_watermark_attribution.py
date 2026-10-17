"""Read-watermark adds leak attribution only for the RMAP service account."""

import io
import os
import secrets
from types import SimpleNamespace
from unittest.mock import Mock

import fitz
import numpy as np
import pytest
from itsdangerous import URLSafeTimedSerializer
from PIL import Image
from rmap.keygen import generate_keypair
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import StaticPool

from watermarking_method import SecretNotFoundError
from watermarking_utils import apply_watermark

pytestmark = pytest.mark.usefixtures("toy_eof_method")

METHOD = "toy-eof"
KEY = "test-watermark-key"
SENSITIVE_CANARY = "synthetic-scoring-key-do-not-disclose"


def _seed_scoring_database(engine, storage):
    """Create temporary attribution tables for SQLite or case-sensitive MariaDB."""
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TEMPORARY TABLE Documents (
                id INTEGER PRIMARY KEY, name TEXT, path TEXT, ownerid INTEGER
            )
        """))
        conn.execute(text("""
            CREATE TEMPORARY TABLE Versions (
                id INTEGER PRIMARY KEY, documentid INTEGER,
                intended_for TEXT, link TEXT, secret TEXT, method TEXT
            )
        """))
        for doc_id, name in ((1, "source.pdf"), (2, "leaked.pdf")):
            conn.execute(text("""
                INSERT INTO Documents (id, name, path, ownerid)
                VALUES (:id, :name, :path, 1)
            """), {"id": doc_id, "name": name, "path": str(storage / name)})
        conn.execute(text("""
            INSERT INTO Versions (id, documentid, intended_for, link, secret, method) VALUES
            (1, 1, 'first', 'first-link', 'first-secret', 'test-scoring'),
            (2, 1, 'winner', 'winner-link', 'winner-secret', 'test-scoring')
        """))


@pytest.fixture
def scoring_app(tmp_path, monkeypatch):
    """Exercise server selection without depending on image robustness or PGP."""
    import server

    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    for name, value in {
        "RMAP_SERVER_PUBLIC_KEY_PATH": "synthetic-public",
        "RMAP_SERVER_PRIVATE_KEY_PATH": "synthetic-private",
        "RMAP_CLIENT_KEYS_DIR": "synthetic-clients",
        "RMAP_DOCUMENT_ID": "1", "RMAP_WATERMARK_METHOD": "test-scoring",
        "RMAP_WATERMARK_KEY": SENSITIVE_CANARY,
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("RMAP_SERVER_KEY_PASSPHRASE", "RMAP_SERVER_KEY_PASSPHRASE_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(server, "RMAPServer", Mock())
    method = SimpleNamespace(
        name="test-scoring", ATTRIBUTION_THRESHOLD=6.0,
        read_secret=Mock(side_effect=SecretNotFoundError(SENSITIVE_CANARY)),
        score_recipients=Mock(return_value={"first-secret": 1.0, "winner-secret": 7.0}),
    )
    monkeypatch.setitem(server.WMUtils.METHODS, method.name, method)
    app = server.create_app()
    storage = app.config["STORAGE_DIR"]
    _pdf(storage / "source.pdf")
    _pdf(storage / "leaked.pdf")
    engine = create_engine("sqlite://", poolclass=StaticPool)
    _seed_scoring_database(engine, storage)
    app.config.update(TESTING=True, _ENGINE=engine)

    def read():
        return app.test_client().post(
            "/api/read-watermark/2", headers=_auth_headers(app)(1),
            json={"method": method.name, "key": SENSITIVE_CANARY},
        )

    try:
        yield SimpleNamespace(app=app, engine=engine, storage=storage, method=method, read=read)
    finally:
        engine.dispose()


@pytest.mark.parametrize("winner", ["first", "winner"])
def test_fingerprint_selection_uses_highest_score(scoring_app, winner):
    scoring_app.method.score_recipients.return_value = {
        "first-secret": 7.0 if winner == "first" else 1.0,
        "winner-secret": 7.0 if winner == "winner" else 1.0,
    }

    response = scoring_app.read()

    assert response.status_code == 201
    assert response.get_json()["secret"] is None
    assert response.get_json()["attribution"] == {"intended_for": winner, "link": f"{winner}-link"}


@pytest.mark.parametrize("score,status", [(5.99, 400), (6.0, 201), (6.01, 201)])
def test_fingerprint_selection_respects_threshold(scoring_app, score, status):
    scoring_app.method.score_recipients.return_value = {"first-secret": 1.0, "winner-secret": score}

    response = scoring_app.read()

    assert response.status_code == status
    assert response.get_json().get("attribution") == (
        {"intended_for": "winner", "link": "winner-link"} if status == 201 else None
    )


@pytest.mark.parametrize("scores", [{}, {"first-secret": 1.0}])
def test_fingerprint_does_not_attribute_missing_or_low_scores(scoring_app, scores):
    scoring_app.method.score_recipients.return_value = scores

    response = scoring_app.read()

    assert response.status_code == 400
    assert response.get_json() == {"error": "could not read watermark"}


def test_fingerprint_without_issued_versions_skips_scoring(scoring_app):
    with scoring_app.engine.begin() as conn:
        conn.execute(text("DELETE FROM Versions"))

    response = scoring_app.read()

    assert response.status_code == 400
    assert response.get_json() == {"error": "could not read watermark"}
    scoring_app.method.score_recipients.assert_not_called()


def test_fingerprint_scoring_error_is_sanitized(scoring_app, caplog):
    scoring_app.method.score_recipients.side_effect = RuntimeError(SENSITIVE_CANARY)

    response = scoring_app.read()

    assert response.status_code == 400
    assert response.get_json() == {"error": "could not read watermark"}
    assert SENSITIVE_CANARY not in response.get_data(as_text=True)
    assert SENSITIVE_CANARY not in caplog.text
    assert str(scoring_app.storage) not in caplog.text
    assert "Traceback" not in caplog.text


def test_fingerprint_query_with_case_sensitive_mariadb(scoring_app, monkeypatch):
    connection_url = os.environ.get("TATOU_TEST_MARIADB_URL")
    if not connection_url:
        pytest.skip("Set TATOU_TEST_MARIADB_URL to a dedicated tatou_test_* MariaDB database")
    url = make_url(connection_url)
    assert url.get_backend_name() in ("mysql", "mariadb")
    assert url.database and url.database.startswith("tatou_test_"), "Use a dedicated test database"
    engine = create_engine(url, poolclass=StaticPool, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT @@lower_case_table_names")).scalar_one() == 0, (
                "This check requires case-sensitive MariaDB table names"
            )
        _seed_scoring_database(engine, scoring_app.storage)
        monkeypatch.setitem(scoring_app.app.config, "_ENGINE", engine)

        response = scoring_app.read()

        assert response.status_code == 201
        assert response.get_json()["attribution"] == {"intended_for": "winner", "link": "winner-link"}
    finally:
        engine.dispose()


def _pdf(path, secret=None):
    document = fitz.open()
    document.new_page().insert_text((72, 72), "attribution test document")
    data = document.tobytes()
    document.close()
    if secret is not None:
        data = apply_watermark(METHOD, data, secret, KEY)
    path.write_bytes(data)


def _configure_rmap(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    client_dir = key_dir / "clients"
    client_dir.mkdir(parents=True)
    server_key = generate_keypair("Server", "server@example.test")
    (key_dir / "server_private.asc").write_text(str(server_key))
    (key_dir / "server_public.asc").write_text(str(server_key.pubkey))
    group_key = generate_keypair("Group_07", "group@example.test")
    (client_dir / "Group_07.asc").write_text(str(group_key.pubkey))

    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("RMAP_SERVER_PUBLIC_KEY_PATH", str(key_dir / "server_public.asc"))
    monkeypatch.setenv("RMAP_SERVER_PRIVATE_KEY_PATH", str(key_dir / "server_private.asc"))
    monkeypatch.setenv("RMAP_CLIENT_KEYS_DIR", str(client_dir))
    monkeypatch.delenv("RMAP_SERVER_KEY_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("RMAP_SERVER_KEY_PASSPHRASE", raising=False)
    monkeypatch.setenv("RMAP_DOCUMENT_ID", "1")
    monkeypatch.setenv("RMAP_WATERMARK_METHOD", "group13-watermark")
    monkeypatch.setenv("RMAP_WATERMARK_KEY", KEY)
    from server import create_app

    return create_app()


def _create_schema(conn):
    conn.execute(text("""
        CREATE TABLE Documents (
            id INTEGER PRIMARY KEY, name TEXT, path TEXT, ownerid INTEGER
        )
    """))
    conn.execute(text("""
        CREATE TABLE Versions (
            id INTEGER PRIMARY KEY, documentid INTEGER, link TEXT UNIQUE,
            intended_for TEXT, secret TEXT, method TEXT, position TEXT, path TEXT
        )
    """))


def _auth_headers(app):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def headers(uid):
        token = serializer.dumps({"uid": uid, "login": f"u{uid}", "email": None})
        return {"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"}

    return headers


@pytest.fixture
def attribution_app(tmp_path, monkeypatch):
    app = _configure_rmap(tmp_path, monkeypatch)
    storage = app.config["STORAGE_DIR"]
    leaked_secret = "Group_07:" + "a" * 32
    _pdf(storage / "source.pdf")
    _pdf(storage / "leaked.pdf", leaked_secret)
    _pdf(storage / "own.pdf", "my own secret")

    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        _create_schema(conn)
        # User 1 = RMAP service account (owns RMAP_DOCUMENT_ID); user 2 = normal user.
        conn.execute(text("""
            INSERT INTO Documents (id, name, path, ownerid) VALUES
            (1, 'source.pdf', :src, 1),
            (2, 'leaked.pdf', :leaked, 1),
            (3, 'own.pdf', :own, 2)
        """), {
            "src": str(storage / "source.pdf"),
            "leaked": str(storage / "leaked.pdf"),
            "own": str(storage / "own.pdf"),
        })
        conn.execute(text("""
            INSERT INTO Versions (documentid, link, intended_for, secret, method)
            VALUES (1, :link, 'Group_07', :secret, :method)
        """), {"link": "a" * 32, "secret": leaked_secret, "method": METHOD})
    app.config.update(TESTING=True, _ENGINE=engine)

    try:
        yield app.test_client(), _auth_headers(app)
    finally:
        engine.dispose()


def test_service_account_gets_attribution_for_rmap_copy(attribution_app):
    client, headers = attribution_app
    response = client.post(
        "/api/read-watermark/2", headers=headers(1),
        json={"method": METHOD, "key": KEY},
    )
    assert response.status_code == 201
    body = response.get_json()
    assert body["attribution"] == {"intended_for": "Group_07", "link": "a" * 32}


def test_normal_user_gets_no_attribution_field(attribution_app):
    client, headers = attribution_app
    response = client.post(
        "/api/read-watermark/3", headers=headers(2),
        json={"method": METHOD, "key": KEY},
    )
    assert response.status_code == 201
    assert response.get_json() == {
        "documentid": 3, "secret": "my own secret",
        "method": METHOD, "position": None,
    }

DAVIDE_METHOD = "davide-watermark"


def _image_pdf(seed):
    """Create a one-page PDF containing a textured JPEG."""
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:512, 0:512]
    base = 96 + 60 * np.sin(x / 31.0) * np.cos(y / 19.0)
    pixels = np.clip(base[..., None] + rng.normal(0, 18, (512, 512, 3)), 0, 255)
    buf = io.BytesIO()
    Image.fromarray(pixels.astype(np.uint8), "RGB").save(buf, "JPEG", quality=90)
    document = fitz.open()
    document.new_page().insert_image(fitz.Rect(72, 72, 512, 512), stream=buf.getvalue())
    data = document.tobytes()
    document.close()
    return data


def _photo(pdf):
    document = fitz.open(stream=pdf, filetype="pdf")
    image = Image.open(io.BytesIO(document.extract_image(document[0].get_images()[0][0])["image"]))
    document.close()
    return image.convert("RGB")


def _with_photo(pdf, image):
    """Replace the photo, as a leaker editing the file would."""
    document = fitz.open(stream=pdf, filetype="pdf")
    xref = document[0].get_images()[0][0]
    buf = io.BytesIO()
    image.save(buf, "JPEG", quality=85)
    document[0].insert_image(document[0].rect, stream=buf.getvalue())
    document[0].delete_image(xref)
    data = document.tobytes(garbage=3)
    document.close()
    return data


def _cropped(pdf):
    """Crop the photo by a few pixels: the blind layer no longer decodes."""
    image = _photo(pdf)
    return _with_photo(pdf, image.crop((3, 5, image.width - 30, image.height)))


def _averaged(a, b):
    """Average two recipient copies to simulate collusion."""
    mix = (np.asarray(_photo(a), dtype=np.float64) + np.asarray(_photo(b), dtype=np.float64)) / 2
    return _with_photo(a, Image.fromarray(mix.round().astype(np.uint8)))

# Four copies of the same source: two for Group_07, one each for Group_12 and Group_21.
ISSUED = [
    ("Group_07", "a" * 32),
    ("Group_07", "b" * 32),
    ("Group_12", "c" * 32),
    ("Group_21", "d" * 32),
]


@pytest.fixture
def fingerprint_app(tmp_path, monkeypatch):
    app = _configure_rmap(tmp_path, monkeypatch)
    storage = app.config["STORAGE_DIR"]
    source = _image_pdf(7)
    copies = {
        link: apply_watermark(DAVIDE_METHOD, source, f"{group}:{link}", KEY)
        for group, link in ISSUED
    }
    files = {
        "source.pdf": source,
        "cropped.pdf": _cropped(copies["a" * 32]),
        "unrelated.pdf": _image_pdf(99),
        "averaged.pdf": _averaged(copies["a" * 32], copies["c" * 32]),
        "intact.pdf": copies["b" * 32],
    }
    for name, data in files.items():
        (storage / name).write_bytes(data)

    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        _create_schema(conn)
        # User 1 = RMAP service account (owns documents 1-7); user 2 = normal user.
        documents = [
            (1, "source.pdf", 1), (2, "cropped.pdf", 1), (3, "unrelated.pdf", 1),
            (4, "cropped.pdf", 2), (5, "source.pdf", 1), (6, "averaged.pdf", 1),
            (7, "intact.pdf", 1),
        ]
        for doc_id, name, owner in documents:
            conn.execute(text("""
                INSERT INTO Documents (id, name, path, ownerid)
                VALUES (:id, :name, :path, :owner)
            """), {"id": doc_id, "name": name, "path": str(storage / name), "owner": owner})
        for group, link in ISSUED:
            conn.execute(text("""
                INSERT INTO Versions (documentid, link, intended_for, secret, method)
                VALUES (1, :link, :group, :secret, :method)
            """), {"link": link, "group": group, "secret": f"{group}:{link}", "method": DAVIDE_METHOD})
    app.config.update(TESTING=True, _ENGINE=engine)

    def read(doc_id, uid=1, key=KEY, method=DAVIDE_METHOD):
        return app.test_client().post(
            f"/api/read-watermark/{doc_id}", headers=_auth_headers(app)(uid),
            json={"method": method, "key": key},
        )

    try:
        yield app, read
    finally:
        engine.dispose()


def test_damaged_leak_is_attributed_to_the_exact_copy(fingerprint_app):
    _, read = fingerprint_app
    response = read(2)
    assert response.status_code == 201
    body = response.get_json()
    # The blind layer did not survive: the result comes from the fingerprint.
    assert body["secret"] is None
    # Group_07 received two copies; the leak is the first one, not the second.
    assert body["attribution"] == {"intended_for": "Group_07", "link": "a" * 32}


def test_intact_copy_is_attributed_by_its_secret(fingerprint_app):
    _, read = fingerprint_app
    response = read(7)
    assert response.status_code == 201
    body = response.get_json()
    assert body["secret"] == "Group_07:" + "b" * 32
    assert body["attribution"] == {"intended_for": "Group_07", "link": "b" * 32}


def test_averaged_copies_are_attributed_to_a_colluder_never_an_innocent(fingerprint_app):
    _, read = fingerprint_app
    response = read(6)
    assert response.status_code == 201
    assert response.get_json()["attribution"] in (
        {"intended_for": "Group_07", "link": "a" * 32},
        {"intended_for": "Group_12", "link": "c" * 32},
    )


@pytest.mark.parametrize("doc_id", [3, 5], ids=["unrelated-pdf", "unmarked-original"])
def test_nobody_is_accused_without_a_fingerprint(fingerprint_app, doc_id):
    _, read = fingerprint_app
    response = read(doc_id)
    assert response.status_code == 400
    assert response.get_json() == {"error": "could not read watermark"}


def test_fingerprint_needs_the_watermark_key(fingerprint_app):
    _, read = fingerprint_app
    assert read(2, key="guessed-key").status_code == 400


def test_normal_user_gets_no_fingerprint_oracle(fingerprint_app):
    _, read = fingerprint_app
    # Same leaked file and the real key, but not the service account.
    response = read(4, uid=2)
    assert response.status_code == 400
    assert "attribution" not in response.get_json()


def test_normal_user_cannot_read_the_service_documents(fingerprint_app):
    _, read = fingerprint_app
    for doc_id in (1, 2, 7):
        assert read(doc_id, uid=2).status_code == 404


def test_read_watermark_requires_authentication(fingerprint_app):
    app, _ = fingerprint_app
    response = app.test_client().post(
        "/api/read-watermark/2", headers={"X-CSRF-Protection": "1"},
        json={"method": DAVIDE_METHOD, "key": KEY},
    )
    assert response.status_code == 401
