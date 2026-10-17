"""Verify RMAP configuration and in-process HTTP handshake behavior."""

import secrets
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import fitz
import pytest
from rmap import RMAPClient
from rmap.keygen import generate_keypair
from sqlalchemy import create_engine, text

from watermarking_method import WatermarkingError
from watermarking_utils import read_watermark


@pytest.fixture
def rmap_startup(tmp_path, monkeypatch):
    """Create an isolated configuration fixture without performing a PGP handshake."""
    from server import create_app

    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    for name, value in {
        "RMAP_SERVER_PUBLIC_KEY_PATH": str(tmp_path / "public.asc"),
        "RMAP_SERVER_PRIVATE_KEY_PATH": str(tmp_path / "private.asc"),
        "RMAP_CLIENT_KEYS_DIR": str(tmp_path / "clients"),
        "RMAP_DOCUMENT_ID": "1",
        "RMAP_WATERMARK_METHOD": "group13-watermark",
        "RMAP_WATERMARK_KEY": "synthetic-watermark-key",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("RMAP_SERVER_KEY_PASSPHRASE", "RMAP_SERVER_KEY_PASSPHRASE_FILE", "RMAP_WATERMARK_POSITION"):
        monkeypatch.delenv(name, raising=False)
    constructor = Mock()
    monkeypatch.setattr("server.RMAPServer", constructor)
    return SimpleNamespace(create_app=create_app, constructor=constructor)


@pytest.mark.parametrize("missing", [
    "RMAP_SERVER_PUBLIC_KEY_PATH", "RMAP_SERVER_PRIVATE_KEY_PATH", "RMAP_CLIENT_KEYS_DIR",
])
def test_rmap_rejects_partial_key_configuration(rmap_startup, monkeypatch, missing):
    monkeypatch.delenv(missing)

    with pytest.raises(RuntimeError):
        rmap_startup.create_app()

    rmap_startup.constructor.assert_not_called()


@pytest.mark.parametrize("document_id", ["", "0", "-1", "not-an-integer"])
def test_rmap_rejects_invalid_source_document(rmap_startup, monkeypatch, document_id):
    monkeypatch.setenv("RMAP_DOCUMENT_ID", document_id)

    with pytest.raises(RuntimeError):
        rmap_startup.create_app()

    rmap_startup.constructor.assert_not_called()


@pytest.mark.parametrize("passphrase", [" caf\u00e9-X \t", "\ncaf\u00e9X", "caf\u00e9X"])
def test_rmap_reads_utf8_passphrase_preserving_significant_characters(
    rmap_startup, monkeypatch, tmp_path, caplog, passphrase,
):
    passphrase_file = tmp_path / "passphrase"
    passphrase_file.write_bytes((passphrase + "\r\n").encode("utf-8"))
    passphrase_file.chmod(0o600)
    monkeypatch.setenv("RMAP_SERVER_KEY_PASSPHRASE_FILE", str(passphrase_file))
    real_read_text = Path.read_text

    def ascii_default_read(path, *args, **kwargs):
        if path == passphrase_file and kwargs.get("encoding") is None:
            kwargs["encoding"] = "ascii"
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", ascii_default_read)

    app = rmap_startup.create_app()

    rmap_startup.constructor.assert_called_once()
    assert rmap_startup.constructor.call_args.kwargs["passphrase"] == passphrase
    assert app.config["RMAP_SERVER"] is rmap_startup.constructor.return_value
    assert passphrase not in caplog.text


@pytest.mark.parametrize("key", [None, ""], ids=["missing", "empty"])
def test_rmap_requires_a_watermark_key(rmap_startup, monkeypatch, key):
    if key is None:
        monkeypatch.delenv("RMAP_WATERMARK_KEY")
    else:
        monkeypatch.setenv("RMAP_WATERMARK_KEY", key)

    with pytest.raises(RuntimeError):
        rmap_startup.create_app()

    rmap_startup.constructor.assert_not_called()


@pytest.mark.parametrize("passphrase", [" caf\u00e9-X \t", "\ncaf\u00e9X"])
def test_rmap_uses_environment_passphrase(rmap_startup, monkeypatch, caplog, passphrase):
    monkeypatch.setenv("RMAP_SERVER_KEY_PASSPHRASE", passphrase)

    app = rmap_startup.create_app()

    assert app.config["RMAP_SERVER_KEY_PASSPHRASE"] == passphrase
    assert rmap_startup.constructor.call_args.kwargs["passphrase"] == passphrase
    assert passphrase not in caplog.text


@pytest.mark.parametrize("value,expected", [
    (None, "group13-watermark"), ("  ", "group13-watermark"), (" toy-eof ", "toy-eof"),
])
def test_rmap_uses_configured_or_default_method(rmap_startup, monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("RMAP_WATERMARK_METHOD")
    else:
        monkeypatch.setenv("RMAP_WATERMARK_METHOD", value)

    app = rmap_startup.create_app()

    assert app.config["RMAP_WATERMARK_METHOD"] == expected


@pytest.mark.parametrize("value,expected", [(None, None), ("", None), (" top-right ", "top-right")])
def test_rmap_uses_configured_or_default_position(rmap_startup, monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("RMAP_WATERMARK_POSITION", raising=False)
    else:
        monkeypatch.setenv("RMAP_WATERMARK_POSITION", value)

    app = rmap_startup.create_app()

    assert app.config["RMAP_WATERMARK_POSITION"] == expected


def test_rmap_rejects_conflicting_passphrase_sources(rmap_startup, monkeypatch, tmp_path, caplog):
    environment_secret = "synthetic-environment-passphrase"
    file_secret = "synthetic-file-passphrase"
    passphrase_file = tmp_path / "passphrase"
    passphrase_file.write_text(file_secret, encoding="utf-8")
    passphrase_file.chmod(0o600)
    monkeypatch.setenv("RMAP_SERVER_KEY_PASSPHRASE", environment_secret)
    monkeypatch.setenv("RMAP_SERVER_KEY_PASSPHRASE_FILE", str(passphrase_file))

    with pytest.raises(RuntimeError) as error:
        rmap_startup.create_app()

    rmap_startup.constructor.assert_not_called()
    for secret in (environment_secret, file_secret):
        assert secret not in str(error.value)
        assert secret not in caplog.text


def _write_keypair(directory, stem, name, passphrase=None):
    key = generate_keypair(name, f"{stem}@example.test", passphrase=passphrase)
    private = directory / f"{stem}_private.asc"
    public = directory / f"{stem}_public.asc"
    private.write_text(str(key))
    public.write_text(str(key.pubkey))
    return private, public


def _pdf(path):
    document = fitz.open()
    page = document.new_page()
    sentence = "RMAP links identify recipients through text in this document."
    for row in range(40):
        page.insert_text((70, 80 + row * 16), sentence, fontsize=10)
    document.save(path)
    document.close()


def test_rmap_handshake_returns_a_link_to_the_identity_version(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    client_dir = key_dir / "clients"
    client_dir.mkdir(parents=True)
    server_passphrase = "test-server-passphrase"
    server_private, server_public = _write_keypair(
        key_dir, "server", "Server", passphrase=server_passphrase,
    )
    client_private, client_public = _write_keypair(key_dir, "group", "Group_01")
    (client_dir / "Group_01.asc").write_text(client_public.read_text())
    passphrase_file = key_dir / "server_passphrase"
    passphrase_file.write_text(server_passphrase)
    passphrase_file.chmod(0o600)

    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("RMAP_SERVER_PUBLIC_KEY_PATH", str(server_public))
    monkeypatch.setenv("RMAP_SERVER_PRIVATE_KEY_PATH", str(server_private))
    monkeypatch.setenv("RMAP_CLIENT_KEYS_DIR", str(client_dir))
    monkeypatch.setenv("RMAP_SERVER_KEY_PASSPHRASE_FILE", str(passphrase_file))
    monkeypatch.setenv("RMAP_DOCUMENT_ID", "1")
    monkeypatch.setenv("RMAP_WATERMARK_METHOD", "group13-watermark")
    monkeypatch.setenv("RMAP_WATERMARK_KEY", "test-watermark-key")
    monkeypatch.setenv("RMAP_WATERMARK_POSITION", "top-right")
    from server import create_app

    app = create_app()
    version_path = app.config["STORAGE_DIR"] / "version.pdf"
    _pdf(version_path)
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY, name TEXT, path TEXT
            )
        """))
        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY, documentid INTEGER, link TEXT UNIQUE,
                intended_for TEXT, secret TEXT, method TEXT, position TEXT, path TEXT
            )
        """))
        conn.execute(
            text("""
                INSERT INTO Documents (id, name, path)
                VALUES (1, 'confidential.pdf', :path)
            """),
            {"path": str(version_path)},
        )
    app.config.update(TESTING=True, _ENGINE=engine)

    import server

    watermark = Mock(wraps=server.WMUtils.apply_watermark)
    monkeypatch.setattr("server.WMUtils.apply_watermark", watermark)
    try:
        http = app.test_client()
        links = []
        for _ in range(2):
            client = RMAPClient("Group_01", client_private, server_public)
            response = http.post("/api/rmap-initiate", json=client.build_msg1())
            assert response.status_code == 200
            client.process_resp1(response.get_json())

            response = http.post("/api/rmap-get-link", json=client.build_msg2())
            assert response.status_code == 200
            link = client.process_resp2(response.get_json())
            assert link == client.expected_link
            links.append(link)

            response = http.get(f"/api/get-version/{link}")
            assert response.status_code == 200
            assert response.mimetype == "application/pdf"

            with engine.connect() as conn:
                version = conn.execute(
                    text("SELECT * FROM Versions WHERE link = :link"), {"link": link},
                ).one()
            assert version.intended_for == "Group_01"
            assert version.secret == link
            assert version.method == "group13-watermark"
            assert version.position == "top-right"
            assert watermark.call_args.kwargs["position"] == "top-right"
            assert read_watermark("group13-watermark", version.path, "test-watermark-key") == version.secret
            assert read_watermark("khaled-text-spacing-watermark", version.path, "test-watermark-key") == version.secret

        assert links[0] != links[1]
        with engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM Versions")).scalar_one() == 2

        replay = http.post("/api/rmap-get-link", json=client.build_msg2())
        assert replay.status_code == 409

        unknown = RMAPClient("Unregistered", client_private, server_public)
        assert http.post("/api/rmap-initiate", json=unknown.build_msg1()).status_code == 400

        for malformed in ({"payload": "not base64 !"}, {"payload": 42}, {}, ["payload"]):
            for route in ("/api/rmap-initiate", "/api/rmap-get-link"):
                response = http.post(route, json=malformed)
                assert response.status_code == 400
                assert "payload" not in response.get_json()

        # A failing watermark (generic error, or the method refusing the source) must never
        # produce a link, a version row or a stored file. The error body differs (handled vs.
        # the app's generic 500 handler); the invariant does not.
        for failure in (RuntimeError("test failure"), WatermarkingError("no usable image")):
            failing_client = RMAPClient("Group_01", client_private, server_public)
            response = http.post("/api/rmap-initiate", json=failing_client.build_msg1())
            assert response.status_code == 200
            failing_client.process_resp1(response.get_json())
            monkeypatch.setattr(
                "server.WMUtils.apply_watermark",
                lambda failure=failure, **_kwargs: (_ for _ in ()).throw(failure),
            )
            failed = http.post("/api/rmap-get-link", json=failing_client.build_msg2())
            assert failed.status_code == 500
            assert "payload" not in failed.get_json()
            with engine.connect() as conn:
                assert conn.execute(text("SELECT COUNT(*) FROM Versions")).scalar_one() == 2
            assert len(list((app.config["STORAGE_DIR"] / "rmap").glob("*.pdf"))) == 2
    finally:
        engine.dispose()


def test_rmap_is_explicitly_unavailable_without_key_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.delenv("RMAP_SERVER_PUBLIC_KEY_PATH", raising=False)
    monkeypatch.delenv("RMAP_SERVER_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.delenv("RMAP_CLIENT_KEYS_DIR", raising=False)
    monkeypatch.delenv("RMAP_SERVER_KEY_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("RMAP_DOCUMENT_ID", raising=False)
    monkeypatch.delenv("RMAP_WATERMARK_METHOD", raising=False)
    monkeypatch.delenv("RMAP_WATERMARK_KEY", raising=False)
    from server import create_app

    app = create_app()
    response = app.test_client().post("/api/rmap-initiate", json={})
    assert response.status_code == 503
    assert response.get_json() == {"error": "RMAP is not configured"}


def test_rmap_rejects_an_insecure_passphrase_file(tmp_path, monkeypatch):
    passphrase_file = tmp_path / "server_passphrase"
    passphrase_file.write_text("private-passphrase")
    passphrase_file.chmod(0o644)
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("RMAP_SERVER_PUBLIC_KEY_PATH", str(tmp_path / "server_public.asc"))
    monkeypatch.setenv("RMAP_SERVER_PRIVATE_KEY_PATH", str(tmp_path / "server_private.asc"))
    monkeypatch.setenv("RMAP_CLIENT_KEYS_DIR", str(tmp_path / "clients"))
    monkeypatch.setenv("RMAP_DOCUMENT_ID", "1")
    monkeypatch.setenv("RMAP_WATERMARK_METHOD", "group13-watermark")
    monkeypatch.setenv("RMAP_WATERMARK_KEY", "test-watermark-key")
    monkeypatch.setenv("RMAP_SERVER_KEY_PASSPHRASE_FILE", str(passphrase_file))
    from server import create_app

    with pytest.raises(RuntimeError, match="must not be group- or world-accessible"):
        create_app()
