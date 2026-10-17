"""Startup configuration and signing-key regression coverage."""

import secrets
from unittest.mock import MagicMock, Mock

import pytest
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


@pytest.fixture
def startup_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    for name in (
        "RMAP_SERVER_PUBLIC_KEY_PATH", "RMAP_SERVER_PRIVATE_KEY_PATH", "RMAP_CLIENT_KEYS_DIR",
        "RMAP_SERVER_KEY_PASSPHRASE", "RMAP_SERVER_KEY_PASSPHRASE_FILE",
        "MAX_UPLOAD_SIZE_BYTES", "TOKEN_TTL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    from server import create_app

    return create_app


@pytest.mark.parametrize("storage_setting", ["default", "nested"])
def test_startup_creates_storage_with_missing_parents(startup_env, monkeypatch, tmp_path, storage_setting):
    monkeypatch.chdir(tmp_path)
    if storage_setting == "default":
        monkeypatch.delenv("STORAGE_DIR")
        expected = tmp_path / "storage"
    else:
        expected = tmp_path / "missing" / "parents" / "storage"
        monkeypatch.setenv("STORAGE_DIR", str(expected))

    app = startup_env()

    assert app.config["STORAGE_DIR"] == expected.resolve()
    assert expected.is_dir()


@pytest.mark.parametrize("value", ["0", "-1", "not-an-integer"])
def test_startup_rejects_invalid_upload_limits(startup_env, monkeypatch, value):
    monkeypatch.setenv("MAX_UPLOAD_SIZE_BYTES", value)

    with pytest.raises((RuntimeError, ValueError)):
        startup_env()


def test_startup_uses_configured_limits(startup_env, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_SIZE_BYTES", "1")
    monkeypatch.setenv("TOKEN_TTL_SECONDS", "123")

    app = startup_env()

    assert app.config["MAX_UPLOAD_SIZE_BYTES"] == 1
    assert app.config["TOKEN_TTL_SECONDS"] == 123


@pytest.mark.parametrize("configured", [False, True], ids=["defaults", "overrides"])
def test_database_configuration_is_used_and_engine_is_reused(startup_env, monkeypatch, caplog, configured):
    import server

    values = {
        "DB_USER": "review-user", "DB_PASSWORD": "synthetic-db-password",
        "DB_HOST": "database.example.test", "DB_PORT": "3307", "DB_NAME": "review-database",
    }
    for name, value in values.items():
        if configured:
            monkeypatch.setenv(name, value)
        else:
            monkeypatch.delenv(name, raising=False)
    def build_engine(*args, **kwargs):
        engine = create_engine(*args, **kwargs)
        monkeypatch.setattr(engine, "connect", MagicMock())
        return engine

    factory = Mock(side_effect=build_engine)
    monkeypatch.setattr(server, "create_engine", factory)
    app = startup_env()

    try:
        for _ in range(2):
            response = app.test_client().get("/healthz")
            assert response.status_code == 200
            assert response.get_json()["db_connected"] is True
    finally:
        if engine := app.config.get("_ENGINE"):
            engine.dispose()

    factory.assert_called_once()
    url = make_url(factory.call_args.args[0])
    expected = (
        ("review-user", "synthetic-db-password", "database.example.test", 3307, "review-database")
        if configured else ("tatou", "tatou", "db", 3306, "tatou")
    )
    assert (url.username, url.password, url.host, url.port, url.database) == expected
    assert values["DB_PASSWORD"] not in caplog.text


@pytest.mark.parametrize(
    "value", [None, "", "   ", "dev-secret-change-me", " dev-secret-change-me "]
)
def test_startup_rejects_missing_or_public_signing_key(monkeypatch, tmp_path, value):
    from server import create_app

    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    if value is None:
        monkeypatch.delenv("SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("SECRET_KEY", value)

    with pytest.raises(RuntimeError, match="Set SECRET_KEY"):
        create_app()


@pytest.fixture
def signing_app(monkeypatch, tmp_path):
    from server import create_app

    key = secrets.token_hex(32)
    monkeypatch.setenv("SECRET_KEY", key)
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    app = create_app()
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY, name TEXT, creation TEXT,
                sha256 BLOB, size INTEGER, ownerid INTEGER
            )
        """))
    app.config.update(TESTING=True, _ENGINE=engine)
    yield app, key
    engine.dispose()


@pytest.mark.parametrize("signing_key", ["dev-secret-change-me", "another-key"])
def test_foreign_signing_keys_cannot_authorize_requests(signing_app, signing_key):
    app, _ = signing_app
    token = URLSafeTimedSerializer(signing_key, salt="tatou-auth").dumps(
        {"uid": 1, "login": "owner"}
    )
    response = app.test_client().get(
        "/api/list-documents", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "Invalid token"}


def test_configured_signing_key_authorizes_requests(signing_app):
    app, key = signing_app
    token = URLSafeTimedSerializer(key, salt="tatou-auth").dumps(
        {"uid": 1, "login": "owner"}
    )
    response = app.test_client().get(
        "/api/list-documents", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.get_json() == {"documents": []}
