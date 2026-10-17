"""Login throttling must bound guesses without extending a user's cooldown."""

import sqlite3
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash


@pytest.fixture
def login_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_KEY", "login-test-private-key")
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path / "storage"))
    from server import create_app

    app = create_app()
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE Users (
            id INTEGER PRIMARY KEY, email TEXT COLLATE NOCASE,
            login TEXT, hpassword TEXT
        )"""))
        conn.execute(text("INSERT INTO Users VALUES (1, :email, 'owner', :password)"), {
            "email": "owner@example.test",
            "password": generate_password_hash("correct-password"),
        })
    app.config.update(TESTING=True, _ENGINE=engine)
    env = SimpleNamespace(app=app, engine=engine, client=app.test_client())
    yield env
    engine.dispose()


def login(env, email="owner@example.test", password="wrong", ip="192.0.2.1", **headers):
    return env.client.post(
        "/api/login", json={"email": email, "password": password},
        headers={"X-CSRF-Protection": "1", **headers},
        environ_overrides={"REMOTE_ADDR": ip},
    )


def test_account_limit_survives_rotating_ips_and_email_case(login_env):
    for n in range(5):
        assert login(login_env, ip=f"192.0.2.{n+1}").status_code == 401
    response = login(login_env, email=" OWNER@EXAMPLE.TEST ", ip="198.51.100.1")
    assert response.status_code == 429
    assert 1 <= int(response.headers["Retry-After"]) <= 60
    assert response.json == {"error": "too many login attempts; try again shortly"}


def test_ip_limit_survives_rotating_accounts_and_forged_forwarding_headers(login_env):
    for n in range(5):
        assert login(login_env, email=f"unknown-{n}@example.test").status_code == 401
    response = login(login_env, email="another@example.test", **{
        "X-Forwarded-For": "203.0.113.100", "X-Real-IP": "203.0.113.100",
    })
    assert response.status_code == 429
    assert login(login_env, email="unrelated@example.test", ip="198.51.100.1").status_code == 401


def test_successful_logins_do_not_consume_failure_budget(login_env):
    for _ in range(7):
        assert login(login_env, password="correct-password").status_code == 200
    for _ in range(5):
        assert login(login_env).status_code == 401
    assert login(login_env, password="correct-password").status_code == 429


def test_success_does_not_erase_prior_failures(login_env):
    for _ in range(4):
        assert login(login_env).status_code == 401
    assert login(login_env, password="correct-password").status_code == 200
    assert login(login_env).status_code == 401
    assert login(login_env).status_code == 429


def test_unknown_account_is_also_limited(login_env):
    for n in range(5):
        assert login(login_env, email="missing@example.test", ip=f"192.0.2.{n+1}").status_code == 401
    assert login(login_env, email="MISSING@example.test", ip="198.51.100.1").status_code == 429


def test_cooldown_expires_and_blocked_retries_do_not_extend_it(login_env, monkeypatch):
    import login_rate_limit

    now = [1000.0]
    monkeypatch.setattr(login_rate_limit.time, "time", lambda: now[0])
    for _ in range(5):
        assert login(login_env).status_code == 401
    assert login(login_env).headers["Retry-After"] == "60"
    now[0] += 59
    assert login(login_env).headers["Retry-After"] == "1"
    now[0] += 1
    assert login(login_env, password="correct-password").status_code == 200


def test_recreated_app_shares_counters(login_env):
    from server import create_app

    for _ in range(5):
        assert login(login_env).status_code == 401
    other = create_app()
    other.config['_ENGINE'] = login_env.engine
    assert login(SimpleNamespace(client=other.test_client())).status_code == 429


def test_locked_account_skips_password_verification(login_env, monkeypatch):
    for _ in range(5):
        assert login(login_env).status_code == 401

    def must_not_run(*_):
        pytest.fail("a blocked login must not check another password")

    monkeypatch.setattr("server.check_password_hash", must_not_run)
    assert login(login_env).status_code == 429


def test_limiter_storage_failure_is_sanitized_and_fails_closed(login_env, monkeypatch, caplog):
    import sqlite3

    from login_rate_limit import LoginRateLimiter

    def unavailable(_):
        raise sqlite3.OperationalError("private storage path and secret")

    monkeypatch.setattr(LoginRateLimiter, "_connect", unavailable)
    response = login(login_env, password="correct-password")
    assert response.status_code == 503
    assert response.json == {"error": "service temporarily unavailable"}
    assert "private storage path and secret" not in caplog.text


def test_verification_error_does_not_consume_budget(login_env, monkeypatch):
    from server import check_password_hash

    def broken(*_):
        raise RuntimeError("verification failure")

    monkeypatch.setattr("server.check_password_hash", broken)
    for _ in range(6):
        assert login(login_env).status_code == 500
    monkeypatch.setattr("server.check_password_hash", check_password_hash)
    assert login(login_env, password="correct-password").status_code == 200


def test_concurrent_attempts_cannot_overrun_limit(tmp_path):
    from login_rate_limit import LoginRateLimited, LoginRateLimiter

    def try_login(_):
        limiter = LoginRateLimiter(tmp_path / "limits.sqlite3", "private-test-key")
        try:
            with limiter.attempt("user:1", "192.0.2.1") as attempt:
                attempt.failed = True
            return True
        except LoginRateLimited:
            return False

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(try_login, range(20)))
    assert sum(results) == 5


def test_limiter_creates_missing_parents_and_reopens_storage(tmp_path):
    from login_rate_limit import LoginRateLimiter

    path = tmp_path / "missing" / "private" / "limits.sqlite3"
    for _ in range(2):
        with LoginRateLimiter(path, "storage-test-key").attempt("user:1", "192.0.2.1") as attempt:
            attempt.failed = True

    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0] == 2


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
def test_limiter_creates_private_directory_with_permissive_umask(tmp_path):
    path = tmp_path / "private" / "limits.sqlite3"
    script = dedent("""
        import os
        import sys
        from pathlib import Path

        sys.path.insert(0, sys.argv[1])
        from login_rate_limit import LoginRateLimiter

        os.umask(0o022)
        with LoginRateLimiter(Path(sys.argv[2]), "permissions-test-key").attempt("user:1", "192.0.2.1"):
            pass
    """)
    subprocess.run(
        [sys.executable, "-B", "-c", script, str(Path(__file__).resolve().parents[2] / "src"), str(path)],
        check=True, capture_output=True, text=True, timeout=15,
    )
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@pytest.mark.parametrize("account,ip", [("user:1", "198.51.100.1"), ("user:2", "192.0.2.1")],
                         ids=["account-budget", "ip-budget"])
def test_limiter_preserves_preexisting_failure_budgets(tmp_path, monkeypatch, account, ip):
    import login_rate_limit

    monkeypatch.setattr(login_rate_limit.time, "time", lambda: 1000.0)
    path = tmp_path / "limits.sqlite3"
    # Frozen records from the existing storage format: do not derive these identifiers with the
    # implementation under test, or namespace changes would silently reset both the fixture and
    # the reader together.
    account_key = "1bae20179b953feac264a5373b5080011b58d693a853a025190c44a6854bd0a6"
    ip_key = "e6f77eda15b022f618c1b684d5e01a3309e0fd320fd19a2b7559d62d9ff28423"
    with sqlite3.connect(path) as conn:
        conn.execute("""CREATE TABLE login_attempts (
            id TEXT PRIMARY KEY, account_key TEXT NOT NULL,
            ip_key TEXT NOT NULL, expires REAL NOT NULL
        )""")
        conn.executemany(
            "INSERT INTO login_attempts VALUES (?, ?, ?, ?)",
            [(f"saved-{n}", account_key, ip_key, 1060.0) for n in range(5)],
        )

    limiter = login_rate_limit.LoginRateLimiter(path, "persistent-budget-test-key")
    with pytest.raises(login_rate_limit.LoginRateLimited) as blocked, limiter.attempt(account, ip):
        pytest.fail("a persisted failure budget must block a new attempt")
    assert blocked.value.retry_after == 60

    # Neither account nor IP is blocked globally by the pre-existing records.
    with limiter.attempt("unrelated-user", "203.0.113.1"):
        pass


@pytest.mark.parametrize("payload", [[], ["invalid"], {"email": 7, "password": "x"},
                                     {"email": "x", "password": ["x"]}])
def test_malformed_login_does_not_reach_authentication(login_env, payload):
    r = login_env.client.post('/api/login', json=payload, headers={"X-CSRF-Protection": "1"})
    assert r.status_code == 400
