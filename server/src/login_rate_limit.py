"""Enforce shared login failure limits with SQLite-backed reservations."""

import hashlib
import hmac
import math
import sqlite3
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4


class LoginRateLimited(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__("login rate limit reached")


@dataclass
class LoginAttempt:
    failed: bool = False


class LoginRateLimiter:
    LIMIT = 5
    WINDOW_SECONDS = 60

    def __init__(self, path: Path, secret_key: str):
        self.path = path
        self.secret_key = secret_key.encode("utf-8")

    def _key(self, scope: str, value: str) -> str:
        # Avoid storing account identifiers and IP addresses in clear text.
        return hmac.new(
            self.secret_key, f"{scope}:{value}".encode(), hashlib.sha256,
        ).hexdigest()

    def _connect(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return sqlite3.connect(self.path, timeout=5)

    def _reserve(self, account: str, ip: str) -> str:
        account_key, ip_key = self._key("account", account), self._key("ip", ip)
        reservation = uuid4().hex
        # BEGIN IMMEDIATE makes the two budgets atomic across workers/threads.
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            conn.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
                id TEXT PRIMARY KEY, account_key TEXT NOT NULL,
                ip_key TEXT NOT NULL, expires REAL NOT NULL
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS attempts_account ON login_attempts(account_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS attempts_ip ON login_attempts(ip_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS attempts_expiry ON login_attempts(expires)")
            conn.execute("DELETE FROM login_attempts WHERE expires <= ?", (now,))
            accounts = conn.execute(
                "SELECT expires FROM login_attempts WHERE account_key = ?", (account_key,),
            ).fetchall()
            ips = conn.execute(
                "SELECT expires FROM login_attempts WHERE ip_key = ?", (ip_key,),
            ).fetchall()
            blocked_until = [min(row[0] for row in bucket)
                             for bucket in (accounts, ips) if len(bucket) >= self.LIMIT]
            if blocked_until:
                # Rejected requests never add failures or move the expiry time.
                wait = max(1, min(self.WINDOW_SECONDS, math.ceil(max(blocked_until) - now)))
                raise LoginRateLimited(wait)
            conn.execute(
                "INSERT INTO login_attempts VALUES (?, ?, ?, ?)",
                (reservation, account_key, ip_key, now + self.WINDOW_SECONDS),
            )
        return reservation

    @contextmanager
    def attempt(self, account: str, ip: str):
        reservation = self._reserve(account, ip)
        result = LoginAttempt()
        try:
            yield result
        finally:
            # Successful logins/server errors release their reservation, but do not erase
            # previous failures. A crashed worker expires within 60s.
            if not result.failed:
                with closing(self._connect()) as conn, conn:
                    conn.execute("DELETE FROM login_attempts WHERE id = ?", (reservation,))
