"""Keep verified proof-of-possession signatures across local wrapper processes."""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path


class WorkspaceNonces:
    # The SDK's default 30-second buckets and five-window PoP span.
    retention_seconds = 210
    pop_window_secs = 30
    max_clock_skew_seconds = 60

    def __init__(self, path: Path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, owner TEXT, expires REAL)")
            db.execute("CREATE INDEX IF NOT EXISTS nonce_expiration ON nonces (expires)")

    def _expires(self, now, ttl_seconds):
        return now + max(ttl_seconds, self.retention_seconds) + self.max_clock_skew_seconds

    def reserve(self, nonce_hex, ttl_seconds, owner):
        now = time.time()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM nonces WHERE expires <= ?", (now,))
            result = db.execute(
                "INSERT OR IGNORE INTO nonces VALUES (?, ?, ?)",
                (nonce_hex, owner, self._expires(now, ttl_seconds)),
            )
            return result.rowcount == 1

    def release(self, nonce_hex, owner):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM nonces WHERE nonce = ? AND owner = ?", (nonce_hex, owner))

    def check_and_record(self, nonce_hex, ttl_seconds):
        return self.reserve(nonce_hex, ttl_seconds, "")

    def seen(self, nonce_hex):
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute(
                "SELECT 1 FROM nonces WHERE nonce = ? AND expires > ?", (nonce_hex, time.time()),
            ).fetchone() is not None

    def record(self, nonce_hex, ttl_seconds):
        expires = self._expires(time.time(), ttl_seconds)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "INSERT INTO nonces VALUES (?, '', ?) ON CONFLICT(nonce) DO UPDATE "
                "SET expires = max(nonces.expires, excluded.expires)",
                (nonce_hex, expires),
            )
