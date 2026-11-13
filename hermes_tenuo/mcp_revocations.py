"""Keep MCP revocation state monotonic across clients and wrapper restarts."""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

from tenuo import SignedRevocationList


class WorkspaceRevocations:
    def __init__(self, workspace: Path, authorizer):
        self.path = workspace / "revocations.srl"
        self.database = workspace / "revocations.sqlite3"
        self.authorizer = authorizer
        self.installed = None
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS accepted_list "
                "(singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version TEXT NOT NULL, digest TEXT NOT NULL)"
            )

    def refresh(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            # Serialize acceptance, including competing wrapper processes that
            # encounter different signed lists at the same version.
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT version, digest FROM accepted_list WHERE singleton = 1").fetchone()
            try:
                raw = self.path.read_bytes()
            except FileNotFoundError:
                if previous is not None or self.installed is not None:
                    raise
                return
            digest = hashlib.sha256(raw).hexdigest()
            if previous is not None and digest == previous[1] and digest == self.installed:
                return
            srl = SignedRevocationList.from_bytes(raw)
            version = int(srl.version)
            if previous is not None:
                prior_version, prior_digest = previous
                if version < int(prior_version) or version == int(prior_version) and digest != prior_digest:
                    raise ValueError("Revocation list is older than or conflicts with the accepted list")
            if digest != self.installed:
                self.authorizer.set_revocation_list(srl)
                self.installed = digest
            if previous != (str(version), digest):
                db.execute("INSERT OR REPLACE INTO accepted_list VALUES (1, ?, ?)", (str(version), digest))
