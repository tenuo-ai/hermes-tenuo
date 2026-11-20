"""Use limits for delegated grants (``max_uses`` in a delegation plan).

A warrant says what a grant may do until it expires. How many times it has done
it is state, and it is kept here, where the calls are checked. A delegated
child's count lives in this process, like its grant. The count of a warrant
that outlives the process is kept in a file (:class:`UseStore`).
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Dict, Hashable, Iterator, NamedTuple, Optional, Tuple

_lock = threading.Lock()  # one lock for every budget: a use is taken along a whole chain


class ArgumentIdentity:
    """Retain an unkeyed call's argument object across Hermes hook worker threads."""

    def __init__(self, args: dict) -> None:
        self.args = args

    def __hash__(self) -> int:
        return id(self.args)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ArgumentIdentity) and self.args is other.args


class Use(NamedTuple):
    """The outcome of asking for one use of a limited tool.

    When *taken*, ``count`` of ``limit`` is where the tightest limit along the
    chain now stands. When refused, it names the limit that is used up. *grant*
    is the id of the grant that limit belongs to; *own* says whether that is
    the grant making the call.
    """

    taken: bool
    count: int
    limit: int
    grant: str
    own: bool

    def record(self) -> Dict[str, object]:
        """The form written to the audit log."""
        return {"count": self.count, "limit": self.limit, "grant": self.grant}


def default_store_path() -> Path:
    """``$HERMES_HOME/tenuo/uses.db`` (profile-aware inside Hermes; see ``_home.hermes_home``)."""
    from hermes_tenuo._home import hermes_home

    return hermes_home() / "tenuo" / "uses.db"


class UseStore:
    """Use counts in a SQLite file, shared by every process of one Hermes profile.

    One row per warrant and tool: ``used``, the uses that count now, and
    ``takes``, how many were ever taken. A use given back lowers ``used`` and
    leaves ``takes``, so ``takes`` never goes down. Taking a use is one write
    transaction, so two processes can never both take the last one. Rows go
    when the warrant expires.
    """

    def __init__(self, path: os.PathLike | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._open()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS use_counts ("
                "warrant TEXT NOT NULL, tool TEXT NOT NULL, used INTEGER NOT NULL, takes INTEGER NOT NULL, "
                "expires REAL NOT NULL, PRIMARY KEY (warrant, tool))"
            )
            db.execute("COMMIT")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _open(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10, isolation_level=None)

    def take(
        self, warrant: str, tool: str, limit: int, expires: float, seen: Tuple[int, int] = (0, 0),
    ) -> Tuple[bool, int, int]:
        """Take one use if fewer than *limit* are used. Returns (taken, used, takes) as now recorded.

        *seen* is the (used, takes) this process last read. A file whose
        ``takes`` is lower was replaced or cleared while Hermes ran, and is put
        back to what was seen. A lower ``used`` with the same or more takes is
        another process giving a use back, and stands.
        """
        with closing(self._open()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM use_counts WHERE expires <= ?", (time.time(),))
                db.execute("INSERT OR IGNORE INTO use_counts VALUES (?, ?, 0, 0, ?)", (warrant, tool, expires))
                used, takes = db.execute(
                    "SELECT used, takes FROM use_counts WHERE warrant = ? AND tool = ?", (warrant, tool)
                ).fetchone()
                if takes < seen[1]:
                    used, takes = max(used, seen[0]), seen[1]
                taken = used < limit
                if taken:
                    used, takes = used + 1, takes + 1
                db.execute("UPDATE use_counts SET used = ?, takes = ? WHERE warrant = ? AND tool = ?",
                           (used, takes, warrant, tool))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return taken, used, takes

    def give_back(self, warrant: str, tool: str) -> int:
        """Return one use. The uses that count afterwards."""
        with closing(self._open()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("UPDATE use_counts SET used = used - 1 WHERE warrant = ? AND tool = ? AND used > 0",
                           (warrant, tool))
                row = db.execute("SELECT used FROM use_counts WHERE warrant = ? AND tool = ?", (warrant, tool)).fetchone()
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return row[0] if row else 0

    def used(self, warrant: str) -> Dict[str, int]:
        """tool → uses recorded for *warrant*."""
        with closing(self._open()) as db:
            return dict(db.execute("SELECT tool, used FROM use_counts WHERE warrant = ? AND expires > ?",
                                   (warrant, time.time())).fetchall())


class UseBudget:
    """How many times one grant may still use each tool that has a limit.

    A use also counts against every ancestor grant that limits the same tool,
    so the grants below one never use a tool more often than it allows.
    """

    def __init__(
        self, limits: Dict[str, int], parent: Optional["UseBudget"] = None, grant: str = "",
        *, store: Optional[UseStore] = None, expires: float = 0.0,
    ) -> None:
        self._limits = dict(limits)
        self._used: Dict[str, int] = {}
        self._parent = parent
        self._grant = grant
        # With a store, this budget's own count is kept in the file; _used and
        # _takes mirror what this process last read there.
        self._store = store
        self._expires = expires
        self._takes: Dict[str, int] = {}
        self._passes: Counter = Counter()

    def _chain(self, tool: str) -> Iterator["UseBudget"]:
        node: Optional[UseBudget] = self
        while node is not None:
            if tool in node._limits:
                yield node
            node = node._parent

    def take(self, tool: str) -> Optional[Use]:
        """Take one use of *tool*. None when nothing limits it."""
        with _lock:
            holders = list(self._chain(tool))
            if not holders:
                return None
            for budget in holders:
                used, limit = budget._used.get(tool, 0), budget._limits[tool]
                if budget._store is None and used >= limit:
                    return Use(False, used, limit, budget._grant, budget is self)
            stored = []
            for budget in holders:
                if budget._store is None:
                    continue
                taken, used, takes = budget._store.take(
                    budget._grant, tool, budget._limits[tool], budget._expires,
                    (budget._used.get(tool, 0), budget._takes.get(tool, 0)),
                )
                budget._used[tool], budget._takes[tool] = used, takes
                if not taken:
                    for earlier in stored:
                        earlier._used[tool] = earlier._store.give_back(earlier._grant, tool)
                    return Use(False, used, budget._limits[tool], budget._grant, budget is self)
                stored.append(budget)
            for budget in holders:
                if budget._store is None:
                    budget._used[tool] = budget._used.get(tool, 0) + 1
            tightest = min(holders, key=lambda b: b._limits[tool] - b._used[tool])
            return Use(True, tightest._used[tool], tightest._limits[tool], tightest._grant, tightest is self)

    def give_back(self, tool: str) -> None:
        """Return a use taken for a call that was then refused before it ran."""
        with _lock:
            for budget in self._chain(tool):
                if budget._store is not None:
                    budget._used[tool] = budget._store.give_back(budget._grant, tool)
                elif budget._used.get(tool, 0) > 0:
                    budget._used[tool] -= 1

    def limits(self, tool: str) -> bool:
        with _lock:
            return next(self._chain(tool), None) is not None

    # Some Hermes builds check one call twice: the plugin hook, then the tool
    # registry. The hook takes the use and leaves a pass for that call; the
    # registry check hands the pass in instead of taking a second use. There is
    # never more than one pass per use taken, so passes cannot add uses.

    def leave_pass(self, call: Hashable) -> None:
        with _lock:
            self._passes[call] += 1

    def hand_in_pass(self, call: Hashable) -> bool:
        with _lock:
            if self._passes[call] <= 0:
                self._passes.pop(call, None)
                return False
            self._passes[call] -= 1
            if not self._passes[call]:
                del self._passes[call]
            return True

    def move_pass(self, source: Hashable, target: Hashable) -> None:
        """Move an unkeyed hook's pass into its execution middleware scope."""
        with _lock:
            count = self._passes.pop(source, 0)
            if count:
                self._passes[target] += count

    def finish_call(self, call: Hashable) -> None:
        """Discard only this invocation's passes, never another concurrent call's.

        An explicit ID matches even if middleware changed the arguments.
        Unkeyed calls match their execution scope, independently of argument rewrites.
        """
        with _lock:
            tool_call_id = call[0]
            if not tool_call_id:
                self._passes.pop(call, None)
                return
            # Sessions that share a budget may each have a call with this id in
            # flight; the scope (tool, session, task) tells them apart.
            for pending in list(self._passes):
                if pending[0] == tool_call_id and pending[1] == call[1]:
                    del self._passes[pending]
