"""Use limits for delegated grants (``max_uses`` in a delegation plan).

A warrant says what a grant may do until it expires. How many times it has done
it is state, and it is kept here, where the calls are checked. The count lives
in this process for as long as the grant's session does.
"""
from __future__ import annotations

import threading
from collections import Counter
from typing import Dict, Hashable, Iterator, NamedTuple, Optional

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


class UseBudget:
    """How many times one grant may still use each tool that has a limit.

    A use also counts against every ancestor grant that limits the same tool,
    so the grants below one never use a tool more often than it allows.
    """

    def __init__(self, limits: Dict[str, int], parent: Optional["UseBudget"] = None, grant: str = "") -> None:
        self._limits = dict(limits)
        self._used: Dict[str, int] = {}
        self._parent = parent
        self._grant = grant
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
                if used >= limit:
                    return Use(False, used, limit, budget._grant, budget is self)
            for budget in holders:
                budget._used[tool] = budget._used.get(tool, 0) + 1
            tightest = min(holders, key=lambda b: b._limits[tool] - b._used[tool])
            return Use(True, tightest._used[tool], tightest._limits[tool], tightest._grant, tightest is self)

    def give_back(self, tool: str) -> None:
        """Return a use taken for a call that was then refused before it ran."""
        with _lock:
            for budget in self._chain(tool):
                if budget._used.get(tool, 0) > 0:
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
            for pending in list(self._passes):
                if pending[0] == tool_call_id:
                    del self._passes[pending]
