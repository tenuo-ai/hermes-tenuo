"""Use limits for delegated grants (``max_uses`` in a delegation plan).

A warrant says what a grant may do until it expires. How many times it has done
it is state, and it is kept here, where the calls are checked. The count lives
in this process for as long as the grant's session does.
"""
from __future__ import annotations

import threading
from collections import Counter
from typing import Dict, Hashable, Iterator, Optional

_lock = threading.Lock()  # one lock for every budget: a use is taken along a whole chain


class UseBudget:
    """How many times one grant may still use each tool that has a limit.

    A use also counts against every ancestor grant that limits the same tool,
    so the grants below one never use a tool more often than it allows.
    """

    def __init__(self, limits: Dict[str, int], parent: Optional["UseBudget"] = None) -> None:
        self._limits = dict(limits)
        self._used: Dict[str, int] = {}
        self._parent = parent
        self._passes: Counter = Counter()

    def _chain(self, tool: str) -> Iterator["UseBudget"]:
        node: Optional[UseBudget] = self
        while node is not None:
            if tool in node._limits:
                yield node
            node = node._parent

    def take(self, tool: str) -> Optional[int]:
        """Take one use of *tool*. None when taken, else the limit that is used up."""
        with _lock:
            holders = list(self._chain(tool))
            for budget in holders:
                if budget._used.get(tool, 0) >= budget._limits[tool]:
                    return budget._limits[tool]
            for budget in holders:
                budget._used[tool] = budget._used.get(tool, 0) + 1
            return None

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

    def finish_call(self, tool_call_id: str, call_key: str) -> None:
        """Discard passes for an invocation that completed, blocked, or was cancelled.

        An ID matches even if middleware changed the arguments. Without an ID,
        discard matching unkeyed passes conservatively rather than let a later
        registry-only invocation reuse one.
        """
        with _lock:
            for call in list(self._passes):
                invocation_id, key = call
                if (tool_call_id and invocation_id == tool_call_id) or (
                    key == call_key and (not tool_call_id or not invocation_id)
                ):
                    del self._passes[call]
