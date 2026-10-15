"""Warrant checks for Hermes Agent tool calls.

``HermesGuard.pre_tool_call`` runs on every tool name and argument dict
before the handler. It returns ``{"action": "block", "message": ...}``
or ``None``. ``post_tool_call`` writes the local audit record.

Typical use is the plugin entry point. You can also construct
``HermesGuard`` in tests and scripts (see ``hermes-tenuo demo``).

Invariants:
    - Agents consume warrants; they do not mint them.
    - ``delegate_task`` children get a grant from the parent's warrant, one
      per task, staged when the call is authorised and attached at
      ``subagent_start``; the hop is verified as a chain. A child with no
      staged grant holds no authority.
    - Tool calls without a session id (``execute_code``) are attributed by
      task id, never silently checked against the config warrant once more
      than one warrant is in use.
    - Concurrent gateway sessions must use ``set_session_warrant`` per
      session with independently minted warrants. The single-agent child
      heuristic is not safe there.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes_tenuo")

# Session marker: a subagent that a delegation plan did not authorise.
_NO_AUTHORITY = object()


@dataclass
class _ChildGrant:
    """A warrant granted to one delegated child, waiting for its session id."""
    warrant: Any
    chain: List[Any]        # ancestor warrants, root first
    key: Any                # the child's own signing key
    goal: Optional[str]     # the task goal, matched against subagent_start


def _toolset_list(value: Any) -> Optional[List[str]]:
    """None when no toolsets were named; otherwise the names as a list."""
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return []


def _delegated_tasks(args: Dict[str, Any]) -> List[Tuple[Optional[str], Optional[List[str]]]]:
    """(goal, toolsets) for each child a delegate_task call spawns, in Hermes's order.

    ``tasks`` wins when it is a non-empty list (Hermes also accepts it as a
    JSON string); otherwise ``goal`` is a single task. A task's own
    ``toolsets`` override the top-level ones. ``None`` means none were named.
    """
    top = _toolset_list(args.get("toolsets"))
    tasks = args.get("tasks")
    if isinstance(tasks, str):
        try:
            tasks = json.loads(tasks)
        except ValueError:
            tasks = None
    if isinstance(tasks, list) and tasks:
        out = []
        for task in tasks:
            if isinstance(task, dict):
                goal = task.get("goal")
                toolsets = _toolset_list(task["toolsets"]) if "toolsets" in task else top
                out.append((goal if isinstance(goal, str) else None, toolsets))
            else:
                out.append((task if isinstance(task, str) else None, top))
        return out
    goal = args.get("goal")
    return [(goal if isinstance(goal, str) else None, top)]


def _allows_unknown_args(warrant: Any, tool: str) -> bool:
    """Whether *warrant* lets *tool* take arguments it does not name (``_allow_unknown``).

    The Python binding does not expose the flag, so ask the core: a call
    with an argument no warrant names fails as an unknown field only when
    the flag is off.
    """
    probe = "__hermes_tenuo_probe__"
    reason = warrant.check_constraints(tool, {probe: 0})
    return not (reason and probe in str(reason) and "unknown field" in str(reason))


# ---------------------------------------------------------------------------
# Audit event
# ---------------------------------------------------------------------------

@dataclass
class HermesAuditEvent:
    """Record of a single authorization decision."""
    tool: str
    args: Dict[str, Any]
    decision: str           # "ALLOW" | "DENY"
    reason: str
    session_id: str = ""
    task_id: str = ""
    tool_call_id: str = ""
    duration_ms: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


AuditCallback = Callable[[HermesAuditEvent], None]


# ---------------------------------------------------------------------------
# Enforcement result helpers
# ---------------------------------------------------------------------------

def _format_denial_reason(result: Any, tool_name: str) -> str:
    """Return a human-readable denial reason, with richer messaging for
    InsufficientApprovals (tenuo>=0.2.3) so the agent knows the call is
    retryable once additional approvals are gathered.
    """
    if getattr(result, "error_type", None) == "insufficient_approvals":
        got = getattr(result, "got", None)
        need = getattr(result, "need", None)
        if got is not None and need is not None:
            return (
                f"Multi-sig approval required for '{tool_name}': "
                f"{got}/{need} approvals received. "
                "Gather the remaining approvals and retry."
            )
        return (
            result.denial_reason
            or f"Multi-sig approval threshold not met for '{tool_name}'. Retry after gathering approvals."
        )
    return result.denial_reason or f"Tool '{tool_name}' not authorized"


# ---------------------------------------------------------------------------
# HermesGuard
# ---------------------------------------------------------------------------

class HermesGuard:
    """Authorization guard for Hermes Agent tool calls.

    Wires into ``pre_tool_call`` and ``post_tool_call``. Without a warrant,
    calls pass through and a warning is logged. With a warrant, each call
    is checked before the handler runs.

    Single-agent (CLI / cron):
        Pass ``warrant`` and ``signing_key``. One session at a time.

    ``delegate_task``:
        When the parent's call is allowed, each task gets a warrant granted
        from the parent's (``child_warrant`` scope if configured, else the
        parent's own, narrowed by any toolsets named on the call) and a
        fresh key. ``subagent_start`` attaches it to the child session with
        the parent chain. A ``delegation_plan`` replaces this with per-depth
        grants.

    Multi-user gateway:
        The single-agent child heuristic is not safe when sessions run
        concurrently. Call ``set_session_warrant(session_id, warrant)``
        with that user's own warrant when a session starts, and
        ``clear_session_warrant`` when it ends. After any session warrant
        exists, calls from a session with none are blocked
        (``require_session_warrant``, on by default).
    """

    def __init__(
        self,
        warrant: Optional[Any] = None,
        signing_key: Optional[Any] = None,
        *,
        child_warrant: Optional[Any] = None,
        trusted_roots: Optional[List[Any]] = None,
        on_denial: str = "block",   # "block" | "log"
        audit_callback: Optional[AuditCallback] = None,
        approval_handler: Optional[Callable] = None,
        require_session_warrant: Optional[bool] = None,
        delegation_plan: Optional[Any] = None,
    ):
        self._static_warrant = warrant
        self._static_signing_key = signing_key
        self._child_warrant = child_warrant
        self._trusted_roots = trusted_roots
        self._trusted_roots_lock = threading.Lock()
        self._on_denial = on_denial
        self._audit_callback = audit_callback
        self._approval_handler = approval_handler
        # None = on once set_session_warrant has been used; True/False override.
        self._require_session_warrant = require_session_warrant
        # Per-depth argument grants for delegate_task trees (hermes_tenuo.delegation).
        self._delegation_plan = delegation_plan
        # parent session → grants staged by an authorised delegate_task, awaiting subagent_start
        self._planned_children: Dict[str, deque] = {}
        self._audit_only_warned = False  # warn once when running without a warrant
        self._uses_session_warrants = False  # set by set_session_warrant (gateway)

        # Session warrant registry: session_id → (warrant, signing_key)
        self._session_warrants: Dict[str, Tuple[Any, Optional[Any]]] = {}
        self._session_lock = threading.Lock()

        # Session warrant chains: session_id → parent_warrant for chain verification
        # session_id → ancestor warrants, root first (the holder presents them all)
        self._session_warrant_chains: Dict[str, List[Any]] = {}
        self._primary_session_id: Optional[str] = None
        self._primary_lock = threading.Lock()

        self._pending_lock = threading.Lock()  # guards _planned_children
        self._saw_subagent_start = False

        # task id → session ids seen with it (attributes sessionless execute_code calls)
        self._task_sessions: Dict[str, set] = {}
        self._task_lock = threading.Lock()

        # Pre-hook decisions: tool_call_id → (allowed, reason)
        # Stored by pre_tool_call so post_tool_call can record the accurate outcome.
        self._pre_decisions: Dict[str, Tuple[bool, str]] = {}
        self._pre_decisions_lock = threading.Lock()

        # Connect to control plane (auto-discovers from env if not already connected)
        from tenuo.control_plane import get_or_create
        self._control_plane = get_or_create()

    @property
    def has_warrant(self) -> bool:
        return self._static_warrant is not None

    @property
    def _session_warrant_required(self) -> bool:
        if self._require_session_warrant is False:
            return False
        if self._require_session_warrant is True:
            return True
        return self._uses_session_warrants

    # ------------------------------------------------------------------
    # Session warrant management (gateway multi-user)
    # ------------------------------------------------------------------

    def set_session_warrant(
        self,
        session_id: str,
        warrant: Any,
        signing_key: Optional[Any] = None,
        *,
        parent_warrant: Optional[Any] = None,
    ) -> None:
        """Attach a warrant to *session_id*.

        Pass *parent_warrant* when *warrant* is a ``grant_builder`` child so
        ``enforce_tool_call`` verifies the delegation chain. Omit it for
        independently minted session warrants (gateway roles).
        """
        with self._session_lock:
            self._session_warrants[session_id] = (warrant, signing_key)
            self._uses_session_warrants = True
            if parent_warrant is not None:
                self._session_warrant_chains[session_id] = (
                    list(parent_warrant) if isinstance(parent_warrant, (list, tuple)) else [parent_warrant]
                )
        logger.debug("hermes-tenuo: registered warrant for session %s", session_id)

    def clear_session_warrant(self, session_id: str) -> None:
        with self._session_lock:
            self._session_warrants.pop(session_id, None)
            self._session_warrant_chains.pop(session_id, None)

    def _chain_for(self, session_id: str) -> List[Any]:
        """Ancestor warrants for *session_id*, root first; empty for a root session."""
        with self._session_lock:
            chain = self._session_warrant_chains.get(session_id)
        if chain is None:
            return []
        return list(chain) if isinstance(chain, (list, tuple)) else [chain]

    def set_trusted_roots(self, roots: Optional[List[Any]]) -> None:
        """Thread-safe replacement of the trusted root set.

        Call this after receiving a warrant to install the issuer
        anchor used for chain verification.  Pass None to clear.
        """
        with self._trusted_roots_lock:
            self._trusted_roots = roots

    def _get_trusted_roots(self) -> Optional[List[Any]]:
        """Thread-safe read of the current trusted root set (testing/introspection)."""
        with self._trusted_roots_lock:
            return self._trusted_roots

    def _resolve_warrant(
        self, session_id: str
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """Return (warrant, signing_key) for a session.

        Resolution order:
        1. Explicit session warrant (set via set_session_warrant — gateway use case,
           or injected by subagent_start hook before the child's first tool call)
        2. Child warrant fallback — heuristic for deployments where subagent_start
           did not fire (e.g. older Hermes builds). Detects child sessions by position:
           the first session_id seen is the primary; all subsequent different IDs are
           assumed children and claim the next pending warrant in FIFO order.
        3. Static warrant from plugin config (fallback for primary session)
        """
        with self._session_lock:
            entry = self._session_warrants.get(session_id)
        if entry is not None:
            return entry

        if self._planned_children and not self._saw_subagent_start:
            # Fallback for a Hermes build that does not fire subagent_start:
            # the first session seen is the primary, and a new session id
            # after an authorised delegate_task claims the next staged grant.
            # Only safe when one parent runs at a time (CLI / cron); gateways
            # attach session warrants explicitly and never reach this branch.
            # Lock ordering: _primary_lock → _pending_lock → _session_lock.
            grant = None
            with self._primary_lock:
                if self._primary_session_id is None and session_id:
                    self._primary_session_id = session_id
                elif self._primary_session_id != session_id and session_id:
                    # No staged grant: a new independent session, not a child.
                    grant = self._claim_child_grant(self._primary_session_id)
            if grant is not None:
                self._attach_child(session_id, grant)
                return grant.warrant, grant.key

        return self._static_warrant, self._static_signing_key

    # ------------------------------------------------------------------
    # delegate_task: one grant per child, staged when the call is allowed
    # ------------------------------------------------------------------

    def _tools_for_toolsets(self, toolsets: List[str], tools: List[str]) -> set:
        """The subset of *tools* (warrant tool names) that *toolsets* cover.

        A toolset that does not resolve contributes nothing, so a typo
        narrows the child instead of widening it.
        """
        wanted: set = set()
        try:
            from toolsets import resolve_toolset
        except ImportError:
            resolve_toolset = None
        for ts in toolsets:
            if resolve_toolset is not None:
                try:
                    wanted.update(resolve_toolset(ts) or [])
                except Exception:
                    pass
                continue
            # Hermes is not importable (tests, scripts): match "web" to web_*.
            for t in tools:
                bare = t.removeprefix("tool:")
                if bare == ts or bare.startswith(ts + "_"):
                    wanted.add(bare)
        return {t for t in tools if t.removeprefix("tool:") in wanted}

    def _child_warrant_grants(self, parent_warrant: Any) -> Tuple[Dict[str, Dict[str, Any]], int]:
        """Capabilities and TTL the configured ``child_warrant`` asks for, under *parent_warrant*.

        Each tool keeps the parent's constraints and takes the child warrant's
        constraints where it names them; Tenuo rejects the grant if any of
        them is wider than the parent. Tools the parent does not hold are
        dropped. Raises ValueError if the child warrant has expired.
        """
        child = self._child_warrant
        remaining = int(child.ttl_remaining.total_seconds())
        if child.is_expired() or remaining <= 0:
            raise ValueError("the configured child_warrant has expired")
        parent_caps = parent_warrant.capabilities or {}
        caps: Dict[str, Dict[str, Any]] = {}
        dropped = []
        for tool, args in (child.capabilities or {}).items():
            match = next(
                (t for t in (tool, f"tool:{tool}", tool.removeprefix("tool:")) if t in parent_caps),
                None,
            )
            if match is None:
                dropped.append(tool)
                continue
            merged = dict(parent_caps[match])
            merged.update(args)
            # Keep "other arguments allowed" only where both warrants allow it.
            if merged and _allows_unknown_args(child, tool) and _allows_unknown_args(parent_warrant, match):
                merged["_allow_unknown"] = True
            caps[match] = merged
        if dropped:
            logger.warning(
                "hermes-tenuo: child_warrant tools %s are not held by the delegating "
                "warrant; the child does not get them", sorted(dropped),
            )
        return caps, remaining

    def _grant_children(
        self, parent_session_id: str, tasks: List[Tuple[Optional[str], Optional[List[str]]]]
    ) -> Optional[Dict[str, Any]]:
        """Grant one warrant per delegated task from the parent's warrant; block if impossible.

        With ``child_warrant`` configured, each child gets that scope, granted
        under the parent so the hop verifies as a chain. Without it, the child
        keeps the parent's scope (Hermes children inherit the parent's
        toolsets). Toolsets named on the call narrow either one further.
        Every child gets a fresh key that only it holds.
        """
        from tenuo import SigningKey

        parent_warrant, parent_key = self._resolve_warrant(parent_session_id)
        if parent_warrant is None or parent_warrant is _NO_AUTHORITY or parent_key is None:
            return {"action": "block", "message": "tenuo: no warrant to delegate from in this session"}
        chain = self._chain_for(parent_session_id) + [parent_warrant]
        parent_tools = list(parent_warrant.tools or [])
        grants = []
        try:
            child_caps: Optional[Dict[str, Dict[str, Any]]] = None
            ttl = 3600  # a requested maximum; the core caps it at the parent's expiry
            if self._child_warrant is not None:
                child_caps, ttl = self._child_warrant_grants(parent_warrant)
            for goal, toolsets in tasks:
                keep = set(child_caps) if child_caps is not None else set(parent_tools)
                if toolsets is not None:
                    keep &= self._tools_for_toolsets(toolsets, parent_tools)
                if not keep:
                    return {
                        "action": "block",
                        "message": (
                            "tenuo: delegation rejected: the child would hold no tools"
                            + (f" (toolsets={toolsets})" if toolsets is not None else "")
                        ),
                    }
                child_key = SigningKey.generate()
                if child_caps is not None:
                    builder = parent_warrant.grant_builder().holder(child_key.public_key)
                    for tool in sorted(keep):
                        builder = builder.capability(tool, **child_caps[tool])
                    if "delegate_task" not in keep:
                        # The child can't delegate, so its grant can't be delegated either.
                        builder = builder.terminal()
                    child = builder.ttl(ttl).grant(parent_key)
                else:
                    b = parent_warrant.attenuate_builder()
                    b.inherit_all()
                    b.retain_tools(sorted(keep))
                    b.with_holder(child_key.public_key)
                    b.with_ttl(ttl)
                    child = b.delegate(parent_key)
                logger.info(
                    "hermes-tenuo: delegation scope: parent has %d tools, child gets %s",
                    len(parent_tools), sorted(keep),
                )
                grants.append(_ChildGrant(child, chain, child_key, goal))
        except Exception as exc:
            logger.warning("hermes-tenuo: delegation grant failed: %s", exc)
            return {"action": "block", "message": f"tenuo: delegation rejected: {exc}"}
        self._stage_grants(parent_session_id, grants)
        return None

    def _register_planned_children(
        self, parent_session_id: str, tasks: List[Tuple[Optional[str], Optional[List[str]]]]
    ) -> Optional[Dict[str, Any]]:
        """Grant each child of one delegate_task call its plan level; block if impossible.

        Each child gets a fresh key, so its warrant is bound to a key only it holds.
        """
        from tenuo import SigningKey

        plan = self._delegation_plan
        depth = len(self._chain_for(parent_session_id)) + 1
        level = plan.level(depth)
        if level is None:
            return {"action": "block",
                    "message": f"tenuo: delegation depth {depth} is beyond the delegation plan (max {plan.max_depth})"}
        parent_warrant, parent_key = self._resolve_warrant(parent_session_id)
        if parent_warrant is None or parent_warrant is _NO_AUTHORITY or parent_key is None:
            return {"action": "block", "message": "tenuo: no warrant to delegate from in this session"}
        chain = self._chain_for(parent_session_id) + [parent_warrant]
        try:
            planned = []
            for goal, _toolsets in tasks:
                child_key = SigningKey.generate()
                builder = parent_warrant.grant_builder().holder(child_key.public_key)
                level_tools = plan.constraints_for(depth)
                for tool, tool_args in level_tools.items():
                    builder = builder.capability(tool, **tool_args) if tool_args else builder.capability(tool)
                if "delegate_task" not in level_tools:
                    # The child can't delegate, so its grant can't be delegated either.
                    builder = builder.terminal()
                planned.append(_ChildGrant(builder.ttl(level.ttl_seconds).grant(parent_key), chain, child_key, goal))
        except Exception as exc:
            logger.warning("hermes-tenuo: delegation plan grant failed at depth %d: %s", depth, exc)
            return {"action": "block", "message": f"tenuo: delegation to depth {depth} rejected: {exc}"}
        self._stage_grants(parent_session_id, planned)
        return None

    def _stage_grants(self, parent_session_id: str, grants: List["_ChildGrant"]) -> None:
        with self._pending_lock:
            self._planned_children.setdefault(parent_session_id, deque()).extend(grants)
        logger.debug(
            "hermes-tenuo: staged %d child grant(s) for session %s", len(grants), parent_session_id,
        )

    def _claim_child_grant(
        self, parent_session_id: str, goal: Optional[str] = None
    ) -> Optional["_ChildGrant"]:
        """Take the staged grant for the next child of *parent_session_id*.

        With *goal* (Hermes passes the child's goal to ``subagent_start``) only
        a grant staged for that goal matches. Without it, grants are taken in
        task order, which is the order Hermes builds the children in.
        """
        with self._pending_lock:
            queue = self._planned_children.get(parent_session_id)
            if not queue:
                return None
            if goal is None:
                return queue.popleft()
            for i, grant in enumerate(queue):
                if grant.goal == goal:
                    del queue[i]
                    return grant
        return None

    def _attach_child(self, child_session_id: str, grant: "_ChildGrant") -> None:
        self.set_session_warrant(child_session_id, grant.warrant, grant.key, parent_warrant=grant.chain)

    # ------------------------------------------------------------------
    # Hook: on_session_start / on_session_end
    # ------------------------------------------------------------------

    def on_session_start(
        self,
        session_id: str,
        parent_session_id: Optional[str] = None,
        task_index: Optional[int] = None,
    ) -> None:
        """Called when Hermes fires on_session_start.

        Hermes passes session_id, model, and platform, not parent_session_id, so
        ``subagent_start`` is where child sessions get their grants. If a
        parent id is ever passed here, the child is attached the same way.
        """
        if parent_session_id and session_id:
            self.on_subagent_start(parent_session_id, session_id)

    def on_session_end(self, session_id: str) -> None:
        self.clear_session_warrant(session_id)
        # Reset primary if this was the primary session, so the next session
        # is correctly identified as a new primary rather than a child.
        with self._primary_lock:
            if self._primary_session_id == session_id:
                self._primary_session_id = None
        with self._session_lock:
            self._session_warrant_chains.pop(session_id, None)
        with self._pending_lock:
            self._planned_children.pop(session_id, None)
        with self._task_lock:
            for task_id in [t for t, s in self._task_sessions.items() if session_id in s]:
                self._task_sessions[task_id].discard(session_id)
                if not self._task_sessions[task_id]:
                    del self._task_sessions[task_id]

    # ------------------------------------------------------------------
    # Hook: subagent_start
    # ------------------------------------------------------------------

    def on_subagent_start(
        self,
        parent_session_id: Optional[str],
        child_session_id: Optional[str],
        *,
        child_goal: Optional[str] = None,
        child_task_id: Optional[str] = None,
        **_kwargs: Any,
    ) -> None:
        """Called when Hermes fires subagent_start (both session ids known, before the child runs).

        Attaches the grant staged when the parent's ``delegate_task`` call was
        authorised. A child with no matching grant holds no authority: its
        calls are blocked rather than falling back to the parent's warrant.
        """
        if not parent_session_id or not child_session_id:
            return
        self._saw_subagent_start = True  # the session-order fallback is no longer needed
        if child_task_id:
            # Hermes runs the child under this task id; execute_code calls made
            # by the child carry it without a session id.
            self._remember_task(child_task_id, child_session_id)

        grant = self._claim_child_grant(parent_session_id, child_goal)
        if grant is not None:
            self._attach_child(child_session_id, grant)
            logger.debug(
                "hermes-tenuo: subagent_start: child %s attached (parent=%s, depth=%d)",
                child_session_id, parent_session_id, len(grant.chain),
            )
            return

        parent_warrant, _ = self._resolve_warrant(parent_session_id)
        if parent_warrant is None:
            # Unconfigured (audit-only) guard: nothing to narrow.
            return
        logger.warning(
            "hermes-tenuo: subagent %s (parent %s) does not match an authorised "
            "delegate_task call; it holds no authority", child_session_id, parent_session_id,
        )
        self.set_session_warrant(child_session_id, _NO_AUTHORITY, None)

    # ------------------------------------------------------------------
    # Sessionless calls (execute_code): attribute by task id
    # ------------------------------------------------------------------

    _MAX_TASKS = 4096

    def _remember_task(self, task_id: str, session_id: str) -> None:
        with self._task_lock:
            self._task_sessions.setdefault(task_id, set()).add(session_id)
            while len(self._task_sessions) > self._MAX_TASKS:
                self._task_sessions.pop(next(iter(self._task_sessions)))

    def _attribute_session(self, session_id: str, task_id: str) -> Tuple[str, Optional[str]]:
        """Return (session_id, block_reason) for a tool call.

        Hermes dispatches tool calls made inside ``execute_code`` with the
        task id and no session id. Every agent's own calls carry both, so the
        task id maps back to the session that ran the script. A sessionless
        call whose task id maps to no single session is blocked once more
        than one warrant is in play (sub-agents or gateway sessions), instead
        of being checked against the config warrant.
        """
        if session_id:
            if task_id:
                self._remember_task(task_id, session_id)
            return session_id, None
        if not task_id:
            return session_id, None
        with self._task_lock:
            sessions = set(self._task_sessions.get(task_id, ()))
        if len(sessions) == 1:
            return sessions.pop(), None
        if self._uses_session_warrants:
            return session_id, (
                f"tenuo: this tool call has no session id and its task id {task_id!r} "
                f"does not identify one session; blocked because more than one warrant "
                f"is in use"
            )
        return session_id, None

    # ------------------------------------------------------------------
    # Hook: pre_tool_call
    # ------------------------------------------------------------------

    def pre_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        *,
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Returns {"action": "block", "message": "..."} to block the call,
        or None to allow it.
        """
        session_id, unattributed = self._attribute_session(session_id, task_id)
        if unattributed is not None:
            self._emit_audit(tool_name, args, False, unattributed, session_id, task_id, tool_call_id)
            self._remember_decision(tool_call_id, False, unattributed)
            return {"action": "block", "message": unattributed}
        warrant, signing_key = self._resolve_warrant(session_id)
        if warrant is _NO_AUTHORITY:
            return {
                "action": "block",
                "message": "tenuo: this subagent was not started by an authorised delegation and holds no authority",
            }

        # Ensure primary session is tracked even before child sessions appear
        if session_id and self._primary_session_id is None:
            with self._primary_lock:
                if self._primary_session_id is None:
                    self._primary_session_id = session_id

        # No warrant on this call. An unconfigured single-agent guard is a
        # documented no-op. A gateway that already called set_session_warrant
        # is configured: unknown sessions fail closed unless the operator
        # sets require_session_warrant=False.
        if warrant is None:
            if self._session_warrant_required:
                return {
                    "action": "block",
                    "message": (
                        "tenuo: no warrant for this session — "
                        "require_session_warrant is on"
                    ),
                }
            if not self._audit_only_warned:
                self._audit_only_warned = True
                logger.warning(
                    "hermes-tenuo: AUDIT-ONLY — no warrant configured; all tool calls "
                    "pass through. Set TENUO_WARRANT to activate enforcement."
                )
            return None

        # Enforcement requires a signing key for Proof-of-Possession.
        # Hard block: a misconfigured demo that silently passes through
        # defeats the point of running Tenuo at all.
        if signing_key is None:
            return {
                "action": "block",
                "message": "tenuo: TENUO_SIGNING_KEY not configured — all calls blocked until signing key is set",
            }

        result = self._enforce(tool_name, args, signing_key, warrant, session_id, task_id, tool_call_id)

        # Intercept delegate_task: only pre-register attenuated child warrants if
        # the delegation call itself was AUTHORIZED. Registering before authorization
        # would let a denied delegation poison pending slots — the next heuristic
        # child session could claim a warrant with no valid parent delegation.
        if tool_name == "delegate_task" and result is None:
            tasks = _delegated_tasks(args)
            if self._delegation_plan is not None:
                blocked = self._register_planned_children(session_id, tasks)
            else:
                blocked = self._grant_children(session_id, tasks)
            if blocked is not None:
                self._remember_decision(tool_call_id, False, blocked["message"])
                return blocked

        return result

    def _enforce(
        self,
        tool_name: str,
        args: Dict[str, Any],
        signing_key: Any,
        warrant: Any,
        session_id: str,
        task_id: str,
        tool_call_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Run enforce_tool_call once against the normalized tool name."""
        try:
            from tenuo._enforcement import enforce_tool_call
            from tenuo.config import resolve_trusted_roots

            bound = warrant.bind(signing_key)
            # For chain verification: use configured trusted_roots.
            # If not configured, extract the root from the parent warrant's issuer.
            chain = self._chain_for(session_id)
            with self._trusted_roots_lock:
                trusted = resolve_trusted_roots(self._trusted_roots)
            # No fallback anchor: not the signing key, and not the issuer of a
            # warrant in the chain being verified. Deriving trust from the
            # credential under test accepts any chain an attacker signs. Without
            # a configured trusted_root, enforce_tool_call fails closed.
            result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=args,
                bound_warrant=bound,
                trusted_roots=trusted,
                warrant_chain=chain or None,
                approval_handler=self._approval_handler,
            )
        except Exception as exc:
            logger.warning("hermes-tenuo: enforcement error for %s: %s", tool_name, exc)
            # Enforcement exceptions always block — on_denial: log only applies to
            # *policy* denials from the Rust core (result.allowed=False). Internal
            # failures (bad warrant, expired key, crypto error) should never silently
            # allow execution, regardless of the on_denial setting.
            self._remember_decision(tool_call_id, False, f"Authorization error: {exc}")
            return {"action": "block", "message": f"Authorization error: {exc}"}

        if self._control_plane is not None:
            try:
                self._control_plane.emit_for_enforcement(
                    result, chain_result=getattr(result, "chain_result", None)
                )
            except Exception:
                pass

        self._emit_audit(tool_name, args, result.allowed, result.denial_reason or "", session_id, task_id, tool_call_id)

        if not result.allowed:
            reason = _format_denial_reason(result, tool_name)
            # Hermes may fire post_tool_call even for a blocked call (0.21+ does),
            # so the post record must carry this decision, not "post-dispatch".
            self._remember_decision(tool_call_id, False, reason)
            if self._on_denial == "log":
                logger.warning("hermes-tenuo [BLOCKED-LOG] %s: %s", tool_name, reason)
                return None
            return {"action": "block", "message": reason}

        self._remember_decision(tool_call_id, True, "")
        return None

    _MAX_PENDING_DECISIONS = 2048

    def _remember_decision(self, tool_call_id: str, allowed: bool, reason: str) -> None:
        """Stash the pre-hook decision for post_tool_call. Bounded: an older Hermes
        that never fires post for a blocked call must not leak memory."""
        if not tool_call_id:
            return
        with self._pre_decisions_lock:
            self._pre_decisions[tool_call_id] = (allowed, reason)
            while len(self._pre_decisions) > self._MAX_PENDING_DECISIONS:
                self._pre_decisions.pop(next(iter(self._pre_decisions)))

    # ------------------------------------------------------------------
    # Hook: post_tool_call
    # ------------------------------------------------------------------

    def post_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: str,
        *,
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
        duration_ms: int = 0,
    ) -> None:
        """Emit an audit event. Fires for every tool call, including audit-only mode."""
        if not session_id and task_id:
            session_id, _ = self._attribute_session(session_id, task_id)
        warrant, _ = self._resolve_warrant(session_id)

        # In audit-only mode (no warrant), emit a passthrough audit event
        if warrant is None:
            if self._control_plane is not None:
                from tenuo._enforcement import EnforcementResult
                audit_result = EnforcementResult(
                    allowed=True,
                    tool=tool_name,
                    arguments=args,
                )
                try:
                    self._control_plane.emit_for_enforcement(audit_result)
                except Exception:
                    pass
            self._emit_audit(tool_name, args, True, "audit-only", session_id, task_id, tool_call_id, duration_ms)
            return

        # The pre hook already decided; this record adds timing. Without a stored
        # decision (no tool_call_id, or a call that skipped the pre hook) the
        # handler did run, so it is an ALLOW tagged "post-dispatch".
        allowed = True
        reason = "post-dispatch"
        if tool_call_id:
            with self._pre_decisions_lock:
                pre = self._pre_decisions.pop(tool_call_id, None)
            if pre is not None:
                allowed, reason = pre
        self._emit_audit(tool_name, args, allowed, reason, session_id, task_id, tool_call_id, duration_ms)

    # ------------------------------------------------------------------
    # Internal: audit callback
    # ------------------------------------------------------------------

    def _emit_audit(
        self,
        tool: str,
        args: Dict[str, Any],
        allowed: bool,
        reason: str,
        session_id: str = "",
        task_id: str = "",
        tool_call_id: str = "",
        duration_ms: int = 0,
    ) -> None:
        if self._audit_callback is None:
            return
        event = HermesAuditEvent(
            tool=tool,
            args=args,
            decision="ALLOW" if allowed else "DENY",
            reason=reason,
            session_id=session_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            duration_ms=duration_ms,
        )
        try:
            self._audit_callback(event)
        except Exception as exc:
            logger.error("hermes-tenuo: audit callback failed: %s", exc, exc_info=True)


__all__ = ["HermesGuard", "HermesAuditEvent", "AuditCallback"]
