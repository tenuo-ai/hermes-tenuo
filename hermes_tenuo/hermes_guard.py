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

import atexit
import hashlib
import json
import logging
import os
import sys
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes_tenuo")

# Session marker: a subagent that a delegation plan did not authorise.
_NO_AUTHORITY = object()
# Session marker: a session whose own warrant was cleared or has expired. It
# stays denied; it must never fall back to the config warrant.
_RETIRED = object()
# Returned for a session with no warrant of its own once the marker table has
# overflowed: it can no longer be told apart from a session that was denied.
_UNTRACKED = object()
# Session marker: an access-governed gateway turn whose sender matches no role
# (or is caught by the deny policy). It holds no authority for this turn.
_NO_ROLE = object()

_MARKER_REASONS = {
    _NO_AUTHORITY: "tenuo: this subagent was not started by an authorised delegation and holds no authority",
    _RETIRED: "tenuo: this session's warrant was cleared or has expired; it holds no authority",
    _UNTRACKED: (
        "tenuo: this session has no warrant of its own and too many sessions have been "
        "denied to tell it from one of them; it holds no authority until Hermes restarts"
    ),
    _NO_ROLE: "tenuo: no access role grants this sender; the call was blocked",
}


def _marker_reason(warrant: Any) -> Optional[str]:
    """The denial reason when *warrant* is a no-authority session marker, else None."""
    for marker, reason in _MARKER_REASONS.items():
        if warrant is marker:
            return reason
    return None

# Bounded waits for signed receipts still in the deferred emitter's queue.
_SESSION_END_FLUSH_SECS = 2.0
_EXIT_FLUSH_SECS = 5.0


def _safe_error_message(exc: BaseException) -> str:
    """Render an SDK error without echoing the Cloud credential."""
    message = str(exc)
    token = os.environ.get("TENUO_CONNECT_TOKEN")
    if token:
        message = message.replace(token, "[REDACTED]")
    return message


def _log_receipt_error(exc: BaseException) -> None:
    logger.warning("hermes-tenuo: receipt delivery failed: %s", _safe_error_message(exc))


def _connect_control_plane() -> Any:
    """Return the process control-plane client, adding Cloud receipts when available."""
    from tenuo.control_plane import get_client, get_or_create

    if get_client() is not None or not os.environ.get("TENUO_CONNECT_TOKEN"):
        return get_or_create()
    try:
        import tenuo_cloud
    except ImportError:
        logger.warning(
            "hermes-tenuo: TENUO_CONNECT_TOKEN is set but tenuo[cloud] is not "
            "installed; decisions stream to the control plane without signed "
            "receipts. %s",
            "Signed receipts need Python 3.13 or earlier until tenuo-cloud supports 3.14."
            if sys.version_info >= (3, 14) else "Install it with: pip install 'hermes-tenuo[cloud]'",
        )
        return get_or_create()
    try:
        from tenuo.control_plane import connect

        cloud = tenuo_cloud.connect(claim=False, apply_env=False)
        client = connect(
            receipt_sink=tenuo_cloud.CloudReceiptSink(cloud),
            on_receipt_error=_log_receipt_error,
        )
    except Exception as exc:  # noqa: BLE001 - receipts must not block startup
        logger.warning(
            "hermes-tenuo: Cloud receipts unavailable (%s); continuing without them",
            _safe_error_message(exc),
        )
        return get_or_create()
    atexit.register(_flush_receipts, client, _EXIT_FLUSH_SECS)
    return client


def _flush_receipts(client: Any, timeout: float) -> None:
    flush = getattr(client, "flush_receipts", None)
    if not callable(flush):
        return
    try:
        if not flush(timeout=timeout):
            logger.warning("hermes-tenuo: receipts still pending after %.0fs", timeout)
    except Exception as exc:  # noqa: BLE001
        logger.warning("hermes-tenuo: receipt flush failed: %s", _safe_error_message(exc))


@dataclass
class _ChildGrant:
    """A warrant granted to one delegated child, waiting for its session id."""
    warrant: Any
    chain: List[Any]        # ancestor warrants, root first
    key: Any                # the child's own signing key
    goal: Optional[str]     # the task goal, matched against subagent_start
    invocation_id: str = ""  # originating delegate_task tool_call_id


def _toolset_list(value: Any) -> Optional[List[str]]:
    """None when no toolsets were named; otherwise the names as a list."""
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return []


def _is_delegation_spawn(tool_name: str, args: Dict[str, Any]) -> bool:
    action = str(args.get("action") or "").strip().lower()
    return tool_name.removeprefix("tool:") == "delegate_task" and action in {"", "spawn"}


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


def _alias_is_no_broader(warrant: Any, exact: str, alternate: str) -> bool:
    """Whether *alternate* is a safe substitute for *exact* in one warrant."""
    capabilities = warrant.capabilities or {}
    exact_args = capabilities.get(exact)
    alternate_args = capabilities.get(alternate)
    if exact_args is None or alternate_args is None:
        return False
    if not _allows_unknown_args(warrant, exact) and _allows_unknown_args(warrant, alternate):
        return False
    if not set(exact_args).issubset(alternate_args):
        return False
    try:
        for name, parent_constraint in exact_args.items():
            parent_constraint.validate_attenuation(alternate_args[name])
    except Exception:
        return False
    return True


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

    A session's own warrant lasts until it is replaced, cleared, or expires.
    Hermes fires ``on_session_end`` after every turn, so that hook does not
    remove it. A session that once held its own warrant never falls back to
    the config warrant.
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
        access_policy: Optional[Any] = None,
        ingress: Optional[Any] = None,
    ):
        self._static_warrant = warrant
        self._static_signing_key = signing_key
        # Role-based access (hermes_tenuo.access): a gateway turn resolves to its
        # sender's role warrant per call. None means single-warrant mode.
        self._access_policy = access_policy
        # Protected A2A ingress (hermes_tenuo.a2a_ingress): an inbound A2A turn runs only on the
        # grant its sender delegated to this agent, verified at ingress. None: A2A turns are not
        # treated specially.
        self._ingress = ingress
        # session id → trusted roots of the A2A grant bound to it
        self._ingress_roots: Dict[str, List[Any]] = {}
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
        # Cancelled workers may announce children late. Never reuse their goals.
        self._cancelled_goals: Dict[str, set] = {}
        self._cancelled_invocations: set = set()
        self._audit_only_warned = False  # warn once when running without a warrant
        # More than one warrant is in play (a gateway session or a delegated child).
        self._uses_session_warrants = False

        # Session warrant registry: session_id → (warrant, signing_key)
        self._session_warrants: Dict[str, Tuple[Any, Optional[Any]]] = {}
        self._session_lock = threading.Lock()
        # Both are queues: OrderedDict removes the front entry in constant
        # time, where a plain dict rescans the slots of removed entries.
        # Delegated children that still hold a live grant, oldest first.
        self._child_sessions: "OrderedDict[str, None]" = OrderedDict()
        # Sessions holding a no-authority marker, oldest first (bounded).
        self._denied_sessions: "OrderedDict[str, None]" = OrderedDict()
        # Set once a marker has been evicted. From then on a session with no
        # warrant of its own is denied instead of using the config warrant,
        # because it may be a session whose marker is gone.
        self._denied_sessions_saturated = False

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
        # Once the table is full, unknown task IDs remain fail-closed instead
        # of evicting live ambiguity information and later trusting a singleton.
        self._task_attribution_saturated = False

        # Pre-hook decisions: tool_call_id → (allowed, reason)
        # Stored by pre_tool_call so post_tool_call can record the accurate outcome.
        self._pre_decisions: Dict[str, Tuple[bool, str]] = {}
        self._pre_decisions_lock = threading.Lock()
        # The same, for calls Hermes sends without a tool-call id: keyed by the
        # call itself. Each entry is (thread id, allowed, reason), one per
        # invocation in flight, since identical calls may run concurrently.
        self._unkeyed_decisions: "OrderedDict[str, deque]" = OrderedDict()

        # Connect to control plane (auto-discovers from env if not already connected);
        # adds signed Cloud receipts when the optional SDK is installed.
        self._control_plane = _connect_control_plane()

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

        The warrant stays attached across turns until it is replaced or
        ``clear_session_warrant`` is called.
        """
        with self._session_lock:
            self._bind_session(session_id, warrant, signing_key, parent_warrant)
        logger.debug("hermes-tenuo: registered warrant for session %s", session_id)

    def clear_session_warrant(self, session_id: str) -> None:
        """Remove *session_id*'s own warrant. The session is denied from then on.

        It does not fall back to the config warrant: a session that was given
        a narrower warrant must not gain a wider one by losing it. Call
        ``set_session_warrant`` again to give the session authority.
        """
        with self._session_lock:
            if session_id in self._session_warrants:
                self._deny_session(session_id, _RETIRED)

    # Bounded so a long-lived process does not keep a marker per session for ever.
    # Overflow fails closed: see ``_denied_sessions_saturated``.
    _MAX_DENIED_SESSIONS = 65536

    def _bind_session(
        self, session_id: str, warrant: Any, signing_key: Optional[Any], parent_warrant: Optional[Any] = None,
    ) -> None:
        """Give *session_id* its own warrant. Caller holds ``_session_lock``."""
        self._session_warrants[session_id] = (warrant, signing_key)
        self._uses_session_warrants = True
        self._denied_sessions.pop(session_id, None)
        self._child_sessions.pop(session_id, None)
        if parent_warrant is not None:
            self._session_warrant_chains[session_id] = (
                list(parent_warrant) if isinstance(parent_warrant, (list, tuple)) else [parent_warrant]
            )
        else:
            self._session_warrant_chains.pop(session_id, None)

    def _deny_session(self, session_id: str, marker: Any) -> None:
        """Replace *session_id*'s warrant with a no-authority marker. Caller holds ``_session_lock``."""
        self._session_warrants[session_id] = (marker, None)
        self._uses_session_warrants = True
        self._session_warrant_chains.pop(session_id, None)
        self._child_sessions.pop(session_id, None)
        self._denied_sessions.pop(session_id, None)
        self._denied_sessions[session_id] = None
        while len(self._denied_sessions) > self._MAX_DENIED_SESSIONS:
            oldest, _ = self._denied_sessions.popitem(last=False)
            self._session_warrants.pop(oldest, None)
            if not self._denied_sessions_saturated:
                self._denied_sessions_saturated = True
                logger.error(
                    "hermes-tenuo: more than %d sessions have been denied; sessions with no "
                    "warrant of their own are blocked and delegate_task is refused until "
                    "Hermes restarts",
                    self._MAX_DENIED_SESSIONS,
                )

    @property
    def _overflowed(self) -> bool:
        """Whether a denied session can no longer be told from an unknown one.

        From then on no session gains authority implicitly: not the config
        warrant, not a staged child grant. Only ``set_session_warrant`` does.
        This holds with or without a config warrant, since where unknown
        sessions pass through (require_session_warrant off) an evicted session
        would too. A guard that never used a warrant cannot be saturated and
        stays a no-op.
        """
        return self._denied_sessions_saturated and (
            self._static_warrant is not None or self._uses_session_warrants
        )

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

        Steps 2 and 3 are skipped once the denied-session record has overflowed.
        """
        with self._session_lock:
            entry = self._session_warrants.get(session_id)
        if entry is not None:
            return entry

        # Once a marker has been evicted, a session with no warrant of its own
        # may be one that was denied. It gets nothing — not a role warrant, not a
        # staged child grant below, and not the config warrant. Explicit bindings
        # above still win; this fail-closed guard comes before access resolution.
        if self._overflowed:
            return _UNTRACKED, None

        # Role-based access governs identified gateway turns. The warrant follows
        # the message's sender (not the session), so a shared group chat is
        # authorised per message; a sender no role grants is blocked, never
        # falling through to a broader warrant. A turn with no gateway identity
        # (CLI / local) is left to the resolution below.
        if self._access_policy is not None:
            from hermes_tenuo.access import current_sender
            ident = current_sender()
            if ident is not None:
                warrant, key = self._access_policy.warrant_for(**ident)
                return (warrant, key) if warrant is not None else (_NO_ROLE, None)

        if self._access_policy is None and self._planned_children and not self._saw_subagent_start:
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

    def _delegating_warrant(self, session_id: str) -> Tuple[Optional[Any], Optional[Any]]:
        """The warrant a ``delegate_task`` call in *session_id* delegates from.

        A child's grant is capped to its parent's expiry. A role warrant is
        shared and renewed on a schedule, so it is minted afresh here: the
        child gets the full lifetime whenever in that schedule it starts.
        """
        with self._session_lock:
            bound = session_id in self._session_warrants
        if not bound and not self._overflowed and self._access_policy is not None:
            from hermes_tenuo.access import current_sender
            ident = current_sender()
            if ident is not None:
                warrant, key = self._access_policy.warrant_for(**ident, fresh=True)
                return (warrant, key) if warrant is not None else (_NO_ROLE, None)
        return self._resolve_warrant(session_id)

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
            # Also support a literal tool name and the conventional prefix
            # form ("web" covers "web_search"). This keeps custom tools
            # usable whether or not Hermes's toolset registry is importable.
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
        self, parent_session_id: str, tasks: List[Tuple[Optional[str], Optional[List[str]]]],
        invocation_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Grant one warrant per delegated task from the parent's warrant; block if impossible.

        With ``child_warrant`` configured, each child gets that scope, granted
        under the parent so the hop verifies as a chain. Without it, the child
        keeps the parent's scope (Hermes children inherit the parent's
        toolsets). Toolsets named on the call narrow either one further.
        Every child gets a fresh key that only it holds.
        """
        from tenuo import SigningKey

        parent_warrant, parent_key = self._delegating_warrant(parent_session_id)
        if parent_warrant is None or _marker_reason(parent_warrant) or parent_key is None:
            return {"action": "block", "message": "tenuo: no warrant to delegate from in this session"}
        chain = self._chain_for(parent_session_id) + [parent_warrant]
        parent_tools = list(parent_warrant.tools or [])
        grants = []
        goal_scopes: Dict[str, frozenset[str]] = {}
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
                if goal is not None:
                    scope = frozenset(keep)
                    prior_scope = goal_scopes.setdefault(goal, scope)
                    if prior_scope != scope:
                        return {
                            "action": "block",
                            "message": (
                                "tenuo: delegation rejected: duplicate child goals "
                                "have different authority"
                            ),
                        }
                child_key = SigningKey.generate()
                builder = parent_warrant.attenuate_builder()
                builder.inherit_all()
                builder.retain_tools(sorted(keep))
                if child_caps is not None:
                    for tool in sorted(keep):
                        builder.with_capability(tool, child_caps[tool])
                builder.with_holder(child_key.public_key)
                # This is an atomic cap in the signed delegation operation. It
                # cannot accidentally request a lifetime beyond the parent.
                builder.with_ttl_capped_to_parent(ttl)
                if "delegate_task" not in {t.removeprefix("tool:") for t in keep}:
                    # The child can't delegate, so its grant can't be delegated either.
                    builder.terminal()
                child = builder.delegate(parent_key)
                logger.info(
                    "hermes-tenuo: delegation scope: parent has %d tools, child gets %s",
                    len(parent_tools), sorted(keep),
                )
                grants.append(_ChildGrant(child, chain, child_key, goal, invocation_id))
        except Exception as exc:
            error_type = type(exc).__name__
            logger.warning("hermes-tenuo: delegation grant failed (%s)", error_type)
            return {"action": "block", "message": f"tenuo: delegation rejected ({error_type})"}
        return self._stage_grants(parent_session_id, grants)

    def _register_planned_children(
        self, parent_session_id: str, tasks: List[Tuple[Optional[str], Optional[List[str]]]],
        invocation_id: str = "",
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
        parent_warrant, parent_key = self._delegating_warrant(parent_session_id)
        if parent_warrant is None or _marker_reason(parent_warrant) or parent_key is None:
            return {"action": "block", "message": "tenuo: no warrant to delegate from in this session"}
        chain = self._chain_for(parent_session_id) + [parent_warrant]
        try:
            planned = []
            goal_scopes: Dict[str, frozenset[str]] = {}
            level_tools = plan.constraints_for(depth)
            available_tools = list(level_tools)
            for goal, toolsets in tasks:
                keep = set(available_tools)
                if toolsets is not None:
                    keep &= self._tools_for_toolsets(toolsets, available_tools)
                if not keep:
                    return {
                        "action": "block",
                        "message": (
                            "tenuo: delegation rejected: the child would hold no tools"
                            + (f" (toolsets={toolsets})" if toolsets is not None else "")
                        ),
                    }
                if goal is not None:
                    scope = frozenset(keep)
                    prior_scope = goal_scopes.setdefault(goal, scope)
                    if prior_scope != scope:
                        return {
                            "action": "block",
                            "message": (
                                "tenuo: delegation rejected: duplicate child goals "
                                "have different authority"
                            ),
                        }
                child_key = SigningKey.generate()
                builder = parent_warrant.attenuate_builder()
                builder.inherit_all()
                builder.retain_tools(sorted(keep))
                for tool in sorted(keep):
                    tool_args = level_tools[tool]
                    if tool_args:
                        builder.with_capability(tool, tool_args)
                builder.with_holder(child_key.public_key)
                builder.with_ttl_capped_to_parent(level.ttl_seconds)
                if "delegate_task" not in {t.removeprefix("tool:") for t in keep}:
                    # The child can't delegate, so its grant can't be delegated either.
                    builder.terminal()
                planned.append(_ChildGrant(builder.delegate(parent_key), chain, child_key, goal, invocation_id))
        except Exception as exc:
            error_type = type(exc).__name__
            logger.warning("hermes-tenuo: delegation plan grant failed at depth %d (%s)", depth, error_type)
            return {
                "action": "block",
                "message": f"tenuo: delegation to depth {depth} rejected ({error_type})",
            }
        return self._stage_grants(parent_session_id, planned)

    def _stage_grants(
        self, parent_session_id: str, grants: List["_ChildGrant"]
    ) -> Optional[Dict[str, Any]]:
        if self._overflowed:
            # A child could not be told from a denied session replaying its start.
            return {
                "action": "block",
                "message": (
                    "tenuo: delegation rejected: too many sessions have been denied to "
                    "attach a child safely; restart Hermes"
                ),
            }
        # subagent_start carries a goal, but no originating tool-call ID.
        # Never let two outstanding invocations compete for the same goal.
        with self._pending_lock:
            if any((parent_session_id, g.invocation_id) in self._cancelled_invocations for g in grants):
                return {"action": "block", "message": "tenuo: delegation invocation was cancelled"}
            cancelled = self._cancelled_goals.get(parent_session_id, set())
            if cancelled and any(None in cancelled or g.goal is None or g.goal in cancelled for g in grants):
                return {
                    "action": "block",
                    "message": "tenuo: delegation rejected: cancelled child goal cannot be reused; use a distinct goal",
                }
            pending = self._planned_children.setdefault(parent_session_id, deque())
            if pending and any(
                not old.invocation_id or not new.invocation_id
                or old.invocation_id == new.invocation_id
                or old.goal is None or new.goal is None or old.goal == new.goal
                for old in pending for new in grants
            ):
                return {
                    "action": "block",
                    "message": "tenuo: delegation rejected: an outstanding invocation has ambiguous child goals",
                }
            pending.extend(grants)
        return None

    def _finish_delegation(
        self,
        session_id: str,
        invocation_id: str,
        status: str = "",
        args: Optional[dict] = None,
        error_type: str = "",
    ) -> None:
        # Normal returns occur after child construction. Cancellation/timeout
        # posts can precede worker exit, so reserve those goals permanently for
        # this guard. Session-end must not erase protection against late hooks.
        abandoned = status in {"cancelled", "timeout"} or (
            status == "error" and error_type != "tool_error"
        )
        with self._pending_lock:
            pending = self._planned_children.get(session_id)
            if abandoned:
                self._cancelled_invocations.add((session_id, invocation_id))
                goals = {goal for goal, _ in _delegated_tasks(args or {})}
                self._cancelled_goals.setdefault(session_id, set()).update(goals)
            if pending is not None:
                if abandoned:
                    goals = {g.goal for g in pending if g.invocation_id == invocation_id}
                    if goals:
                        self._cancelled_goals.setdefault(session_id, set()).update(goals)
                remaining = deque(g for g in pending if g.invocation_id != invocation_id)
                if remaining:
                    self._planned_children[session_id] = remaining
                else:
                    self._planned_children.pop(session_id, None)

    def _claim_child_grant(
        self, parent_session_id: str, goal: Optional[str] = None
    ) -> Optional["_ChildGrant"]:
        """Take the staged grant for the next child of *parent_session_id*.

        With *goal* (Hermes passes the child's goal to ``subagent_start``) only
        a grant staged for that goal matches. Without it, grants are taken in
        task order, which is the order Hermes builds the children in.
        """
        with self._pending_lock:
            cancelled = self._cancelled_goals.get(parent_session_id, set())
            if cancelled and (goal is None or None in cancelled or goal in cancelled):
                return None
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

    # Children examined for an expired grant on each attach. The scan rotates
    # through the live children, so the work under the lock stays constant
    # however many there are.
    _CHILD_SWEEP = 32

    def _attach_child(self, child_session_id: str, grant: "_ChildGrant") -> None:
        with self._session_lock:
            # A child keeps its grant for as long as it runs, across turns.
            # Drop the key material of children whose grant has expired; they
            # stay denied instead of falling back to the config warrant.
            for _ in range(min(len(self._child_sessions), self._CHILD_SWEEP)):
                session_id, _ = self._child_sessions.popitem(last=False)
                warrant, _key = self._session_warrants.get(session_id, (None, None))
                try:
                    expired = warrant is None or warrant.is_expired()
                except Exception:
                    expired = True
                if expired:
                    self._deny_session(session_id, _RETIRED)
                else:
                    self._child_sessions[session_id] = None  # back of the rotation
            self._bind_session(child_session_id, grant.warrant, grant.key, grant.chain)
            self._child_sessions[child_session_id] = None

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
        """Called when Hermes fires on_session_end, which is after every turn.

        The session may run again (a gateway user's next message, a child's
        correction turn), so its own warrant and chain stay attached. Only
        per-turn state is dropped here.
        """
        # Reset primary if this was the primary session, so the next session
        # is correctly identified as a new primary rather than a child.
        with self._primary_lock:
            if self._primary_session_id == session_id:
                self._primary_session_id = None
        with self._pending_lock:
            abandoned = self._planned_children.pop(session_id, ())
            if abandoned:
                self._cancelled_goals.setdefault(session_id, set()).update(g.goal for g in abandoned)
                self._cancelled_invocations.update((session_id, g.invocation_id) for g in abandoned)
        with self._task_lock:
            for task_id in [t for t, s in self._task_sessions.items() if session_id in s]:
                self._task_sessions[task_id].discard(session_id)
                if not self._task_sessions[task_id]:
                    del self._task_sessions[task_id]
        if self._control_plane is not None:
            _flush_receipts(self._control_plane, _SESSION_END_FLUSH_SECS)

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
        with self._session_lock:
            if child_session_id in self._session_warrants:
                # Hermes may replay lifecycle hooks. Never consume another
                # one-time grant or revoke an already attached child.
                return
        if child_task_id:
            # Hermes runs the child under this task id; execute_code calls made
            # by the child carry it without a session id.
            self._remember_task(child_task_id, child_session_id)

        if self._overflowed:
            # This may be a denied child whose marker was evicted, replaying
            # its start. It must not take a grant staged for another child.
            logger.warning(
                "hermes-tenuo: subagent %s (parent %s) gets no grant: the denied-session "
                "record has overflowed", child_session_id, parent_session_id,
            )
            return

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
        with self._session_lock:
            self._deny_session(child_session_id, _NO_AUTHORITY)

    # ------------------------------------------------------------------
    # Sessionless calls (execute_code): attribute by task id
    # ------------------------------------------------------------------

    _MAX_TASKS = 4096

    def _remember_task(self, task_id: str, session_id: str) -> None:
        with self._task_lock:
            sessions = self._task_sessions.get(task_id)
            if sessions is not None:
                sessions.add(session_id)
                return
            if len(self._task_sessions) >= self._MAX_TASKS:
                self._task_attribution_saturated = True
                return
            self._task_sessions[task_id] = {session_id}

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
        if not task_id and not self._uses_session_warrants:
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
            return self._block(tool_name, args, unattributed, session_id, task_id, tool_call_id)
        refusal = self._bind_ingress_grant(session_id)
        if refusal is not None:
            return self._block(tool_name, args, refusal, session_id, task_id, tool_call_id)
        warrant, signing_key = self._resolve_warrant(session_id)
        if self._access_policy is not None:
            from hermes_tenuo.access import current_sender, subagent_attribution_lookup
            lookup = subagent_attribution_lookup()
            child = lookup(task_id) if lookup is not None and task_id else None
            if child is not None:
                parent_id = child.get("parent_session_id")
                with self._session_lock:
                    bound = session_id in self._session_warrants
                    parent_bound = parent_id in self._session_warrants if parent_id else False
                # Only a positively identified, audit-only local parent permits
                # an unbound child. Static, explicit, and role authority all need
                # the narrowed grant; missing attribution cannot imply audit-only.
                if not bound and (current_sender() is not None or self._static_warrant is not None
                                  or parent_bound or not parent_id):
                    return self._block(tool_name, args,
                                       "tenuo: subagent has no bound delegation warrant; tool call blocked",
                                       session_id, task_id, tool_call_id)
            if _is_delegation_spawn(tool_name, args) and warrant is not None and lookup is None:
                return self._block(tool_name, args,
                                   "tenuo: access-mode delegation requires Hermes subagent attribution; upgrade Hermes",
                                   session_id, task_id, tool_call_id)
        reason = _marker_reason(warrant)
        if reason is not None:
            return self._block(tool_name, args, reason, session_id, task_id, tool_call_id)

        # Ensure primary session is tracked even before child sessions appear
        if session_id and self._primary_session_id is None:
            with self._primary_lock:
                if self._primary_session_id is None:
                    self._primary_session_id = session_id

        reason = self._denial_before_enforcement(warrant, signing_key)
        if reason is not None:
            return self._block(tool_name, args, reason, session_id, task_id, tool_call_id)

        # No warrant on this call: an unconfigured single-agent guard is a
        # documented no-op. In access mode this is only a non-gateway turn
        # (CLI/local) falling through — gateway turns are enforced by role, so
        # the audit-only warning would be misleading and is suppressed.
        if warrant is None:
            if self._access_policy is None and not self._audit_only_warned:
                self._audit_only_warned = True
                logger.warning(
                    "hermes-tenuo: AUDIT-ONLY — no warrant configured; all tool calls "
                    "pass through. Set TENUO_WARRANT to activate enforcement."
                )
            return None

        result, _ = self._enforce(tool_name, args, signing_key, warrant, session_id, task_id, tool_call_id)
        return result

    def _bind_ingress_grant(self, session_id: str) -> Optional[str]:
        """For an inbound A2A turn, bind its verified grant to the session; a refusal reason when
        it has none. Other turns are untouched (None).

        The grant is W_B, held by this agent: enforcement signs proof of possession with this
        agent's own A2A key and verifies the full chain from the grant's trusted roots. No
        static, role or child warrant can stand in for a missing grant."""
        ingress = self._ingress
        if ingress is None:
            return None
        turn = ingress.current_turn()
        if turn is None:
            return None
        grant = ingress.grant_for(*turn)
        if grant is None:
            return "tenuo: this A2A task carries no verified grant; tool call blocked"
        if not session_id:
            return "tenuo: an A2A tool call without a session cannot be matched to its grant"
        with self._session_lock:
            entry = self._session_warrants.get(session_id)
            bound = entry is not None and entry[0] is grant.warrant
            if not bound:
                self._bind_session(session_id, grant.warrant, ingress.own_key, list(grant.chain))
            self._ingress_roots[session_id] = list(ingress.trusted_roots)
        return None

    def delegation_authority(self, session_id: str) -> Tuple[List[Any], Optional[Any]]:
        """This session's own authority for delegating onward: (chain root-first ending with its
        warrant, its signing key), or ([], None) when it holds none. A delegated A2A turn delegates
        from its verified grant, so a further hop stays within it."""
        if self._bind_ingress_grant(session_id) is not None:
            return [], None
        warrant, key = self._resolve_warrant(session_id)
        if warrant is None or key is None or _marker_reason(warrant) is not None:
            return [], None
        return self._chain_for(session_id) + [warrant], key

    def _denial_before_enforcement(self, warrant: Any, signing_key: Optional[Any]) -> Optional[str]:
        """Why a call is blocked before the warrant is checked, or None if it is not.

        Shared by the pre and post hooks so a call blocked here is never
        recorded as allowed.
        """
        reason = _marker_reason(warrant)
        if reason is not None:
            return reason
        if warrant is None:
            # Role-governed children must not turn unrelated local audit-only
            # sessions into warrant-required sessions. An explicit requirement
            # still wins, as do denied/evicted-session markers checked above.
            if self._access_policy is not None and self._require_session_warrant is None:
                from hermes_tenuo.access import current_sender
                if current_sender() is None:
                    return None
            # A gateway that already called set_session_warrant is configured:
            # unknown sessions fail closed unless the operator sets
            # require_session_warrant=False.
            if self._session_warrant_required:
                return "tenuo: no warrant for this session — require_session_warrant is on"
            return None
        if signing_key is None:
            # Enforcement requires a signing key for Proof-of-Possession. Hard
            # block: a misconfigured install that silently passes through
            # defeats the point of running Tenuo at all.
            return "tenuo: TENUO_SIGNING_KEY not configured — all calls blocked until signing key is set"
        return None

    def _block(
        self, tool_name: str, args: Dict[str, Any], reason: str,
        session_id: str, task_id: str, tool_call_id: str,
    ) -> Dict[str, Any]:
        """Record a denial and return the block response for it."""
        self._emit_audit(tool_name, args, False, reason, session_id, task_id, tool_call_id)
        # Hermes may fire post_tool_call for a blocked call; it must carry this decision.
        self._remember_decision(tool_call_id, False, reason, (tool_name, args, session_id, task_id))
        return {"action": "block", "message": reason}

    def _enforce(
        self,
        tool_name: str,
        args: Dict[str, Any],
        signing_key: Any,
        warrant: Any,
        session_id: str,
        task_id: str,
        tool_call_id: str,
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        """Return the hook response and the actual authorization decision.

        Logging a denial may permit execution, but must never mint authority.
        """
        try:
            from tenuo._enforcement import enforce_tool_call
            from tenuo.config import resolve_trusted_roots

            bound = warrant.bind(signing_key)
            # For chain verification: use configured trusted_roots.
            # If not configured, extract the root from the parent warrant's issuer.
            chain = self._chain_for(session_id)
            with self._session_lock:
                ingress_roots = self._ingress_roots.get(session_id)
            if ingress_roots is not None:
                # An A2A grant is trusted only through the roots configured for A2A ingress.
                trusted = list(ingress_roots)
            else:
                with self._trusted_roots_lock:
                    trusted = resolve_trusted_roots(self._trusted_roots)
            # No fallback anchor: not the signing key, and not the issuer of a
            # warrant in the chain being verified. Deriving trust from the
            # credential under test accepts any chain an attacker signs. Without
            # a configured trusted_root, enforce_tool_call fails closed.
            # Preserve exact matches across the entire chain. If an ancestor
            # had an exact capability that the leaf dropped, falling back to a
            # broader alias would bypass the ancestor's restriction.
            authorization_tool = tool_name
            alternate = tool_name.removeprefix("tool:") if tool_name.startswith("tool:") else f"tool:{tool_name}"
            exact_ancestors = [item for item in chain if tool_name in (item.tools or [])]
            if tool_name not in (warrant.tools or []) and alternate in (warrant.tools or []):
                if not exact_ancestors or all(
                    _alias_is_no_broader(item, tool_name, alternate)
                    for item in exact_ancestors
                ):
                    authorization_tool = alternate
            result = enforce_tool_call(
                tool_name=authorization_tool,
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
            return self._block(
                tool_name, args, f"Authorization error: {exc}", session_id, task_id, tool_call_id,
            ), False

        # Grant validation is part of the effective delegation decision. Do it
        # before publishing any ALLOW, and never issue authority for log-only denials.
        grant_rejected = False
        if result.allowed and _is_delegation_spawn(tool_name, args):
            tasks = _delegated_tasks(args)
            if self._delegation_plan is not None:
                blocked = self._register_planned_children(session_id, tasks, tool_call_id)
            else:
                blocked = self._grant_children(session_id, tasks, tool_call_id)
            if blocked is not None:
                grant_rejected = True
                # A plugin policy refusal is not a Rust-attested authorization.
                result = replace(result, allowed=False, denial_reason=blocked["message"],
                                 error_type="delegation_rejected", chain_result=None)

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
            self._remember_decision(tool_call_id, False, reason, (tool_name, args, session_id, task_id))
            with self._session_lock:
                delegated_in = session_id in self._ingress_roots
            # A delegated A2A grant is always enforced: log-only mode never lets it through.
            if (self._on_denial == "log" and not grant_rejected and not delegated_in
                    and not _is_delegation_spawn(tool_name, args)):
                logger.warning("hermes-tenuo [BLOCKED-LOG] %s: %s", tool_name, reason)
                return None, False
            return {"action": "block", "message": reason}, False

        self._remember_decision(tool_call_id, True, "", (tool_name, args, session_id, task_id))
        return None, True

    _MAX_PENDING_DECISIONS = 2048

    @staticmethod
    def _call_key(call: Tuple[str, Dict[str, Any], str, str]) -> str:
        """Identify a call that has no tool-call id by what it is."""
        tool_name, args, session_id, task_id = call
        try:
            digest = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()
        except Exception:
            digest = ""
        return "\0".join((session_id, task_id, tool_name, digest))

    def _remember_decision(
        self, tool_call_id: str, allowed: bool, reason: str,
        call: Optional[Tuple[str, Dict[str, Any], str, str]] = None,
    ) -> None:
        """Stash the pre-hook decision for post_tool_call. Bounded: an older Hermes
        that never fires post for a blocked call must not leak memory.

        *call* is ``(tool_name, args, session_id, task_id)``; it stands in for
        the id when Hermes sends none, so the post record still carries this
        decision instead of being logged as an unobserved call.
        """
        with self._pre_decisions_lock:
            if tool_call_id:
                self._pre_decisions[tool_call_id] = (allowed, reason)
                while len(self._pre_decisions) > self._MAX_PENDING_DECISIONS:
                    self._pre_decisions.pop(next(iter(self._pre_decisions)))
            elif call is not None:
                key = self._call_key(call)
                pending = self._unkeyed_decisions.setdefault(key, deque(maxlen=64))
                # One thread runs one invocation at a time. An earlier entry
                # from this thread is the same invocation checked again (hook,
                # then registry) or one whose post never came: replace it.
                thread_id = threading.get_ident()
                for index in range(len(pending) - 1, -1, -1):
                    if pending[index][0] == thread_id:
                        del pending[index]
                        break
                pending.append((thread_id, allowed, reason))
                self._unkeyed_decisions.move_to_end(key)
                while len(self._unkeyed_decisions) > self._MAX_PENDING_DECISIONS:
                    self._unkeyed_decisions.popitem(last=False)

    def _take_decision(
        self, tool_call_id: str, call: Tuple[str, Dict[str, Any], str, str], blocked: bool = False,
    ) -> Optional[Tuple[bool, str]]:
        """The pre-hook decision for this post event, removed from the pending set.

        Without a tool-call id the match is by the call itself: this thread's
        own decision, else the oldest. A call Hermes reports as *blocked* did
        not run, so it only ever takes a denial (this thread's, else the
        newest); with none pending it takes nothing, and the caller records
        the block.
        """
        with self._pre_decisions_lock:
            if tool_call_id:
                return self._pre_decisions.pop(tool_call_id, None)
            key = self._call_key(call)
            pending = self._unkeyed_decisions.get(key)
            if not pending:
                return None
            newest_first = range(len(pending) - 1, -1, -1)
            thread_id = threading.get_ident()
            own = next((i for i in newest_first if pending[i][0] == thread_id), None)
            decision = None
            if not blocked:
                index = own if own is not None else 0
            elif own is not None and not pending[own][1]:
                index = own
            else:
                index = next((i for i in newest_first if not pending[i][1]), None)
            if index is not None:
                _, allowed, reason = pending[index]
                decision = (allowed, reason)
                del pending[index]
            elif own is not None:
                # This thread allowed the call and something else blocked it.
                # Drop the entry so it cannot be taken for a later call.
                del pending[own]
            if not pending:
                del self._unkeyed_decisions[key]
            return decision

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
        status: str = "",
        error_type: str = "",
    ) -> None:
        """Emit an audit event. Fires for every tool call, including audit-only mode."""
        # A recorded pre-hook denial wins even when no static warrant exists
        # (e.g. gateway-only session warrants). Never turn it into audit-only ALLOW.
        session_id, unattributed = self._attribute_session(session_id, task_id)
        pre = self._take_decision(
            tool_call_id, (tool_name, args, session_id, task_id), blocked=status == "blocked",
        )
        if pre is None and unattributed is not None:
            self._emit_audit(
                tool_name, args, False, unattributed,
                session_id, task_id, tool_call_id, duration_ms,
            )
            return
        if _is_delegation_spawn(tool_name, args) and unattributed is None:
            self._finish_delegation(session_id, tool_call_id, status, args, error_type)
        if pre is not None:
            allowed, reason = pre
            self._emit_audit(tool_name, args, allowed, reason, session_id, task_id, tool_call_id, duration_ms)
            return
        # No pre decision to go by. Hermes reports a call that was blocked
        # before its handler; that is never an allowed call.
        if status == "blocked":
            self._emit_audit(tool_name, args, False, "tenuo: blocked before the tool ran",
                             session_id, task_id, tool_call_id, duration_ms)
            return
        # A call the pre hook would have blocked outright is still a denial.
        warrant, signing_key = self._resolve_warrant(session_id)
        denial = self._denial_before_enforcement(warrant, signing_key)
        if denial is not None:
            self._emit_audit(tool_name, args, False, denial,
                             session_id, task_id, tool_call_id, duration_ms)
            return

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

        # No correlated pre decision: this is an unobserved post-dispatch event.
        self._emit_audit(tool_name, args, True, "post-dispatch", session_id, task_id, tool_call_id, duration_ms)

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
