"""Warrant checks for Hermes Agent tool calls.

``HermesGuard.pre_tool_call`` runs on every tool name and argument dict
before the handler. It returns ``{"action": "block", "message": ...}``
or ``None``. ``post_tool_call`` writes the local audit record.

Typical use is the plugin entry point. You can also construct
``HermesGuard`` in tests and scripts (see ``hermes-tenuo demo``).

Invariants:
    - Agents consume warrants; they do not mint them.
    - ``delegate_task`` children get a grant from the parent (``grant_builder``
      or attenuation). Pass ``parent_warrant`` into ``set_session_warrant``
      so the hop is verified as a chain.
    - Concurrent gateway sessions must use ``set_session_warrant`` per
      session with independently minted warrants. The single-agent child
      heuristic is not safe there.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes_tenuo")


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
        After the parent call is allowed, attach a grant from the parent
        warrant (``grant_builder`` or ``subagent_start`` attenuation) with
        ``set_session_warrant(..., parent_warrant=parent)`` so the chain
        is verified.

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
        self._audit_only_warned = False  # warn once when running without a warrant
        self._uses_session_warrants = False  # set by set_session_warrant (gateway)

        # Session warrant registry: session_id → (warrant, signing_key)
        self._session_warrants: Dict[str, Tuple[Any, Optional[Any]]] = {}
        self._session_lock = threading.Lock()

        # Session warrant chains: session_id → parent_warrant for chain verification
        self._session_warrant_chains: Dict[str, Any] = {}
        self._primary_session_id: Optional[str] = None
        self._primary_lock = threading.Lock()

        # Pending child warrants: (parent_session_id, task_index) → warrant
        self._pending_child_warrants: Dict[Tuple[str, int], Any] = {}
        self._pending_lock = threading.Lock()

        # Per-parent child counter for task_index assignment
        self._child_counters: Dict[str, int] = {}
        self._counter_lock = threading.Lock()

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
                self._session_warrant_chains[session_id] = parent_warrant
        logger.debug("hermes-tenuo: registered warrant for session %s", session_id)

    def clear_session_warrant(self, session_id: str) -> None:
        with self._session_lock:
            self._session_warrants.pop(session_id, None)
            self._session_warrant_chains.pop(session_id, None)

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

        if self._child_warrant is not None or self._pending_child_warrants:
            # Lock ordering: _primary_lock → _pending_lock → _counter_lock → _session_lock.
            # Acquire _primary_lock to determine the child warrant, then release it
            # before touching _session_lock (set_session_warrant / _session_warrant_chains).
            child_w = None
            parent_w = None
            is_child_session = False

            with self._primary_lock:
                if self._primary_session_id is None and session_id:
                    self._primary_session_id = session_id
                elif self._primary_session_id != session_id and session_id:
                    # V1 LIMITATION: single-parent-session only.
                    # This heuristic is ONLY safe for single-agent deployments
                    # (CLI / cron) where one parent runs at a time.
                    # For multi-user gateways, use set_session_warrant() per
                    # session instead — explicit session warrants bypass this
                    # branch entirely (the session-registry lookup above).
                    # subagent_start (wired Jun 2026) injects child warrants before
                    # the first tool call, making this path a fallback for older builds.
                    pending = self._claim_child_warrant(self._primary_session_id)
                    if pending is not None:
                        is_child_session = True
                        if isinstance(pending, tuple):
                            child_w, parent_w = pending
                        else:
                            child_w = pending
                    # Note: if pending is None (no delegation happened for this primary),
                    # this session is treated as a new independent session and falls
                    # through to _static_warrant. We intentionally do NOT fall back to
                    # _child_warrant here: a session with no pending warrant is a
                    # concurrent parent session, not a child, so giving it _child_warrant
                    # (potentially narrower or broader) would be wrong. The _child_warrant
                    # fallback only applies inside _attenuate_for_toolsets when delegation
                    # is actually in progress.
            # _primary_lock released — now safe to acquire _session_lock

            if is_child_session and child_w is not None:
                if parent_w is not None:
                    with self._session_lock:
                        self._session_warrant_chains[session_id] = parent_w
                self.set_session_warrant(session_id, child_w, self._static_signing_key)
                return child_w, self._static_signing_key

        return self._static_warrant, self._static_signing_key

    # ------------------------------------------------------------------
    # delegate_task child warrant pre-registration
    # ------------------------------------------------------------------

    def _attenuate_for_toolsets(
        self,
        parent_warrant: Any,
        toolsets: List[str],
        signing_key: Any,
    ) -> Optional[Any]:
        """Attenuate the parent warrant to only the tools in the given Hermes toolsets.

        Uses parent_warrant.attenuate_builder() with inherit_all() so all parent
        constraints are preserved — the child cannot exceed the parent's scope.
        """
        try:
            # Resolve toolset names → Hermes tool names
            requested_tools: set = set()
            resolution_failed = False
            for ts in (toolsets or []):
                try:
                    from toolsets import resolve_toolset
                    requested_tools.update(resolve_toolset(ts))
                except ImportError:
                    resolution_failed = True
                    break
                except Exception:
                    pass

            # Get parent's authorized tool names
            parent_tools = set(parent_warrant.tools or [])

            # Determine which tools to keep in the child
            if requested_tools:
                # Map bare names to tool: prefixed names used on some warrants
                keep = set()
                for bare in requested_tools:
                    for candidate in (f"tool:{bare}", bare):
                        if candidate in parent_tools:
                            keep.add(candidate)
            elif not toolsets:
                # No toolsets specified → child keeps the parent's tools
                keep = parent_tools
            elif resolution_failed:
                # Hermes toolsets module unavailable — match toolset names as prefixes
                # e.g. "web" matches "tool:web_search", "tool:web_extract"
                keep = set()
                for ts in toolsets:
                    for t in parent_tools:
                        bare = t.removeprefix("tool:")
                        if bare == ts or bare.startswith(ts + "_") or bare.startswith(ts):
                            keep.add(t)
            else:
                # Toolsets were named but none resolved to a parent tool
                # (typo, empty toolset). Do not widen the child to the parent.
                keep = set()

            if not keep:
                logger.warning(
                    "hermes-tenuo: toolsets %s matched no parent tools — "
                    "not widening the child to the parent's full scope",
                    toolsets,
                )
                return self._child_warrant

            # Build attenuated child via attenuate_builder:
            # inherit_all() preserves all parent constraints (avoids monotonicity violations)
            # with_tools() whitelists only the requested tools
            b = parent_warrant.attenuate_builder()
            b.inherit_all()
            b.with_tools(sorted(keep))
            # TTL is capped at parent's remaining lifetime by the Rust core
            # (I3: child.exp <= parent.exp) — passing 3600 is a requested maximum.
            b.with_ttl(3600)
            child = b.delegate(signing_key)

            # Log scope reduction clearly — important for demo and audit
            parent_tool_count = len(set(parent_warrant.tools or []))
            logger.info(
                "hermes-tenuo: delegation scope — parent has %d tools, child gets %d "
                "(toolsets=%s, tools=%s)",
                parent_tool_count,
                len(keep),
                toolsets,
                sorted(keep),
            )
            return child

        except Exception as exc:
            logger.warning("hermes-tenuo: attenuation failed (%s), using static child_warrant", exc)
            return self._child_warrant

    def _register_child_warrants(
        self, parent_session_id: str, task_count: int, toolsets: Optional[List[str]] = None
    ) -> None:
        """Pre-register attenuated warrants for upcoming child sessions.

        If toolsets is provided, dynamically attenuates the parent warrant.
        The parent warrant is stored alongside the child so enforcement can
        pass the full delegation chain to enforce_tool_call (warrant_chain=[parent]).
        """
        parent_warrant, signing_key = self._resolve_warrant(parent_session_id)

        # Try dynamic attenuation first if we have both parent warrant and signing key
        if parent_warrant and signing_key and (toolsets is not None or self._child_warrant is None):
            child = self._attenuate_for_toolsets(parent_warrant, toolsets or [], signing_key)
        elif self._child_warrant:
            child = self._child_warrant
            parent_warrant = None  # no chain for static child_warrant
        else:
            return

        if child is None:
            return

        with self._pending_lock:
            for i in range(task_count):
                # Store (child_warrant, parent_warrant) so enforcement can use
                # the full chain: warrant_chain=[parent] + child as leaf
                self._pending_child_warrants[(parent_session_id, i)] = (child, parent_warrant)
        logger.debug(
            "hermes-tenuo: pre-registered %d child warrant(s) for session %s (chain=%s)",
            task_count, parent_session_id, parent_warrant is not None,
        )

    def _claim_child_warrant(
        self, parent_session_id: str
    ) -> Optional[Any]:
        """Claim the next pending child warrant for this parent (FIFO by task_index).

        Returns the child warrant (or a (child, parent) tuple if chain is available).
        """
        with self._counter_lock:
            idx = self._child_counters.get(parent_session_id, 0)
            self._child_counters[parent_session_id] = idx + 1
        with self._pending_lock:
            return self._pending_child_warrants.pop((parent_session_id, idx), None)

    # ------------------------------------------------------------------
    # Hook: on_session_start / on_session_end
    # ------------------------------------------------------------------

    def on_session_start(
        self,
        session_id: str,
        parent_session_id: Optional[str] = None,
        task_index: Optional[int] = None,
    ) -> None:
        """Called when Hermes fires on_session_start (fired since upstream commit 455bf2e, Mar 2026).

        Passes session_id, model, and platform. Does not pass parent_session_id —
        use the subagent_start hook for child-session warrant injection.
        """
        # on_session_start fires but without parent_session_id, so this branch only
        # applies if Hermes ever adds that kwarg. The subagent_start hook is the
        # authoritative path for child warrant injection today.
        if parent_session_id and self._child_warrant:
            claimed = self._claim_child_warrant(parent_session_id)
            if isinstance(claimed, tuple):
                child_w, parent_w = claimed
            else:
                child_w, parent_w = claimed, None
            warrant = child_w or self._child_warrant
            if parent_w is not None:
                with self._session_lock:
                    self._session_warrant_chains[session_id] = parent_w
            self.set_session_warrant(session_id, warrant, self._static_signing_key)
            logger.debug(
                "hermes-tenuo: on_session_start fired — child session %s registered "
                "(parent=%s, chain=%s)",
                session_id, parent_session_id, parent_w is not None,
            )

    def on_session_end(self, session_id: str) -> None:
        self.clear_session_warrant(session_id)
        with self._counter_lock:
            self._child_counters.pop(session_id, None)
        # Reset primary if this was the primary session, so the next session
        # is correctly identified as a new primary rather than a child.
        with self._primary_lock:
            if self._primary_session_id == session_id:
                self._primary_session_id = None
        with self._session_lock:
            self._session_warrant_chains.pop(session_id, None)

    # ------------------------------------------------------------------
    # Hook: subagent_start
    # ------------------------------------------------------------------

    def on_subagent_start(
        self,
        parent_session_id: Optional[str],
        child_session_id: Optional[str],
        **_kwargs: Any,
    ) -> None:
        """Called when Hermes fires subagent_start (upstream delegate_tool.py, Jun 2026).

        This is the authoritative injection point for child-session warrants: both
        parent and child session IDs are known before the child runs any tool calls.
        Takes precedence over the heuristic in _resolve_warrant for delegate_task children.
        """
        if not parent_session_id or not child_session_id:
            return

        # Prefer a pre-registered pending warrant (staged in pre_tool_call when
        # delegate_task was authorised) — these carry task-specific attenuation.
        pending = self._claim_child_warrant(parent_session_id)
        if pending is not None:
            child_w, parent_w = (pending if isinstance(pending, tuple) else (pending, None))
            if parent_w is not None:
                with self._session_lock:
                    self._session_warrant_chains[child_session_id] = parent_w
            self.set_session_warrant(child_session_id, child_w, self._static_signing_key)
            logger.debug(
                "hermes-tenuo: subagent_start — child %s registered from pending warrant (parent=%s)",
                child_session_id, parent_session_id,
            )
            return

        # No pending warrant — attenuate live from the parent's warrant.
        parent_warrant, signing_key = self._resolve_warrant(parent_session_id)
        if parent_warrant is None:
            logger.debug(
                "hermes-tenuo: subagent_start — no warrant for parent %s; child %s falls through to static",
                parent_session_id, child_session_id,
            )
            return
        child_w = self._attenuate_for_toolsets(parent_warrant, [], signing_key)
        if child_w is None:
            return
        with self._session_lock:
            self._session_warrant_chains[child_session_id] = parent_warrant
        self.set_session_warrant(child_session_id, child_w, signing_key)
        logger.debug(
            "hermes-tenuo: subagent_start — child %s attenuated from parent %s",
            child_session_id, parent_session_id,
        )

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
        warrant, signing_key = self._resolve_warrant(session_id)

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
            tasks = args.get("tasks") or []
            task_count = len(tasks) if isinstance(tasks, list) else 1
            toolsets = args.get("toolsets") or []
            self._register_child_warrants(session_id, task_count, toolsets=toolsets)

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
            with self._session_lock:
                parent_warrant = self._session_warrant_chains.get(session_id)
            with self._trusted_roots_lock:
                trusted = resolve_trusted_roots(self._trusted_roots)
            if trusted is None and parent_warrant is not None:
                # Derive trusted root from the parent's issuer.
                try:
                    if parent_warrant.issuer is not None:
                        trusted = [parent_warrant.issuer]
                except Exception:
                    pass
            # No signing_key.public_key fallback here: without an explicit trusted
            # root anchor we must fail closed and let enforce_tool_call reject the
            # warrant rather than silently accepting a self-issued one.
            result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=args,
                bound_warrant=bound,
                trusted_roots=trusted,
                warrant_chain=[parent_warrant] if parent_warrant is not None else None,
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
