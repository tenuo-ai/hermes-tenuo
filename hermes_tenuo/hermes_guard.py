"""
Tenuo Hermes Agent Integration

Provides warrant-based authorization for Hermes Agent tool calls via the
Hermes plugin hook system.

Primary usage is through the hermes-tenuo plugin package (pip install hermes-tenuo).
HermesGuard can also be used directly for programmatic setups.

Architecture:
    Every Hermes tool call flows through handle_function_call() in model_tools.py,
    which fires pre_tool_call hooks before dispatch and post_tool_call hooks after.
    HermesGuard.pre_tool_call() enforces the warrant; post_tool_call() emits audit
    events to Tenuo Cloud.

Audit-first on-ramp:
    Set TENUO_CONNECT_TOKEN to start streaming tool calls to Cloud immediately.
    Enforcement activates once TENUO_WARRANT is set (or warrant= is passed directly).
    Cloud's warrant builder learns from real call patterns and generates tight warrants.

    Install:
        pip install hermes-tenuo

    Minimal config (~/.hermes/config.yaml):
        plugins:
          enabled:
            - hermes-tenuo
          entries:
            hermes-tenuo:
              connect_token: tc_live_...

Security invariants:
    - Agents are warrant consumers, never warrant requesters.
    - TENUO_WARRANT must not be set from within agent tool context.
    - Child warrants for delegate_task subagents are pre-registered by the
      plugin before delegate_task runs, keyed by (parent_session_id, task_index).
    - Children inherit the child_warrant config or an attenuated warrant —
      never the parent's root warrant.
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
    decision: str           # "ALLOW" | "DENY" | "AUDIT"
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
# HermesGuard
# ---------------------------------------------------------------------------

class HermesGuard:
    """
    Authorization guard for Hermes Agent tool calls.

    Wires into Hermes's pre_tool_call and post_tool_call plugin hooks.
    In audit-only mode (no warrant configured), every tool call is logged
    to Tenuo Cloud for warrant builder learning. Enforcement activates
    once a warrant is present.

    Session warrant registry supports per-session warrants for multi-user
    gateway deployments (different warrant per Telegram/Discord user).

    delegate_task interception: when tool_name == "delegate_task", the guard
    pre-registers attenuated child warrants keyed by (parent_session_id, task_index)
    so children never inherit the parent's root authority.
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
    ):
        self._static_warrant = warrant
        self._static_signing_key = signing_key
        self._child_warrant = child_warrant
        self._trusted_roots = trusted_roots
        self._trusted_roots_lock = threading.Lock()
        self._on_denial = on_denial
        self._audit_callback = audit_callback
        self._approval_handler = approval_handler
        self._audit_only_warned = False  # warn once when running without a warrant

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

        # Connect to control plane (auto-discovers from env if not already connected)
        from tenuo.control_plane import get_or_create
        self._control_plane = get_or_create()

    @property
    def has_warrant(self) -> bool:
        return self._static_warrant is not None

    # ------------------------------------------------------------------
    # Session warrant management (gateway multi-user)
    # ------------------------------------------------------------------

    def set_session_warrant(
        self,
        session_id: str,
        warrant: Any,
        signing_key: Optional[Any] = None,
    ) -> None:
        with self._session_lock:
            self._session_warrants[session_id] = (warrant, signing_key)
        logger.debug("hermes-tenuo: registered warrant for session %s", session_id)

    def clear_session_warrant(self, session_id: str) -> None:
        with self._session_lock:
            self._session_warrants.pop(session_id, None)

    def set_trusted_roots(self, roots: Optional[List[Any]]) -> None:
        """Thread-safe replacement of the trusted root set.

        Call this after receiving a Cloud-issued warrant to install the issuer
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
        1. Explicit session warrant (set via set_session_warrant — gateway use case)
        2. Child warrant fallback — if child_warrant is configured and session_id
           is not the primary session, treat as a subagent session. This works
           because on_session_start is not currently fired by Hermes (it is in
           VALID_HOOKS but has no invoke_hook call), so child warrants cannot be
           pre-injected per-session at start time. Instead we detect child sessions
           heuristically: the first session_id seen is treated as the primary session;
           all subsequent different session_ids are child sessions.
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
                    # V1 LIMITATION: single-parent-session only. If two parent sessions
                    # run concurrently (same process, e.g. gateway), the second parent is
                    # misidentified as a child of the first. Mitigated by on_session_end
                    # resetting _primary_session_id. The correct fix is on_session_start
                    # with parent_session_id (not currently emitted by Hermes).
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
                # Map bare names to tool: prefixed names used in Cloud warrants
                keep = set()
                for bare in requested_tools:
                    for candidate in (f"tool:{bare}", bare):
                        if candidate in parent_tools:
                            keep.add(candidate)
            elif toolsets and resolution_failed:
                # Hermes toolsets module unavailable — match toolset names as prefixes
                # e.g. "web" matches "tool:web_search", "tool:web_extract"
                keep = set()
                for ts in toolsets:
                    for t in parent_tools:
                        bare = t.removeprefix("tool:")
                        if bare == ts or bare.startswith(ts + "_") or bare.startswith(ts):
                            keep.add(t)
                if not keep:
                    keep = parent_tools  # full fallback if nothing matched
            else:
                # No toolsets specified (or Hermes toolsets module unavailable)
                # → child gets all parent tools
                keep = parent_tools

            if not keep:
                logger.debug("hermes-tenuo: no overlapping tools for child — using static child_warrant")
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
        """Called if Hermes fires on_session_start (currently not fired — kept for future compatibility)."""
        # on_session_start is in VALID_HOOKS but Hermes does not currently fire it.
        # Child warrant injection uses the heuristic in _resolve_warrant instead.
        # If a future Hermes version fires this with parent_session_id, the explicit
        # session warrant registration here will take precedence over the heuristic.
        if parent_session_id and self._child_warrant:
            child_warrant = self._claim_child_warrant(parent_session_id)
            warrant = child_warrant or self._child_warrant
            self.set_session_warrant(session_id, warrant, self._static_signing_key)
            logger.debug(
                "hermes-tenuo: on_session_start fired — child session %s registered (parent=%s)",
                session_id, parent_session_id,
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
        # Intercept delegate_task to pre-register attenuated child warrants
        if tool_name == "delegate_task":
            tasks = args.get("tasks") or []
            task_count = len(tasks) if isinstance(tasks, list) else 1
            toolsets = args.get("toolsets") or []
            self._register_child_warrants(session_id, task_count, toolsets=toolsets)

        warrant, signing_key = self._resolve_warrant(session_id)

        # Ensure primary session is tracked even before child sessions appear
        if session_id and self._primary_session_id is None:
            with self._primary_lock:
                if self._primary_session_id is None:
                    self._primary_session_id = session_id

        # Audit-only mode: no warrant configured — pass through, emit later
        if warrant is None:
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

        # Normalize tool name to match the warrant's capability naming convention.
        # Cloud trigger UI emits "tool:web_search"; Hermes calls "web_search".
        # Normalize once here so enforcement never sees a double-denial.
        effective_tool_name = self._normalize_tool_name(tool_name, warrant)

        return self._enforce(effective_tool_name, args, signing_key, warrant, session_id, task_id, tool_call_id)

    def _normalize_tool_name(self, tool_name: str, warrant: Any) -> str:
        """Map the incoming Hermes tool name to the warrant's capability name.

        Cloud triggers use a namespaced convention ("tool:web_search") while Hermes
        uses bare names ("web_search"). This is a bridge layer — one lookup against
        the warrant's tool list, no double enforcement. When Cloud warrant issuance
        moves to bare names, delete this method and call _enforce directly.
        """
        if warrant is None:
            return tool_name
        tools = set(warrant.tools or [])
        if tool_name in tools:
            return tool_name
        prefixed = f"tool:{tool_name}"
        if prefixed in tools:
            return prefixed
        return tool_name

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
            # For chain verification: use configured trusted_roots (Cloud's key).
            # If not configured, extract the root from the parent warrant's issuer
            # field — the parent was Cloud-signed, so parent.issuer IS Cloud's key.
            with self._session_lock:
                parent_warrant = self._session_warrant_chains.get(session_id)
            with self._trusted_roots_lock:
                trusted = resolve_trusted_roots(self._trusted_roots)
            if trusted is None and parent_warrant is not None:
                # Derive trusted root from the parent's issuer (the Cloud signing key)
                try:
                    if parent_warrant.issuer is not None:
                        trusted = [parent_warrant.issuer]
                except Exception:
                    pass
            if trusted is None and signing_key is not None:
                # Last resort: trust the agent's own key (covers static child_warrant)
                try:
                    trusted = [signing_key.public_key]
                except Exception:
                    pass
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
            reason = result.denial_reason or f"Tool '{tool_name}' not authorized"
            if self._on_denial == "log":
                logger.warning("hermes-tenuo [BLOCKED-LOG] %s: %s", tool_name, reason)
                return None
            return {"action": "block", "message": reason}

        return None

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
        """Emit audit event to Cloud. Fires for every tool call, including audit-only mode."""
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

        # If enforcement ran in pre_tool_call, post_tool_call is observational only
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
