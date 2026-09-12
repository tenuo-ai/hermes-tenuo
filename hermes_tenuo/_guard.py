"""
Bridge between Hermes plugin hooks and tenuo.hermes.HermesGuard.

build_plugin_guard() reads Hermes config, constructs HermesGuard,
and returns a PluginGuard that wraps hook signatures.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from hermes_tenuo.hermes_guard import HermesGuard

logger = logging.getLogger("hermes_tenuo._guard")


def build_plugin_guard(ctx: Any) -> Optional["PluginGuard"]:
    """Read config and build the guard. Returns None if not configured."""
    from hermes_tenuo._config import (
        get_audit_log_path,
        get_child_warrant_raw,
        get_on_denial,
        get_require_session_warrant,
        get_signing_key,
        get_trusted_roots,
        get_warrant_raw,
        load_warrant,
    )

    warrant_raw = get_warrant_raw(ctx)
    if not warrant_raw:
        return None

    warrant = load_warrant(warrant_raw)
    child_warrant = load_warrant(get_child_warrant_raw(ctx))
    signing_key = get_signing_key(ctx)
    trusted_roots = get_trusted_roots(ctx)
    on_denial = get_on_denial(ctx)

    audit_callback = None
    audit_path = get_audit_log_path(ctx)
    if audit_path is not None:
        from hermes_tenuo.audit import LocalAuditLog
        audit_callback = LocalAuditLog(audit_path)
        logger.debug("hermes-tenuo: audit log at %s", audit_path)

    guard = HermesGuard(
        warrant=warrant,
        signing_key=signing_key,
        child_warrant=child_warrant,
        trusted_roots=trusted_roots,
        on_denial=on_denial,
        audit_callback=audit_callback,
        require_session_warrant=get_require_session_warrant(ctx),
    )

    return PluginGuard(guard)


class PluginGuard:
    """Adapts Hermes hook signatures to HermesGuard methods."""

    def __init__(self, guard: HermesGuard):
        self._guard = guard

    @property
    def has_warrant(self) -> bool:
        return self._guard.has_warrant

    def pre_tool_call_hook(
        self,
        tool_name: str = "",
        args: Optional[dict] = None,
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
        **kwargs: Any,
    ) -> Optional[dict]:
        result = self._guard.pre_tool_call(
            tool_name=tool_name,
            args=args or {},
            task_id=task_id,
            session_id=session_id,
            tool_call_id=tool_call_id,
        )
        if result and result.get("action") == "block":
            self._auto_block_kanban_task(tool_name, result.get("message", ""))
        return result  # None = allow, {"action": "block", "message": "..."} = block

    @staticmethod
    def _auto_block_kanban_task(tool_name: str, deny_message: str) -> None:
        """If this is a kanban worker, mark the task blocked on the board.

        A direct kanban_db write (not a kanban_block tool dispatch) so the
        system event does not re-enter the enforcement fn and does not need
        kanban_block to be in the worker's warrant. Idempotent: subsequent
        denials on an already-blocked task are no-ops.
        """
        from hermes_tenuo.kanban import current_task_id, block_task

        kanban_task = current_task_id()
        if not kanban_task:
            return
        reason = f"warrant denied {tool_name}: {deny_message}".strip()
        if block_task(kanban_task, reason):
            logger.warning(
                "hermes-tenuo: auto-blocked kanban task %s (%s)",
                kanban_task, reason,
            )

    def post_tool_call_hook(
        self,
        tool_name: str = "",
        args: Optional[dict] = None,
        result: str = "",
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
        duration_ms: int = 0,
        **kwargs: Any,
    ) -> None:
        self._guard.post_tool_call(
            tool_name=tool_name,
            args=args or {},
            result=result,
            task_id=task_id,
            session_id=session_id,
            tool_call_id=tool_call_id,
            duration_ms=duration_ms,
        )

    def on_session_start_hook(
        self,
        session_id: str = "",
        **kwargs: Any,
    ) -> None:
        parent_session_id = kwargs.get("parent_session_id")
        task_index = kwargs.get("task_index")
        self._guard.on_session_start(
            session_id=session_id,
            parent_session_id=parent_session_id,
            task_index=task_index,
        )

    def on_session_end_hook(
        self,
        session_id: str = "",
        **kwargs: Any,
    ) -> None:
        self._guard.on_session_end(session_id=session_id)

    def on_subagent_start_hook(
        self,
        parent_session_id: str = "",
        child_session_id: str = "",
        **kwargs: Any,
    ) -> None:
        self._guard.on_subagent_start(
            parent_session_id=parent_session_id or None,
            child_session_id=child_session_id or None,
        )

    # ------------------------------------------------------------------
    # Gateway proxy helpers (forward to inner HermesGuard)
    # ------------------------------------------------------------------

    def set_session_warrant(
        self,
        session_id: str,
        warrant: Any,
        signing_key: Optional[Any] = None,
        *,
        parent_warrant: Optional[Any] = None,
    ) -> None:
        """Forward to HermesGuard.set_session_warrant (gateway / child grant)."""
        self._guard.set_session_warrant(
            session_id, warrant, signing_key, parent_warrant=parent_warrant
        )

    def clear_session_warrant(self, session_id: str) -> None:
        """Forward to HermesGuard.clear_session_warrant (gateway use)."""
        self._guard.clear_session_warrant(session_id)

    def set_trusted_roots(self, roots: Optional[Any]) -> None:
        """Forward to HermesGuard.set_trusted_roots (thread-safe)."""
        self._guard.set_trusted_roots(roots)
