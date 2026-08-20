"""
hermes-tenuo: Tenuo authorization plugin for Hermes Agent.

Hermes plugin entry point. Hermes calls register(ctx) at startup.

Install:
    pip install hermes-tenuo

Enable in ~/.hermes/config.yaml:
    plugins:
      enabled:
        - hermes-tenuo
      entries:
        hermes-tenuo:
          warrant: ~/.hermes/tenuo/warrant
          # connect_token: tc_live_...   # optional: Tenuo Cloud
"""

from __future__ import annotations

import logging
from typing import Any

from hermes_tenuo.hermes_guard import HermesGuard, HermesAuditEvent  # noqa: F401

logger = logging.getLogger("hermes_tenuo")


def _register_kanban_block_all(ctx: Any, task_id: str) -> None:
    """Install a block-all enforcement hook for a kanban worker with no warrant."""
    deny_msg = (
        f"hermes-tenuo: kanban worker '{task_id}' has no warrant — "
        "tool call blocked. Stage a task warrant before dispatching."
    )

    # Prefer ToolRegistry.set_enforcement_fn for bypass-immune coverage.
    try:
        from tools.registry import registry as _tr
        if hasattr(_tr, "set_enforcement_fn"):
            try:
                from tools.registry import EnforcementDenied
                _exc_cls = EnforcementDenied
            except ImportError:
                _exc_cls = PermissionError

            def _block_all_fn(tool_name: str, args: dict, **kwargs: Any) -> None:
                raise _exc_cls(deny_msg)

            _tr.set_enforcement_fn(_block_all_fn)
            logger.info("hermes-tenuo: block-all registered via ToolRegistry for kanban worker %s", task_id)
            return
    except Exception as exc:
        logger.debug("hermes-tenuo: ToolRegistry unavailable for block-all (%s), falling back to hook", exc)

    def _block_all_hook(tool_name: str = "", **kwargs: Any) -> dict:
        return {"action": "block", "message": deny_msg}

    ctx.register_hook("pre_tool_call", _block_all_hook)
    logger.info("hermes-tenuo: block-all hook registered for kanban worker %s", task_id)


def register(ctx: Any) -> None:
    """Called by Hermes plugin loader at startup."""
    from hermes_tenuo._guard import build_plugin_guard

    guard = build_plugin_guard(ctx)
    if guard is None:
        from hermes_tenuo.kanban import current_task_id
        kanban_task = current_task_id()
        if kanban_task:
            # Kanban worker with no task warrant — block every tool call so the
            # worker cannot proceed with the broader install-wide permissions.
            logger.error(
                "hermes-tenuo: kanban worker %s has no warrant — registering block-all enforcement",
                kanban_task,
            )
            _register_kanban_block_all(ctx, kanban_task)
        else:
            logger.debug("hermes-tenuo: no warrant or connect_token configured, plugin inactive")
        return

    # Primary enforcement: register directly with ToolRegistry for universal
    # coverage including execute_code sandbox (tenuo-ai/hermes-agent fork).
    # Falls back gracefully to the pre_tool_call hook on upstream Hermes.
    _registered_via_registry = False
    try:
        from tools.registry import registry as _tool_registry
        if hasattr(_tool_registry, "set_enforcement_fn"):
            def _enforcement_fn(tool_name: str, args: dict, **kwargs: Any) -> None:
                result = guard.pre_tool_call_hook(
                    tool_name=tool_name,
                    args=args,
                    task_id=str(kwargs.get("task_id") or ""),
                    session_id=str(kwargs.get("session_id") or ""),
                    tool_call_id=str(kwargs.get("tool_call_id") or ""),
                )
                if result and result.get("action") == "block":
                    # Use EnforcementDenied sentinel so the registry distinguishes
                    # a policy denial from a bug in the enforcement fn.
                    try:
                        from tools.registry import EnforcementDenied
                        raise EnforcementDenied(result.get("message", f"Tool '{tool_name}' not authorized"))
                    except ImportError:
                        # Upstream Hermes without EnforcementDenied — fall back to PermissionError
                        raise PermissionError(result.get("message", f"Tool '{tool_name}' not authorized"))

            _tool_registry.set_enforcement_fn(_enforcement_fn)
            _registered_via_registry = True
            logger.info("hermes-tenuo: enforcement registered via ToolRegistry (universal coverage)")
    except Exception as exc:
        logger.debug("hermes-tenuo: ToolRegistry enforcement unavailable (%s), using hook fallback", exc)

    # Always register pre_tool_call — it is the only enforcement path for tools
    # that run_agent.py intercepts before reaching the registry (delegate_task,
    # todo, memory, session_search).  set_enforcement_fn never fires for those.
    # For registry-dispatched tools both paths run; the hook fires first in the
    # agent loop and the enforcement fn fires inside dispatch() — defense in depth
    # with no double-audit (post_tool_call fires once, after the handler returns).
    ctx.register_hook("pre_tool_call", guard.pre_tool_call_hook)
    if not _registered_via_registry:
        logger.debug("hermes-tenuo: pre_tool_call hook is sole enforcement path (no registry enforcement fn)")

    ctx.register_hook("post_tool_call", guard.post_tool_call_hook)
    ctx.register_hook("on_session_start", guard.on_session_start_hook)
    ctx.register_hook("on_session_end", guard.on_session_end_hook)
    ctx.register_hook("subagent_start", guard.on_subagent_start_hook)

    mode = "enforcing" if guard.has_warrant else "audit-only"
    if mode == "audit-only":
        logger.warning(
            "hermes-tenuo: running in AUDIT-ONLY mode — all tool calls are logged "
            "but NOT blocked. Set TENUO_WARRANT (or warrant: in config) to activate "
            "enforcement. This mode is intended only for initial warrant-builder "
            "on-ramp; do not use in production without a warrant."
        )
    else:
        logger.info("hermes-tenuo: active (%s)", mode)
