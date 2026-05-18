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


def register(ctx: Any) -> None:
    """Called by Hermes plugin loader at startup."""
    from hermes_tenuo._guard import build_plugin_guard

    guard = build_plugin_guard(ctx)
    if guard is None:
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

    if not _registered_via_registry:
        # Fallback: pre_tool_call hook (upstream Hermes — no execute_code coverage)
        ctx.register_hook("pre_tool_call", guard.pre_tool_call_hook)

    ctx.register_hook("post_tool_call", guard.post_tool_call_hook)
    ctx.register_hook("on_session_start", guard.on_session_start_hook)
    ctx.register_hook("on_session_end", guard.on_session_end_hook)

    mode = "enforcing" if guard.has_warrant else "audit-only"
    logger.info("hermes-tenuo: active (%s)", mode)
