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
          connect_token: tc_live_...   # paste from Tenuo Cloud dashboard
          # warrant: ~/.hermes/tenuo/warrant  # optional: activates enforcement
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger("hermes_tenuo")


def register(ctx: Any) -> None:
    """Called by Hermes plugin loader at startup."""
    from hermes_tenuo._guard import build_plugin_guard

    guard = build_plugin_guard(ctx)
    if guard is None:
        logger.debug("hermes-tenuo: no connect_token configured, plugin inactive")
        return

    ctx.register_hook("pre_tool_call", guard.pre_tool_call_hook)
    ctx.register_hook("post_tool_call", guard.post_tool_call_hook)
    ctx.register_hook("on_session_start", guard.on_session_start_hook)
    ctx.register_hook("on_session_end", guard.on_session_end_hook)

    mode = "enforcing" if guard.has_warrant else "audit-only"
    logger.info("hermes-tenuo: active (%s)", mode)
