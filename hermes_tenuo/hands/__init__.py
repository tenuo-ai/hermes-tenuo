"""Hands: let a Hermes agent on a server use a folder on your own machine.

`hermes-tenuo hands up` on the machine dials out to the server plugin and hands it a
warrant for one folder and a time window. The plugin adds a `hands` terminal backend
and a `/hands` chat command. Off unless `hands.listen` is configured.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("hermes_tenuo.hands")


def settings(ctx: Any) -> dict:
    from hermes_tenuo._config import _get_plugin_entry
    entry = _get_plugin_entry(ctx).get("hands") or {}
    entry = dict(entry) if isinstance(entry, dict) else {}
    if os.environ.get("TENUO_HANDS_LISTEN"):
        entry.setdefault("listen", os.environ["TENUO_HANDS_LISTEN"])
    if os.environ.get("TENUO_HANDS_URL"):
        entry.setdefault("url", os.environ["TENUO_HANDS_URL"])
    return entry


def register(ctx: Any) -> bool:
    """Start Hands in this Hermes process if it is configured. True when it is on."""
    from hermes_tenuo.hands import chat
    ctx.register_hook("pre_llm_call", chat.before_turn)
    ctx.register_command("hands", chat.command, description="Connect a folder on your own machine",
                         args_hint="setup [read|edit|online] | invite | verify | on [name] | off | status | revoke <name>")
    prompt = getattr(ctx, "register_system_prompt_section", None)
    if prompt is not None:
        prompt("hands", chat.CONTEXT)
    config = settings(ctx)
    listen = str(config.get("listen") or "").strip()
    if not listen:
        return False
    register_provider = getattr(ctx, "register_terminal_environment_provider", None)
    if register_provider is None:
        logger.warning("hermes-tenuo hands: this Hermes version has no terminal backend plugins; Hands is off")
        return False
    from hermes_tenuo.hands import chat
    from hermes_tenuo.hands.hub import start_hub
    hub = start_hub(listen, str(config.get("url") or ""))
    if hub is None:
        return False
    hub.joined = chat.joined
    from hermes_tenuo.hands.backend import HandsProvider
    register_provider(HandsProvider())
    register_middleware = getattr(ctx, "register_middleware", None)
    if register_middleware is not None:
        register_middleware("tool_execution", chat.around_tool)
        chat.can_switch = True
        chat.restore()  # conversations keep the machine they were using before a restart
    logger.info("hermes-tenuo hands: listening on %s", listen)
    return True
