"""
Bridge between Hermes plugin hooks and tenuo.hermes.HermesGuard.

build_plugin_guard() reads Hermes config, constructs HermesGuard,
and returns a PluginGuard that wraps hook signatures.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("hermes_tenuo._guard")


def build_plugin_guard(ctx: Any) -> Optional["PluginGuard"]:
    """Read config and build the guard. Returns None if not configured."""
    from hermes_tenuo._config import (
        get_connect_token,
        get_child_warrant_raw,
        get_signing_key,
        get_warrant_raw,
        load_warrant,
    )

    connect_token = get_connect_token(ctx)
    if not connect_token:
        return None

    # Connect to Tenuo Cloud — starts background heartbeat, enables audit
    try:
        from tenuo.control_plane import connect
        connect(token=connect_token)
    except Exception as exc:
        logger.warning("hermes-tenuo: Cloud connection failed: %s", exc)
        # Continue — enforcement can still run locally without Cloud

    warrant = load_warrant(get_warrant_raw(ctx))
    child_warrant = load_warrant(get_child_warrant_raw(ctx))
    signing_key = get_signing_key(ctx)

    from hermes_tenuo.hermes_guard import HermesGuard
    guard = HermesGuard(
        warrant=warrant,
        signing_key=signing_key,
        child_warrant=child_warrant,
    )

    return PluginGuard(guard)


class PluginGuard:
    """Adapts Hermes hook signatures to HermesGuard methods."""

    def __init__(self, guard: "HermesGuard"):
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
        return result  # None = allow, {"action": "block", "message": "..."} = block

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
