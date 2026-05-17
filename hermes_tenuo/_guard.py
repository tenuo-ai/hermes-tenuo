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
        get_trusted_roots,
        get_warrant_raw,
        load_warrant,
    )

    connect_token = get_connect_token(ctx)
    warrant_raw = get_warrant_raw(ctx)
    if not connect_token and not warrant_raw:
        return None

    # Parse Cloud credentials if connect_token is present
    cloud_creds = None
    if connect_token:
        from hermes_tenuo._cloud import parse_connect_token
        cloud_creds = parse_connect_token(connect_token)
        if cloud_creds:
            try:
                from tenuo.control_plane import connect
                connect(token=connect_token)
            except Exception as exc:
                logger.warning("hermes-tenuo: Cloud connection failed: %s", exc)

    warrant = load_warrant(warrant_raw)
    child_warrant = load_warrant(get_child_warrant_raw(ctx))
    signing_key = get_signing_key(ctx)
    trusted_roots = get_trusted_roots(ctx)

    # Wire Cloud approval handler when connect_token is present
    approval_handler = None
    if cloud_creds and cloud_creds.api_key:
        try:
            from hermes_tenuo._cloud import make_cloud_approval_handler
            approval_handler = make_cloud_approval_handler(
                api_key=cloud_creds.api_key,
                endpoint=cloud_creds.endpoint,
                signing_key=signing_key,
            )
            logger.debug("hermes-tenuo: Cloud approval handler configured")
        except Exception as exc:
            logger.warning("hermes-tenuo: could not create approval handler: %s", exc)

    # Load trigger_map for session warrant delivery
    trigger_map = _get_trigger_map(ctx)

    from hermes_tenuo.hermes_guard import HermesGuard
    guard = HermesGuard(
        warrant=warrant,
        signing_key=signing_key,
        child_warrant=child_warrant,
        trusted_roots=trusted_roots,
        approval_handler=approval_handler,
    )

    return PluginGuard(guard, cloud_creds=cloud_creds, trigger_map=trigger_map)


def _get_trigger_map(ctx: Any) -> dict:
    """Read trigger_map from config: {role_or_key: trigger_id}."""
    try:
        from hermes_tenuo._config import _get_plugin_entry
        entry = _get_plugin_entry(ctx)
        trigger_map = entry.get("trigger_map") or {}
        return trigger_map if isinstance(trigger_map, dict) else {}
    except Exception:
        return {}


class PluginGuard:
    """Adapts Hermes hook signatures to HermesGuard methods."""

    def __init__(
        self,
        guard: "HermesGuard",
        cloud_creds: Optional[Any] = None,
        trigger_map: Optional[dict] = None,
    ):
        self._guard = guard
        self._cloud_creds = cloud_creds
        self._trigger_map = trigger_map or {}

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

        # Session warrant via trigger_map (gateway multi-user)
        # Hermes may pass user_role or similar kwargs in future versions.
        # Currently supported via explicit fire_session_warrant() call from gateway code.
        user_role = kwargs.get("user_role") or kwargs.get("role")
        if user_role and self._trigger_map and self._cloud_creds:
            trigger_id = self._trigger_map.get(user_role)
            if trigger_id:
                self._fire_trigger_for_session(session_id, trigger_id)

    def on_session_end_hook(
        self,
        session_id: str = "",
        **kwargs: Any,
    ) -> None:
        self._guard.on_session_end(session_id=session_id)

    def fire_session_warrant(self, session_id: str, trigger_id: str) -> bool:
        """Fire a Cloud trigger to get a warrant for a specific session.

        Call this from gateway orchestration code when a user session starts:
            guard.fire_session_warrant(session_id, trigger_id)

        Returns True on success, False on failure.
        """
        if not self._cloud_creds:
            logger.warning("hermes-tenuo: fire_session_warrant requires connect_token")
            return False
        return self._fire_trigger_for_session(session_id, trigger_id)

    def _fire_trigger_for_session(self, session_id: str, trigger_id: str) -> bool:
        """Internal: fire trigger and register the resulting warrant for session_id."""
        try:
            from hermes_tenuo._cloud import fire_trigger, CloudAPIError
            from hermes_tenuo._config import load_warrant, get_signing_key
            from hermes_tenuo._config import get_trusted_roots

            result = fire_trigger(
                trigger_id,
                api_key=self._cloud_creds.api_key,
                endpoint=self._cloud_creds.endpoint,
                event_data={"session_id": session_id},
            )
            warrant = load_warrant(result.warrant_b64)
            if warrant is None:
                logger.warning("hermes-tenuo: trigger returned empty warrant for session %s", session_id)
                return False

            # Derive trusted_root from the issued warrant itself
            signing_key = self._guard._static_signing_key
            self._guard.set_session_warrant(session_id, warrant, signing_key)

            # Update trusted_roots if we got an issuer from the warrant
            if result.trusted_root_b64 and self._guard._trusted_roots is None:
                try:
                    import base64
                    from tenuo_core import PublicKey
                    root = PublicKey.from_bytes(base64.b64decode(result.trusted_root_b64))
                    self._guard._trusted_roots = [root]
                except Exception:
                    pass

            logger.info(
                "hermes-tenuo: fired trigger %s for session %s (warrant_id=%s)",
                trigger_id, session_id, result.warrant_id,
            )
            return True
        except Exception as exc:
            logger.warning(
                "hermes-tenuo: failed to fire trigger %s for session %s: %s",
                trigger_id, session_id, exc,
            )
            return False
