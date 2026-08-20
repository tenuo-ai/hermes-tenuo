"""
Config resolution for hermes-tenuo.

Priority order for each setting:
  1. Hermes config.yaml: plugins.entries.hermes-tenuo.<key>
  2. Environment variable fallback
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path
from typing import Any, List, Optional

logger = logging.getLogger("hermes_tenuo._config")

_PLUGIN_KEY = "hermes-tenuo"


def _get_plugin_entry(ctx: Any) -> dict:
    """Read plugins.entries.hermes-tenuo from Hermes config.yaml."""
    try:
        from hermes_cli.config import load_config
        config = load_config() or {}
        plugins_cfg = config.get("plugins") or {}
        entries = plugins_cfg.get("entries") or {}
        entry = entries.get(_PLUGIN_KEY) or {}
        return entry if isinstance(entry, dict) else {}
    except Exception as exc:
        logger.debug("Could not read Hermes config: %s", exc)
        return {}


def get_connect_token(ctx: Any) -> Optional[str]:
    entry = _get_plugin_entry(ctx)
    return (
        entry.get("connect_token")
        or os.environ.get("TENUO_CONNECT_TOKEN")
    )


def _looks_like_path(s: str) -> bool:
    """Return True if the string looks like a file path rather than base64 data."""
    return (
        len(s) < 256  # max filename length on most filesystems
        and (s.startswith("/") or s.startswith("~") or s.startswith("."))
    )


def get_warrant_raw(ctx: Any) -> Optional[str]:
    """Return raw warrant: base64 string or path to warrant file.

    When this process is a kanban worker (HERMES_KANBAN_TASK set), a staged
    per-task warrant takes precedence over the global warrant. Workers are
    scoped to their task, period — the install-wide warrant does not apply.
    """
    from hermes_tenuo.kanban import current_task_id, load_task_warrant_raw

    task_id = current_task_id()
    if task_id:
        task_raw = load_task_warrant_raw(task_id)
        if task_raw:
            logger.info(
                "loaded task warrant for kanban worker (task_id=%s)", task_id,
            )
            return task_raw
        # Fail closed: a kanban worker scoped to a task must not inherit the
        # install-wide warrant.  Returning None here causes build_plugin_guard
        # to return None (no warrant, no connect_token), and register() will
        # install a block-all pre_tool_call hook so the worker cannot proceed.
        logger.error(
            "kanban worker %s has no staged task warrant — all tool calls will be blocked. "
            "Stage a warrant at ~/.hermes/tenuo/warrants/%s.warrant before dispatching.",
            task_id, task_id,
        )
        return None

    entry = _get_plugin_entry(ctx)
    raw = entry.get("warrant") or os.environ.get("TENUO_WARRANT")
    if not raw:
        return None
    if _looks_like_path(raw):
        path = Path(raw).expanduser()
        if path.exists():
            return path.read_text().strip()
    return raw


def get_child_warrant_raw(ctx: Any) -> Optional[str]:
    """Return child warrant for delegate_task subagents."""
    entry = _get_plugin_entry(ctx)
    raw = entry.get("child_warrant") or os.environ.get("TENUO_CHILD_WARRANT")
    if not raw:
        return None
    if _looks_like_path(raw):
        path = Path(raw).expanduser()
        if path.exists():
            return path.read_text().strip()
    return raw


def get_signing_key(ctx: Any):
    """Return SigningKey from env or config, or None."""
    entry = _get_plugin_entry(ctx)
    key_env = entry.get("signing_key_env", "TENUO_SIGNING_KEY")
    raw = os.environ.get(key_env)
    if not raw:
        return None
    try:
        from tenuo_core import SigningKey
        return SigningKey.from_bytes(base64.b64decode(raw))
    except Exception as exc:
        logger.warning("hermes-tenuo: could not load signing key: %s", exc)
        return None


def get_trusted_roots(ctx: Any) -> Optional[List[Any]]:
    """Return list of trusted PublicKeys from env or config, or None."""
    entry = _get_plugin_entry(ctx)
    raw = entry.get("trusted_root") or os.environ.get("TENUO_TRUSTED_ROOT")
    if not raw:
        return None
    try:
        from tenuo_core import PublicKey
        roots = []
        for r in raw.split(","):
            r = r.strip()
            if r:
                roots.append(PublicKey.from_bytes(base64.b64decode(r)))
        return roots if roots else None
    except Exception as exc:
        logger.warning("hermes-tenuo: could not load trusted_root: %s", exc)
        return None


def get_on_denial(ctx: Any) -> str:
    """Return on_denial mode: 'block' (default) or 'log' (audit — log but don't block)."""
    entry = _get_plugin_entry(ctx)
    return entry.get("on_denial", "block")


def load_warrant(raw: Optional[str]):
    """Deserialise a base64 warrant string into a Warrant object."""
    if not raw:
        return None
    try:
        from tenuo_core import Warrant
        padded = raw + "=" * (-len(raw) % 4)
        data = base64.urlsafe_b64decode(padded)
        return Warrant.from_bytes(data)
    except Exception as exc:
        logger.warning("hermes-tenuo: could not load warrant: %s", exc)
        return None
