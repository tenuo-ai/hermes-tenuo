"""
Config resolution for hermes-tenuo.

Priority order for each setting:
  1. Hermes config.yaml: plugins.entries.hermes-tenuo.<key>
  2. Environment / profile secret scope (see ``_env_secret``)
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path
from typing import Any, List, Optional

logger = logging.getLogger("hermes_tenuo._config")

_PLUGIN_KEY = "hermes-tenuo"


def _env_secret(name: str) -> Optional[str]:
    """Resolve a Tenuo credential without leaking another Hermes profile's env.

    Under ``gateway.multiplex_profiles`` (Hermes #108319 / #108748, Sep 2026)
    profile secrets live in a contextvar scope, not ``os.environ``. Reading
    ``os.environ`` on a secondary-profile turn would return the launch
    profile's ``TENUO_*`` values. ``get_secret`` is fail-closed: a miss or
    an unscoped read never falls through to another profile.

    On older Hermes (no ``agent.secret_scope``) or single-profile runs,
    this is ``os.environ.get``.
    """
    try:
        from agent.secret_scope import UnscopedSecretError, get_secret
    except ImportError:
        return os.environ.get(name)
    try:
        return get_secret(name)
    except UnscopedSecretError:
        logger.debug(
            "hermes-tenuo: %s unscoped under multiplex — treating as unset",
            name,
        )
        return None


def _get_plugin_entry(ctx: Any) -> dict:
    """Read plugins.entries.hermes-tenuo from Hermes config (see ``_home.load_hermes_config``)."""
    try:
        from hermes_tenuo._home import load_hermes_config
        config = load_hermes_config()
        plugins_cfg = config.get("plugins") or {}
        entries = plugins_cfg.get("entries") or {}
        entry = entries.get(_PLUGIN_KEY) or {}
        return entry if isinstance(entry, dict) else {}
    except Exception as exc:
        logger.debug("Could not read Hermes config: %s", exc)
        return {}


def _looks_like_path(s: str) -> bool:
    """Return True if the string looks like a file path rather than base64 data."""
    return (
        len(s) < 256  # max filename length on most filesystems
        and (s.startswith("/") or s.startswith("~") or s.startswith("."))
    )


def resolve_warrant_text(ctx: Any) -> tuple[Optional[str], str]:
    """Return ``(raw, source)`` using the same order the plugin loads at runtime.

    Kanban workers prefer the staged task warrant and never inherit the
    install-wide value. A configured path that does not exist raises
    ``FileNotFoundError``.
    """
    from hermes_tenuo.kanban import current_task_id, load_task_warrant_raw, task_warrant_path

    task_id = current_task_id()
    if task_id:
        path = task_warrant_path(task_id)
        task_raw = load_task_warrant_raw(task_id)
        if task_raw:
            logger.info(
                "loaded task warrant for kanban worker (task_id=%s)", task_id,
            )
            return task_raw, f"file: {path} (kanban {task_id})"
        # Fail closed: a kanban worker scoped to a task must not inherit the
        # install-wide warrant. Returning None here causes build_plugin_guard
        # to return None (no warrant), and register() will
        # install a block-all pre_tool_call hook so the worker cannot proceed.
        logger.error(
            "kanban worker %s has no staged task warrant — all tool calls will be blocked. "
            "Stage a warrant at ~/.hermes/tenuo/warrants/%s.warrant before dispatching.",
            task_id, task_id,
        )
        return None, f"kanban: {path} (missing)"

    entry = _get_plugin_entry(ctx)
    if entry.get("warrant"):
        raw = str(entry.get("warrant"))
        source = "config: warrant"
    else:
        raw = _env_secret("TENUO_WARRANT")
        source = "env: TENUO_WARRANT"
    if not raw:
        return None, "none"
    if _looks_like_path(raw):
        path = Path(raw).expanduser()
        if not path.exists():
            raise FileNotFoundError(str(path))
        return path.read_text().strip(), f"{source} -> {path}"
    return raw, source


def get_warrant_raw(ctx: Any) -> Optional[str]:
    """Return raw warrant: base64 string or contents of a warrant file."""
    try:
        raw, _ = resolve_warrant_text(ctx)
        return raw
    except FileNotFoundError as exc:
        logger.warning("hermes-tenuo: warrant path does not exist: %s", exc)
        return None


def get_child_warrant_raw(ctx: Any) -> Optional[str]:
    """Return child warrant for delegate_task subagents."""
    entry = _get_plugin_entry(ctx)
    raw = entry.get("child_warrant") or _env_secret("TENUO_CHILD_WARRANT")
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
    raw = _env_secret(key_env)
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
    raw = entry.get("trusted_root") or _env_secret("TENUO_TRUSTED_ROOT")
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


def get_audit_log_path(ctx: Any):
    """Return the local audit log path, or None when disabled.

    ``plugins.entries.hermes-tenuo.audit_log`` (or ``TENUO_AUDIT_LOG``) may be a
    path, or ``false`` / ``off`` to disable. Unset means the default
    ``$HERMES_HOME/tenuo/audit.jsonl``.
    """
    from hermes_tenuo.audit import default_audit_path
    entry = _get_plugin_entry(ctx)
    raw = entry.get("audit_log", None)
    if raw is None:
        raw = _env_secret("TENUO_AUDIT_LOG")
    if raw is None or raw == "":
        return default_audit_path()
    if raw is False or (isinstance(raw, str) and raw.strip().lower() in ("false", "off", "no", "0", "none")):
        return None
    from pathlib import Path
    return Path(str(raw)).expanduser()


def get_on_denial(ctx: Any) -> str:
    """Return on_denial mode: 'block' (default) or 'log' (audit — log but don't block)."""
    entry = _get_plugin_entry(ctx)
    return entry.get("on_denial", "block")


def get_require_session_warrant(ctx: Any) -> Optional[bool]:
    """Return the session-warrant gate, or None for the auto default.

    Auto (unset) turns the gate on once ``set_session_warrant`` has been
    used. ``true`` / ``false`` override that.
    """
    entry = _get_plugin_entry(ctx)
    raw = entry.get("require_session_warrant")
    if raw is None:
        raw = _env_secret("TENUO_REQUIRE_SESSION_WARRANT")
    if raw is None or raw == "":
        return None
    if raw is True or (isinstance(raw, str) and raw.strip().lower() in ("true", "on", "yes", "1")):
        return True
    if raw is False or (isinstance(raw, str) and raw.strip().lower() in ("false", "off", "no", "0")):
        return False
    logger.warning("hermes-tenuo: unknown require_session_warrant value %r — using auto", raw)
    return None


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
