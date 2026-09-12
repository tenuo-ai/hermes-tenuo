"""
Per-task warrants for Hermes Kanban workers.

Convention:
  - Each kanban task gets its own warrant at
    ~/.hermes/tenuo/warrants/<task_id>.warrant
  - The plugin auto-loads the matching warrant when the dispatcher-injected
    HERMES_KANBAN_TASK env var is set in the worker process.
  - A warrant denial inside a kanban worker auto-blocks the task on the board
    via a direct kanban_db write (bypassing the agent path because the denial
    is a system event, not an agent action).

This module is the pure-utility layer. The CLI (hermes-tenuo kanban …)
and the plugin wiring in _config.py / _guard.py call into here.

Credential scoping in worker subprocesses
------------------------------------------
On a single-profile Hermes, kanban_db._default_spawn copies ``os.environ``
into the worker, so TENUO_SIGNING_KEY / TENUO_WARRANT
are inherited from the dispatcher.

Under ``gateway.multiplex_profiles`` (Hermes #108748), that copy is
scrubbed and the worker is given the *routed* profile's secret scope.
``_config._env_secret`` reads those names through ``get_secret``, so a
secondary profile never sees the launch profile's Tenuo credentials.

TENUO_SIGNING_KEY: intentionally forwarded. The worker needs it to produce
  Proof-of-Possession signatures against its per-task warrant. The key
  matches the holder field of the per-task warrant, not the global warrant,
  so enforcement is still scoped correctly. A compromised worker process
  cannot use the key to authorize tools beyond what its warrant allows.

TENUO_WARRANT: superseded at load time. _config.get_warrant_raw() checks
  HERMES_KANBAN_TASK first and loads the per-task warrant from disk instead.
  The global TENUO_WARRANT env var is ignored for kanban workers. It is
  forwarded but harmless.
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple

logger = logging.getLogger("hermes_tenuo.kanban")

CapabilitySpec = Tuple[str, dict]

# Default fallback — used when hermes_constants is not importable (unit tests,
# standalone scripts).  Production code always goes through _warrants_dir().
_DEFAULT_WARRANTS_DIR = Path("~/.hermes/tenuo/warrants").expanduser()


def _warrants_dir() -> Path:
    """Return the warrants directory, rooted in the active Hermes profile home.

    Uses hermes_constants.get_hermes_home() so that per-profile cron workers
    (whose HERMES_HOME is set to the profile's directory since upstream #53570)
    find their warrants under the correct profile root rather than the shared
    default home.  Falls back to ~/.hermes/tenuo/warrants when hermes_constants
    is not importable (non-Hermes environments, unit tests).
    """
    try:
        from hermes_constants import get_hermes_home
        return get_hermes_home() / "tenuo" / "warrants"
    except Exception:
        return _DEFAULT_WARRANTS_DIR


def task_warrant_path(task_id: str) -> Path:
    """Canonical on-disk location for a task warrant (profile-aware)."""
    return _warrants_dir() / f"{task_id}.warrant"


def current_task_id() -> Optional[str]:
    """Return the dispatcher-injected task id if this process is a kanban worker."""
    return os.environ.get("HERMES_KANBAN_TASK") or None


def load_task_warrant_raw(task_id: str) -> Optional[str]:
    """Return the base64-encoded warrant for a task, if staged on disk."""
    path = task_warrant_path(task_id)
    if not path.exists():
        return None
    try:
        return path.read_text().strip() or None
    except OSError as exc:
        logger.warning("could not read task warrant %s: %s", path, exc)
        return None


def mint_task_warrant(
    task_id: str,
    capabilities: Iterable[CapabilitySpec],
    ttl_seconds: int,
    holder_pubkey: Any,
    control_key: Any,
) -> Path:
    """Mint a warrant scoped to a kanban task and stage it on disk.

    The caller chooses argument constraints (Subpath, Wildcard, fixed values)
    per capability. This function only handles serialisation and on-disk
    placement under the conventional path.

    TTL should cover worst-case task duration plus a margin so heartbeats
    survive — a warrant that expires mid-task will block the heartbeat tool
    and the dispatcher will time the worker out as if it died.
    """
    from tenuo_core import Warrant

    caps_list: List[CapabilitySpec] = list(capabilities)
    builder = Warrant.mint_builder().holder(holder_pubkey)
    for tool_name, kwargs in caps_list:
        builder = builder.capability(tool_name, **kwargs)
    builder = builder.ttl(ttl_seconds)
    warrant = builder.mint(control_key)

    raw = base64.b64encode(warrant.to_bytes()).decode()
    _warrants_dir().mkdir(parents=True, exist_ok=True)
    path = task_warrant_path(task_id)
    path.write_text(raw)
    try:
        path.chmod(0o600)
    except OSError:
        pass

    logger.info(
        "minted task warrant for %s (TTL %ds, %d capabilities)",
        task_id, ttl_seconds, len(caps_list),
    )
    return path


def delete_task_warrant(task_id: str) -> bool:
    """Remove a task warrant. Returns True if a file was removed."""
    path = task_warrant_path(task_id)
    if not path.exists():
        return False
    try:
        path.unlink()
        return True
    except OSError as exc:
        logger.warning("could not delete task warrant %s: %s", path, exc)
        return False


def block_task(task_id: str, reason: str) -> bool:
    """Mark a kanban task as blocked, with the given reason.

    Writes directly to the kanban DB rather than dispatching kanban_block
    as a tool. The denial is a system event raised by the enforcement
    layer; routing it back through the registry would re-enter the
    enforcement fn (and require the worker's warrant to authorize
    kanban_block, which it may not).

    Returns True if the task transitioned to blocked; False if the DB
    is unavailable, the kanban module is not importable in this venv,
    or the task was not in a blockable state (already blocked, done, etc.).
    """
    try:
        from hermes_cli import kanban_db as kb
    except ImportError:
        logger.debug("kanban_db unavailable in this venv; cannot auto-block %s", task_id)
        return False

    try:
        conn = kb.connect()
    except Exception as exc:
        logger.warning("could not open kanban DB: %s", exc)
        return False

    try:
        return kb.block_task(conn, task_id, reason=reason)
    except Exception as exc:
        logger.warning("failed to block task %s: %s", task_id, exc)
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass
