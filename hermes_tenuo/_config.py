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
from typing import Any, Optional

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


def get_warrant_raw(ctx: Any) -> Optional[str]:
    """Return raw warrant: base64 string or path to warrant file."""
    entry = _get_plugin_entry(ctx)
    raw = entry.get("warrant") or os.environ.get("TENUO_WARRANT")
    if not raw:
        return None
    # If it looks like a path, read the file
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
    path = Path(raw).expanduser()
    if path.exists():
        return path.read_text().strip()
    return raw


def get_signing_key(ctx: Any):
    """Return SigningKey from env or config, or None."""
    entry = _get_plugin_entry(ctx)
    # config can name an env var to read from, or supply the key directly
    key_env = entry.get("signing_key_env", "TENUO_SIGNING_KEY")
    raw = os.environ.get(key_env)
    if not raw:
        return None
    try:
        from tenuo_core import SigningKey
        return SigningKey.from_base64(raw)
    except Exception as exc:
        logger.warning("hermes-tenuo: could not load signing key: %s", exc)
        return None


def load_warrant(raw: Optional[str]):
    """Deserialise a base64 warrant string into a Warrant object."""
    if not raw:
        return None
    try:
        from tenuo_core import Warrant
        data = base64.b64decode(raw)
        return Warrant.from_bytes(data)
    except Exception as exc:
        logger.warning("hermes-tenuo: could not load warrant: %s", exc)
        return None
