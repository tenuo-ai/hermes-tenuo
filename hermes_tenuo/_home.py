"""Where Hermes lives, and how to read its config, from inside or outside Hermes.

Inside a Hermes process ``hermes_constants`` and ``hermes_cli`` are importable
and authoritative (profile overrides, managed scope, env expansion). From a
plain shell, for example ``hermes-tenuo status`` in a different venv, the same
answers come from ``HERMES_HOME`` (default ``~/.hermes``) and a plain read of
``config.yaml``. Every path the plugin derives from the Hermes home goes
through :func:`hermes_home` so the two modes agree.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("hermes_tenuo")


def hermes_home() -> Path:
    """Hermes home: ``hermes_constants.get_hermes_home()`` → ``$HERMES_HOME`` → ``~/.hermes``."""
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home())
    except Exception:
        pass
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env).expanduser()
    return Path("~/.hermes").expanduser()


def config_path() -> Path:
    return hermes_home() / "config.yaml"


def hermes_cli_available() -> bool:
    try:
        import hermes_cli.config  # noqa: F401
        return True
    except ImportError:
        return False


def load_hermes_config() -> Dict[str, Any]:
    """Hermes's merged config when ``hermes_cli`` is importable, else a plain
    YAML read of ``$HERMES_HOME/config.yaml``. ``{}`` when neither exists."""
    try:
        from hermes_cli.config import load_config
    except ImportError:
        load_config = None
    if load_config is not None:
        try:
            data = load_config() or {}
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.debug("hermes-tenuo: hermes_cli.load_config failed (%s); reading config.yaml directly", exc)
    path = config_path()
    if not path.is_file():
        return {}
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.debug("hermes-tenuo: could not read %s: %s", path, exc)
        return {}
