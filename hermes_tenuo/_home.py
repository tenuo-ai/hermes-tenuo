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


def managed_environments_without_plugin() -> list:
    """Hermes-managed Python environments of this install that do not contain hermes-tenuo.

    ``hermes plugins install`` moves an install onto an environment Hermes builds and owns
    (``installs/<id>/environments/<id>/venv``). A hermes-tenuo that was pip-installed into the
    environment Hermes ran from before is not carried over: Hermes keeps listing it as enabled but
    does not load it. A copy installed with ``hermes plugins install`` lives in ``plugins/`` and is
    not affected, so with one present this returns nothing.
    """
    import json

    home = hermes_home()
    roots = [home, home.parent.parent] if home.parent.name == "profiles" else [home]
    if (home / "plugins" / "hermes-tenuo").is_dir():  # Hermes loads directory plugins from the active profile only
        return []
    try:
        # The record of the Hermes that runs this check, when this is its Python.
        from pm.environments import install_state_dir
        from pm.paths import install_root

        records = [Path(install_state_dir(install_root())) / "facts.json"]
    except Exception:  # noqa: BLE001 - not Hermes's Python: which install is meant is unknown, so look at each
        records = [facts for root in roots for facts in sorted(root.glob("installs/*/facts.json"))]
    missing = []
    for facts in records:
        try:
            env = json.loads(facts.read_text(encoding="utf-8"))["packages"]["venv"]["environment"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        env = Path(env)
        if not env.is_dir():
            continue
        found = list(env.glob("lib/python*/site-packages/hermes_tenuo*")) + list(env.glob("Lib/site-packages/hermes_tenuo*"))
        if not found:
            missing.append(env)
    return missing
