"""Hermes directory-plugin entry point.

``hermes plugins install tenuo-ai/hermes-tenuo`` clones this repository into
``~/.hermes/plugins/hermes-tenuo/`` and imports this file as the plugin
module. ``pip install`` users never touch it: Hermes finds the
``hermes_agent.plugins`` entry point and imports ``hermes_tenuo`` directly.

This shim makes the clone importable without putting the clone on
``sys.path``: if ``hermes_tenuo`` is already installed it is reused,
otherwise the sibling package directory is loaded by path.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent / "hermes_tenuo"


def _load_package():
    if "hermes_tenuo" in sys.modules:
        return sys.modules["hermes_tenuo"]
    try:
        return importlib.import_module("hermes_tenuo")
    except ModuleNotFoundError as exc:
        if exc.name != "hermes_tenuo":
            raise
    spec = importlib.util.spec_from_file_location(
        "hermes_tenuo", _PKG_DIR / "__init__.py", submodule_search_locations=[str(_PKG_DIR)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load hermes_tenuo from {_PKG_DIR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["hermes_tenuo"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("hermes_tenuo", None)
        raise
    return module


try:
    _pkg = _load_package()
except ModuleNotFoundError as exc:
    if exc.name in ("tenuo", "tenuo_core"):
        raise ModuleNotFoundError(
            "hermes-tenuo needs the 'tenuo' package, which Hermes does not install for "
            "plugins. Run: pip install 'tenuo>=0.3.0' in the environment Hermes uses."
        ) from exc
    raise

register = _pkg.register
HermesGuard = _pkg.HermesGuard
HermesAuditEvent = _pkg.HermesAuditEvent

__all__ = ["register", "HermesGuard", "HermesAuditEvent"]
