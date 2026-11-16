"""Hermes directory-plugin entry point.

``hermes plugins install hermes-tenuo`` (the catalog entry) clones this repository into
``~/.hermes/plugins/hermes-tenuo/`` and imports this file as the plugin
module. ``pip install`` users never touch it: Hermes finds the
``hermes_agent.plugins`` entry point and imports ``hermes_tenuo`` directly.

This shim makes the clone importable without putting the clone on
``sys.path``. The selected checkout is authoritative. An already loaded package
from another installation is never mixed with it: the plugin then registers a
hook that blocks every tool call and names both installations, so a second
installation cannot leave Hermes running without enforcement.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent / "hermes_tenuo"


class InstallConflict(ImportError):
    """Another hermes-tenuo installation was imported before this checkout."""


def _blocking_register(message: str):
    """A ``register`` that blocks every tool call with *message* (fail closed).

    Raising instead would make Hermes drop the plugin and run every tool call
    unchecked, with a configured warrant or access policy silently ignored.
    """

    def register(ctx):
        import logging

        logging.getLogger("hermes_tenuo").error("%s Every tool call is blocked.", message)
        try:
            from tools.registry import registry

            if hasattr(registry, "set_enforcement_fn"):
                try:
                    from tools.registry import EnforcementDenied as denied
                except ImportError:
                    denied = PermissionError

                def _deny(tool_name, args, **kwargs):
                    raise denied(message)

                registry.set_enforcement_fn(_deny)
        except Exception:
            pass  # the hook below still covers every dispatched call

        def _block(tool_name="", **kwargs):
            return {"action": "block", "message": message}

        ctx.register_hook("pre_tool_call", _block)

    return register


def _python_files(root: Path) -> dict:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*.py"))
        if "__pycache__" not in path.parts
    }


def _same_code(loaded_dir: Path) -> bool:
    """Whether an already loaded package is byte-for-byte this checkout's code.

    Hermes 0.23's package manager also installs an enabled git plugin into its
    managed environment (``…/workspace/plugin-sources/hermes-tenuo-<hash>/``), so the
    same code can be imported from there before this shim runs. That copy is the
    same installation, not a second one.
    """
    try:
        return _python_files(loaded_dir) == _python_files(_PKG_DIR)
    except OSError:
        return False


def _load_package():
    loaded = sys.modules.get("hermes_tenuo")
    if loaded is not None:
        source = getattr(loaded, "__file__", None)
        if source and Path(source).resolve() == (_PKG_DIR / "__init__.py").resolve():
            return loaded
        if source and _same_code(Path(source).resolve().parent):
            return loaded
        raise InstallConflict(
            f"hermes-tenuo installation conflict: {source} is already loaded, "
            f"but Hermes selected {_PKG_DIR}. Keep one plugin installation "
            "(directory or pip entry point), then restart Hermes."
        )
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
except InstallConflict as exc:
    _pkg = None
    register = _blocking_register(str(exc))
    __all__ = ["register"]
except ModuleNotFoundError as exc:
    if exc.name in ("tenuo", "tenuo_core", "path_jail"):
        raise ModuleNotFoundError(
            "hermes-tenuo runtime dependency is missing. Run `hermes plugins enable "
            "hermes-tenuo` to install the manifest dependencies, or install "
            "'tenuo>=0.3.6,<0.4' and 'path-jail>=0.3,<0.4' in the Hermes environment."
        ) from exc
    raise
else:
    register = _pkg.register
    HermesGuard = _pkg.HermesGuard
    HermesAuditEvent = _pkg.HermesAuditEvent

    __all__ = ["register", "HermesGuard", "HermesAuditEvent"]
