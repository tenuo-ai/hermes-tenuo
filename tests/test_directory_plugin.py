"""The repo root must load as a Hermes *directory* plugin.

``hermes plugins install tenuo-ai/hermes-tenuo`` clones the repo into
``~/.hermes/plugins/hermes-tenuo/`` and Hermes imports ``<dir>/__init__.py``
by path (``importlib.util.spec_from_file_location`` with the directory as
the package path). This mirrors that loader exactly.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_as_hermes_does(module_name: str = "hermes_plugins.hermes_tenuo_test"):
    init_file = ROOT / "__init__.py"
    assert init_file.is_file(), "repo root needs __init__.py for hermes plugins install"
    spec = importlib.util.spec_from_file_location(
        module_name, init_file, submodule_search_locations=[str(ROOT)]
    )
    module = importlib.util.module_from_spec(spec)
    module.__package__ = module_name
    module.__path__ = [str(ROOT)]
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
    return module


def test_root_init_exposes_register():
    module = _load_as_hermes_does()
    assert callable(module.register)
    import hermes_tenuo
    assert module.register is hermes_tenuo.register


def test_root_init_registers_hooks_and_skill(monkeypatch, tmp_path):
    from tests.test_integration_smoke import MockCtx
    from tests.test_config import FakeCtx  # noqa: F401
    module = _load_as_hermes_does()
    ctx = MockCtx()
    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry", lambda _ctx: {})
    for var in ("TENUO_WARRANT", "TENUO_CONNECT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    module.register(ctx)
    # Unconfigured install: the plugin still registers its skill and does not crash.
    assert "tenuo-scope" in ctx.skills


def test_plugin_yaml_declares_tenuo_dependency():
    text = (ROOT / "plugin.yaml").read_text()
    assert "python_dependencies" in text and "tenuo>=0.3.6,<0.4" in text


def test_directory_rejects_already_loaded_other_install(monkeypatch, tmp_path):
    from types import ModuleType
    import pytest
    stale = ModuleType('hermes_tenuo')
    stale.__file__ = str(tmp_path / 'old' / '__init__.py')
    monkeypatch.setitem(sys.modules, 'hermes_tenuo', stale)
    with pytest.raises(ImportError, match='installation conflict'):
        _load_as_hermes_does()
    assert sys.modules['hermes_tenuo'] is stale


def test_directory_ignores_unloaded_stale_package(tmp_path):
    """A stale distribution on sys.path must not override the chosen checkout."""
    import subprocess
    stale = tmp_path / 'hermes_tenuo'
    stale.mkdir()
    (stale / '__init__.py').write_text("raise AssertionError('stale package imported')")
    code = f'''
import importlib.util, sys
from pathlib import Path
sys.path.insert(0, {str(tmp_path)!r})
spec = importlib.util.spec_from_file_location('selected_plugin', {str(ROOT / '__init__.py')!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert Path(module._pkg.__file__).resolve() == Path({str(ROOT / 'hermes_tenuo/__init__.py')!r}).resolve()
from hermes_tenuo.hands import device
'''
    subprocess.run([sys.executable, '-c', code], cwd=tmp_path, check=True)
