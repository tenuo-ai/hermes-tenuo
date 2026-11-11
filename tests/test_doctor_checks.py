"""doctor and status report what the plugin will do at runtime."""

from __future__ import annotations

import argparse
import base64
import json

import pytest
from tenuo import SigningKey, Warrant

from hermes_tenuo.cli import cmd_doctor, cmd_status


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.fixture
def install(tmp_path, monkeypatch):
    """A working install; returns a function that rewrites its config entry."""
    home = tmp_path / "h"
    home.mkdir()
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().tool("read_file").holder(holder.public_key).ttl(3600).mint(issuer)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("TENUO_SIGNING_KEY", _b64(holder.secret_key_bytes()))
    monkeypatch.delenv("TENUO_DELEGATION_PLAN", raising=False)

    def write(**overrides):
        entry = {"warrant": _b64(warrant.to_bytes()), "trusted_root": _b64(issuer.public_key.to_bytes())}
        entry.update(overrides)
        lines = ["plugins:", "  enabled:", "    - hermes-tenuo", "  entries:", "    hermes-tenuo:"]
        lines += [f"      {k}: {v}" for k, v in entry.items() if v is not None]
        (home / "config.yaml").write_text("\n".join(lines) + "\n")

    write()
    return write


def _doctor(capsys):
    rc = cmd_doctor(argparse.Namespace())
    return rc, capsys.readouterr().out


def test_working_install_passes(install, capsys):
    rc, out = _doctor(capsys)
    assert rc == 0 and "All checks passed" in out
    assert "✓  warrant is signed by trusted_root" in out


def test_trusted_root_that_did_not_sign_the_warrant_fails(install, capsys):
    install(trusted_root=_b64(SigningKey.generate().public_key.to_bytes()))
    rc, out = _doctor(capsys)
    assert rc == 1 and "All checks passed" not in out
    assert "✗  warrant is not signed by trusted_root" in out
    assert "every tool call is blocked until this is fixed" in out


@pytest.mark.parametrize("root", ["other", "not-a-key", None])
def test_trusted_root_failures_say_what_log_mode_does(install, capsys, root):
    if root == "other":
        root = _b64(SigningKey.generate().public_key.to_bytes())
    install(trusted_root=root, on_denial="log")
    rc, out = _doctor(capsys)
    assert rc == 1
    assert "with on_denial: log it is recorded and still runs" in out
    assert "is blocked until this is fixed" not in out


def test_one_matching_root_in_a_list_is_enough(install, capsys, monkeypatch):
    install(trusted_root=None)
    other = _b64(SigningKey.generate().public_key.to_bytes())
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().tool("read_file").holder(holder.public_key).ttl(3600).mint(issuer)
    monkeypatch.setenv("TENUO_SIGNING_KEY", _b64(holder.secret_key_bytes()))
    install(warrant=_b64(warrant.to_bytes()), trusted_root=f"{other},{_b64(issuer.public_key.to_bytes())}")
    rc, out = _doctor(capsys)
    assert rc == 0 and "✓  warrant is signed by trusted_root" in out


def test_trusted_root_that_is_not_a_key_fails(install, capsys):
    install(trusted_root="not-a-key")
    rc, out = _doctor(capsys)
    assert rc == 1
    assert "✗  trusted_root is not a base64 public key" in out
    assert "every tool call is blocked until this is fixed" in out


def test_missing_delegation_plan_fails(install, capsys, tmp_path):
    install(delegation_plan=str(tmp_path / "nope.json"))
    rc, out = _doctor(capsys)
    assert rc == 1
    assert "✗  delegation plan" in out and "does not exist" in out


def test_valid_delegation_plan_passes(install, capsys, tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "version": 1,
        "root": {"tools": {"read_file": {}, "delegate_task": {}}},
        "levels": [{"ttl_seconds": 60, "tools": {"read_file": {}}}],
    }))
    plan.chmod(0o600)
    install(delegation_plan=str(plan))
    rc, out = _doctor(capsys)
    assert rc == 0 and "✓  delegation plan loads" in out


def test_misspelt_on_denial_fails_and_log_is_noted(install, capsys):
    install(on_denial="lgo")
    rc, out = _doctor(capsys)
    assert rc == 1 and "on_denial is 'lgo'" in out
    install(on_denial="log")
    rc, out = _doctor(capsys)
    assert rc == 0 and "on_denial: log" in out


def test_kanban_worker_with_a_task_warrant_from_another_issuer_fails(install, capsys, monkeypatch):
    from hermes_tenuo.cli import cmd_mint

    args = argparse.Namespace(ttl="1h", allow=["read_file"], output="env", task="card-1")
    assert cmd_mint(args) == 0
    captured = capsys.readouterr()
    assert "did not sign this task warrant" in captured.err
    monkeypatch.setenv("HERMES_KANBAN_TASK", "card-1")
    rc, out = _doctor(capsys)
    assert rc == 1 and "✗  warrant is not signed by trusted_root" in out


def _status(capsys):
    assert cmd_status(argparse.Namespace()) == 0
    return capsys.readouterr().out


def test_status_says_blocked_when_only_the_key_is_missing(install, capsys, monkeypatch):
    monkeypatch.delenv("TENUO_SIGNING_KEY")
    out = _status(capsys)
    assert "every tool call is blocked" in out and "pass through" not in out


def test_status_says_not_enforcing_when_no_warrant(install, capsys):
    install(warrant=None)
    assert "general tool-call authorization is off" in _status(capsys)
    install(warrant=None, require_warrant="true")
    assert "require_warrant is on — every tool call is blocked" in _status(capsys)


def test_status_missing_trusted_root_depends_on_on_denial(install, capsys):
    install(trusted_root=None)
    out = _status(capsys)
    assert "trusted_root is not — every tool call is blocked" in out
    install(trusted_root=None, on_denial="log")
    out = _status(capsys)
    assert "recorded and still runs" in out and "is blocked until" not in out


def test_status_missing_key_blocks_even_in_log_mode(install, capsys, monkeypatch):
    install(on_denial="log")
    monkeypatch.delenv("TENUO_SIGNING_KEY")
    assert "signing key is not — every tool call is blocked" in _status(capsys)


@pytest.mark.parametrize("global_warrant", [True, False])
def test_status_reports_the_kanban_task_warrant(install, capsys, monkeypatch, global_warrant):
    from hermes_tenuo.kanban import task_warrant_path

    if not global_warrant:
        install(warrant=None)
    monkeypatch.setenv("HERMES_KANBAN_TASK", "card-1")
    out = _status(capsys)
    assert "not staged  (kanban task card-1:" in out
    assert "No warrant is staged for kanban task card-1 — every tool call is blocked" in out
    assert "general tool-call authorization is off" not in out and "Ready for enforcement" not in out

    path = task_warrant_path("card-1")
    path.parent.mkdir(parents=True)
    path.write_text("staged-warrant-text")
    out = _status(capsys)
    assert "Warrant        set  (kanban task card-1, file)" in out
    assert "Ready for enforcement" in out
    assert "staged-warrant-text" not in out


def _directory_install(home, shim_text):
    directory = home / "plugins" / "hermes-tenuo"
    (directory / "hermes_tenuo").mkdir(parents=True)
    (directory / "hermes_tenuo" / "__init__.py").write_text("")
    (directory / "__init__.py").write_text(shim_text)
    return directory


_THIS_SHIM = (__import__("pathlib").Path(__file__).resolve().parents[1] / "__init__.py").read_text()
# The loader that refused a second installation by raising, so Hermes dropped the plugin.
_RAISING_SHIM = """
def _load_package():
    raise ImportError("hermes-tenuo installation conflict: x is already loaded")
_pkg = _load_package()
register = _pkg.register
"""
# The 0.3 loader: use whichever package is already importable.
_REUSING_SHIM = """
import importlib
_pkg = importlib.import_module("hermes_tenuo")
register = _pkg.register
"""


@pytest.mark.parametrize("shim, effect, said, fails", [
    (_THIS_SHIM, "blocks", "when Hermes loads both, every tool call is blocked", True),
    (_RAISING_SHIM, "drops", "when Hermes loads both, the plugin is not loaded and nothing is enforced", True),
    (_REUSING_SHIM, "reuses", "—  two installations", False),
])
def test_doctor_reports_a_second_installation_by_what_its_loader_does(
        tmp_path, monkeypatch, capsys, shim, effect, said, fails):
    from hermes_tenuo import cli
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr("hermes_tenuo._home.hermes_cli_available", lambda: True)
    directory = _directory_install(tmp_path, shim)
    assert cli._second_installation() == (directory, effect)
    code = cli.cmd_doctor(argparse.Namespace())
    out = capsys.readouterr().out
    assert said in out and str(directory) in out
    assert ("✗  two installations" in out) is fails
    if fails:
        assert code == 1


def test_doctor_ignores_the_plugin_directory_outside_the_hermes_environment(tmp_path, monkeypatch):
    from hermes_tenuo import cli
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _directory_install(tmp_path, _THIS_SHIM)
    monkeypatch.setattr("hermes_tenuo._home.hermes_cli_available", lambda: False)
    assert cli._second_installation() is None
    monkeypatch.setattr("hermes_tenuo._home.hermes_cli_available", lambda: True)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "elsewhere"))
    assert cli._second_installation() is None
