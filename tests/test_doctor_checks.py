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
    assert "blocks every tool call" in out


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
    assert "blocks every tool call" in out


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
    assert "enforces nothing" in _status(capsys)
    install(warrant=None, require_warrant="true")
    assert "require_warrant is on — every tool call is blocked" in _status(capsys)
