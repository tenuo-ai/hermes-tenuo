"""Zero-command key provisioning for access, and build_plugin_guard wiring it together."""
from __future__ import annotations

import stat as stat_module

import pytest

tenuo = pytest.importorskip("tenuo")


ROLES = {
    "roles": {
        "owner": {"match": {"user": ["telegram:1"]}, "allow": {"web_search": {}}},
        "guest": {"default": True, "allow": {"read_file": {"path": "/data/**"}}},
    },
}


def test_signing_key_is_provisioned_once_reused_and_recovers(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from hermes_tenuo.access import access_key_path, load_access_key, load_or_create_signing_key

    assert load_access_key() is None                         # nothing yet
    first = load_or_create_signing_key()
    path = access_key_path()
    assert path.is_file()
    assert stat_module.S_IMODE(path.stat().st_mode) == 0o600  # private
    assert load_or_create_signing_key().public_key.to_bytes() == first.public_key.to_bytes()  # reused

    path.write_text("not-a-valid-key")                       # corrupt file must not crash startup
    assert load_access_key() is None
    recovered = load_or_create_signing_key()
    assert recovered.public_key.to_bytes() != first.public_key.to_bytes()
    assert stat_module.S_IMODE(path.stat().st_mode) == 0o600


def _config(block):
    return {"plugins": {"enabled": ["hermes-tenuo"], "entries": {"hermes-tenuo": {"access": block}}}}


def test_build_plugin_guard_auto_provisions_and_enforces_per_sender(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for var in ("TENUO_SIGNING_KEY", "TENUO_WARRANT", "TENUO_TRUSTED_ROOT"):
        monkeypatch.delenv(var, raising=False)
    import hermes_tenuo._home as home
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config(ROLES))

    from hermes_tenuo import access
    from hermes_tenuo._guard import build_plugin_guard

    guard = build_plugin_guard(None)                          # no key configured
    assert guard is not None
    assert access.access_key_path().is_file()                 # a key was provisioned

    def call(tool, args, session="s", **ident):
        monkeypatch.setattr(access, "current_sender", lambda: ident or None)
        return bool(guard.pre_tool_call_hook(tool, args, session_id=session))

    # owner: web_search yes, read_file no (not in the owner role)
    assert not call("web_search", {"query": "x"}, user="telegram:1", platform="telegram")
    assert call("read_file", {"path": "/data/x"}, user="telegram:1", platform="telegram")
    # a different sender falls to guest: read_file under /data yes, web_search no
    assert not call("read_file", {"path": "/data/y"}, session="s2", user="telegram:9", platform="telegram")
    assert call("web_search", {"query": "x"}, session="s2", user="telegram:9", platform="telegram")


def test_build_plugin_guard_blocks_all_on_a_broken_access_block(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
    import hermes_tenuo._home as home
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config({"roles": {"x": {"allow": {"t": {}}}}}))  # no match
    from hermes_tenuo._guard import WarrantLoadError, build_plugin_guard

    with pytest.raises(WarrantLoadError, match="non-default role must have a match"):
        build_plugin_guard(None)


def test_a_configured_key_takes_precedence_over_provisioning(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    key = tenuo.SigningKey.generate()
    import base64
    monkeypatch.setenv("TENUO_SIGNING_KEY", base64.b64encode(key.secret_key_bytes()).decode())
    monkeypatch.delenv("TENUO_WARRANT", raising=False)
    import hermes_tenuo._home as home
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config(ROLES))
    from hermes_tenuo.access import access_key_path
    from hermes_tenuo._guard import build_plugin_guard

    guard = build_plugin_guard(None)
    assert guard is not None
    assert not access_key_path().is_file()   # the configured key was used; nothing provisioned


def test_doctor_reports_the_access_block(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
    monkeypatch.delenv("TENUO_WARRANT", raising=False)
    import hermes_tenuo._home as home
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config(ROLES))
    from argparse import Namespace

    from hermes_tenuo.cli import cmd_doctor

    cmd_doctor(Namespace())
    out = capsys.readouterr().out
    assert "access: 2 role(s)" in out and "unmatched senders → guest" in out
    assert "every role compiles to a warrant" in out
    # No static warrant is not a failure when access provides the authority.
    assert "role-based access (below) is the tool-call authority" in out


def test_a_malformed_configured_key_fails_closed_without_provisioning(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TENUO_SIGNING_KEY", "not-a-valid-base64-key!!!")
    monkeypatch.delenv("TENUO_WARRANT", raising=False)
    import hermes_tenuo._home as home
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config(ROLES))
    from hermes_tenuo._guard import WarrantLoadError, build_plugin_guard
    from hermes_tenuo.access import access_key_path

    with pytest.raises(WarrantLoadError, match="could not be loaded"):
        build_plugin_guard(None)
    assert not access_key_path().is_file()   # did not provision a different key behind a bad one


def test_access_with_an_empty_static_warrant_still_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
    import hermes_tenuo._config as cfgmod
    import hermes_tenuo._home as home
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config(ROLES))
    monkeypatch.setattr(cfgmod, "resolve_warrant_text", lambda ctx: ("", "env"))  # configured but empty
    from hermes_tenuo._guard import WarrantLoadError, build_plugin_guard

    with pytest.raises(WarrantLoadError, match="empty"):
        build_plugin_guard(None)


def test_a_broken_constraint_in_the_block_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
    monkeypatch.delenv("TENUO_WARRANT", raising=False)
    import hermes_tenuo._home as home
    bad = {"roles": {"r": {"match": {"user": ["u"]}, "allow": {"wait": {"seconds": {"range": [1]}}}}}}
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config(bad))
    from hermes_tenuo._guard import WarrantLoadError, build_plugin_guard

    with pytest.raises(WarrantLoadError):
        build_plugin_guard(None)


@pytest.mark.parametrize("constraint", [{"patterns": ["^[$"]}, {"subpath": "relative"}])
def test_sdk_constraint_errors_install_block_all_and_doctor_reports_failure(tmp_path, monkeypatch, capsys, constraint):
    import hermes_tenuo as plugin
    import hermes_tenuo._home as home
    from argparse import Namespace
    from hermes_tenuo.cli import cmd_doctor

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
    monkeypatch.delenv("TENUO_WARRANT", raising=False)
    block = {"roles": {"guest": {"default": True, "allow": {"read_file": {"path": constraint}}}}}
    monkeypatch.setattr(home, "load_hermes_config", lambda: _config(block))
    monkeypatch.setattr(plugin, "_register_skills", lambda ctx: None)
    monkeypatch.setattr("hermes_tenuo.hands.register", lambda ctx: False)

    class Context:
        def __init__(self):
            self.hooks = {}

        def register_hook(self, name, hook):
            self.hooks[name] = hook

    ctx = Context()
    plugin.register(ctx)
    assert ctx.hooks["pre_tool_call"]("read_file")["action"] == "block"
    assert cmd_doctor(Namespace()) == 1
    assert "access config:" in capsys.readouterr().out


@pytest.mark.parametrize("corrupt", [False, True])
def test_concurrent_processes_share_one_access_identity(tmp_path, corrupt):
    import os
    import subprocess
    import sys
    from pathlib import Path

    key_path = tmp_path / "tenuo" / "access.key"
    key_path.parent.mkdir()
    if corrupt:
        key_path.write_text("corrupt")
    # Widen the read/write race in separate interpreters, exercising the OS lock
    # rather than relying on threads or an in-process mutex.
    script = """
import time
from hermes_tenuo import access
original = access.load_access_key
def slow_load():
    value = original()
    time.sleep(0.1)
    return value
access.load_access_key = slow_load
print(access.load_or_create_signing_key().public_key.to_bytes().hex())
"""
    env = dict(os.environ, HERMES_HOME=str(tmp_path), PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    processes = [subprocess.Popen([sys.executable, "-c", script], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    identities = []
    for process in processes:
        out, err = process.communicate(timeout=15)
        assert process.returncode == 0, err
        identities.append(out.strip())
    assert len(set(identities)) == 1
    from tenuo import SigningKey
    import base64
    persisted = SigningKey.from_bytes(base64.b64decode(key_path.read_text()))
    assert identities[0] == persisted.public_key.to_bytes().hex()


def test_doctor_uses_only_the_selected_signing_key_variable(tmp_path, monkeypatch, capsys):
    from argparse import Namespace
    import hermes_tenuo._home as home
    from hermes_tenuo.cli import cmd_doctor
    from hermes_tenuo._guard import build_plugin_guard

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TENUO_SIGNING_KEY", "invalid-but-not-selected")
    monkeypatch.delenv("ACCESS_TEST_KEY", raising=False)
    monkeypatch.delenv("TENUO_WARRANT", raising=False)
    config = _config(ROLES)
    config["plugins"]["entries"]["hermes-tenuo"]["signing_key_env"] = "ACCESS_TEST_KEY"
    monkeypatch.setattr(home, "load_hermes_config", lambda: config)
    assert build_plugin_guard(None) is not None
    cmd_doctor(Namespace())
    output = capsys.readouterr().out
    assert "access: using the provisioned key" in output
    assert "access signing key could not be loaded" not in output
