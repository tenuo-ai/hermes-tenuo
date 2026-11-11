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
