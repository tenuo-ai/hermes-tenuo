"""Hermes home and config resolution outside a Hermes process."""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path


def _mint():
    from tenuo import SigningKey, Subpath, Warrant, Wildcard
    root, agent = SigningKey.generate(), SigningKey.generate()
    w = (Warrant.mint_builder().holder(agent.public_key)
         .capability("read_file", path=Subpath("/data")).capability("web_search", query=Wildcard())
         .ttl(600).mint(root))
    return root, agent, w


def test_hermes_home_honors_env(tmp_path, monkeypatch):
    from hermes_tenuo._home import config_path, hermes_home
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    assert hermes_home() == tmp_path / "h"
    assert config_path() == tmp_path / "h" / "config.yaml"


def test_hermes_home_defaults_to_dot_hermes(monkeypatch):
    from hermes_tenuo._home import hermes_home
    monkeypatch.delenv("HERMES_HOME", raising=False)
    assert hermes_home() == Path("~/.hermes").expanduser()


def test_default_paths_follow_hermes_home(tmp_path, monkeypatch):
    from hermes_tenuo.audit import default_audit_path
    from hermes_tenuo.kanban import task_warrant_path
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    assert default_audit_path() == tmp_path / "h" / "tenuo" / "audit.jsonl"
    assert task_warrant_path("t1") == tmp_path / "h" / "tenuo" / "warrants" / "t1.warrant"


def test_plain_config_read_when_hermes_cli_absent(tmp_path, monkeypatch):
    from hermes_tenuo._config import _get_plugin_entry, get_trusted_roots, get_warrant_raw
    from hermes_tenuo._home import load_hermes_config
    home = tmp_path / "h"; home.mkdir()
    root, agent, w = _mint()
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - hermes-tenuo\n  entries:\n    hermes-tenuo:\n"
        f"      warrant: {base64.b64encode(w.to_bytes()).decode()}\n"
        f"      trusted_root: {base64.b64encode(root.public_key.to_bytes()).decode()}\n"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert "hermes-tenuo" in load_hermes_config()["plugins"]["enabled"]
    assert _get_plugin_entry(None)["warrant"]
    assert get_warrant_raw(None) == base64.b64encode(w.to_bytes()).decode()
    assert get_trusted_roots(None)


def test_status_reports_config_sources(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.cli import cmd_status
    home = tmp_path / "h"; home.mkdir()
    (home / "config.yaml").write_text(
        "plugins:\n  entries:\n    hermes-tenuo:\n      warrant: ~/w.warrant\n      trusted_root: abc\n"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("TENUO_SIGNING_KEY", "dummy")
    assert cmd_status(argparse.Namespace()) == 0
    out = capsys.readouterr().out
    assert str(home / "config.yaml") in out and "found" in out
    assert "Warrant        set  (config: warrant, file)" in out
    assert "Signing key    set  (env: TENUO_SIGNING_KEY)" in out
    assert "Trusted root   set  (config: trusted_root, inline)" in out
    assert "~/w.warrant" not in out and "abc" not in out  # values are never echoed
    assert "Ready for enforcement" in out


def test_verify_reads_config_then_home_file(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.cli import cmd_verify
    home = tmp_path / "h"; (home / "tenuo").mkdir(parents=True)
    root, agent, w = _mint()
    b64 = base64.b64encode(w.to_bytes()).decode()
    monkeypatch.setenv("HERMES_HOME", str(home))

    assert cmd_verify(argparse.Namespace()) == 1
    assert str(home / "tenuo" / "warrant") in capsys.readouterr().err

    (home / "tenuo" / "warrant").write_text(b64)
    assert cmd_verify(argparse.Namespace()) == 0
    out = capsys.readouterr().out
    assert f"Source:      file: {home / 'tenuo' / 'warrant'}" in out and "Expired:     no" in out

    other = tmp_path / "other.warrant"; other.write_text(b64)
    (home / "config.yaml").write_text(f"plugins:\n  entries:\n    hermes-tenuo:\n      warrant: {other}\n")
    assert cmd_verify(argparse.Namespace()) == 0
    assert f"Source:      config: warrant -> {other}" in capsys.readouterr().out

    monkeypatch.setenv("TENUO_WARRANT", b64)
    assert cmd_verify(argparse.Namespace()) == 0
    assert "Source:      env: TENUO_WARRANT" in capsys.readouterr().out


def test_suite_never_touches_real_home():
    assert "hermes-home" in os.environ["HERMES_HOME"]
    assert os.environ["HERMES_HOME"] != str(Path("~/.hermes").expanduser())


def _configured_home(tmp_path, monkeypatch, signing_key):
    home = tmp_path / "h"; home.mkdir(exist_ok=True)
    root, agent, w = _mint()
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - hermes-tenuo\n  entries:\n    hermes-tenuo:\n"
        f"      warrant: {base64.b64encode(w.to_bytes()).decode()}\n"
        f"      trusted_root: {base64.b64encode(root.public_key.to_bytes()).decode()}\n"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    key = agent if signing_key == "matching" else root
    monkeypatch.setenv("TENUO_SIGNING_KEY", base64.b64encode(key.secret_key_bytes()).decode())


def test_doctor_holder_match_true_positive(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.cli import cmd_doctor
    _configured_home(tmp_path, monkeypatch, "matching")
    cmd_doctor(argparse.Namespace())
    out = capsys.readouterr().out
    assert "✓  signing key matches warrant holder" in out
    assert "does not match" not in out
    assert "reading" in out and "config.yaml directly" in out


def test_doctor_holder_match_true_negative(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.cli import cmd_doctor
    _configured_home(tmp_path, monkeypatch, "wrong")
    cmd_doctor(argparse.Namespace())
    assert "✗  signing key does not match warrant holder" in capsys.readouterr().out
