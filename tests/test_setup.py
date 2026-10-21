"""hermes-tenuo setup: one command from install to observing, without hand-editing YAML."""
import sys

import pytest
import yaml

from hermes_tenuo import cli


def run(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["hermes-tenuo", "setup", *argv])
    with pytest.raises(SystemExit) as done:
        cli.main()
    return done.value.code


@pytest.fixture
def profile(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr("hermes_tenuo._home.hermes_home", lambda: home)
    return home


def test_setup_creates_the_workspace_enables_the_plugin_and_observes(profile, tmp_path, monkeypatch, capsys):
    (profile / "config.yaml").write_text("model: anthropic/claude\nplugins:\n  enabled: [other]\n")
    workspace = tmp_path / ".tenuo"
    assert run(monkeypatch, "--home", str(workspace)) == 0
    config = yaml.safe_load((profile / "config.yaml").read_text())
    assert config["model"] == "anthropic/claude"
    assert config["plugins"]["enabled"] == ["other", "hermes-tenuo"]
    assert config["plugins"]["entries"]["hermes-tenuo"] == {"local_home": str(workspace)}
    assert yaml.safe_load((workspace / "config.yaml").read_text())["mode"] == "observe"
    assert (profile / "config.yaml.before-hermes-tenuo").read_text().startswith("model:")
    out = capsys.readouterr().out
    assert "tenuo-cli calls summary" in out
    # Rerunning keeps the workspace and its keys.
    key = (workspace / "keys/agent.key").read_bytes()
    assert run(monkeypatch, "--home", str(workspace), "--enforce") == 0
    assert (workspace / "keys/agent.key").read_bytes() == key
    assert yaml.safe_load((workspace / "config.yaml").read_text())["mode"] == "enforce"


def test_setup_refuses_a_profile_with_legacy_authority(profile, tmp_path, monkeypatch):
    (profile / "config.yaml").write_text(yaml.safe_dump(
        {"plugins": {"enabled": ["hermes-tenuo"], "entries": {"hermes-tenuo": {"warrant": "abc"}}}}))
    assert run(monkeypatch, "--home", str(tmp_path / ".tenuo")) == 2
    assert "local_home" not in (profile / "config.yaml").read_text()
    assert not (tmp_path / ".tenuo").exists()
