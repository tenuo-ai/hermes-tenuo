"""tenuo-cli hermes setup: one command from install to observing, without hand-editing YAML."""
import pytest

pytest.importorskip("tenuo.local_cli.observations", reason="needs the Tenuo SDK with the local CLI (tenuo-ai/tenuo#970)")

import sys

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
    assert f"tenuo-cli --home {workspace} calls summary" in out
    assert f"tenuo-cli --home {workspace} mode enforce" in out
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


def test_session_attach_list_show_detach(tmp_path, monkeypatch, capsys):
    from tenuo import WarrantTemplate
    from tenuo.local_cli.warrants import encode_chain
    from tenuo.local_cli.workspace import Workspace

    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    warrant = WarrantTemplate({"version": 2, "ttl": "1h", "capabilities": {"web_search": {}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("agent"))
    path = tmp_path / "job.warrant"
    path.write_text(encode_chain([warrant]))

    from tenuo.local_cli import commands
    if not hasattr(commands, "integrations"):
        pytest.skip("tenuo-cli without integration commands")
    assert commands.integrations()["hermes"].value == "hermes_tenuo.cli:tenuo_cli"

    def session(*argv):
        code = commands.main(["--home", str(workspace.path), "hermes", "session", *argv])
        return code, capsys.readouterr()

    code, out = session("attach", "--session", "cron_briefing", "--file", str(path))
    assert code == 0 and str(warrant.id) in out.out
    assert str(warrant.id) in session("list")[1].out
    assert str(warrant.id) in session("show", "--session", "cron_briefing")[1].out
    assert session("detach", "--session", "cron_briefing", "--id", str(warrant.id))[0] == 0
    code, out = session("show", "--session", "chat-x")
    assert code == 1 and "no attachments" in out.err
    # The standalone command still works.
    monkeypatch.setattr(sys, "argv", ["hermes-tenuo", "session", "--home", str(workspace.path), "list"])
    with pytest.raises(SystemExit) as done:
        cli.main()
    assert done.value.code == 0
