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
    import json

    from tenuo import WarrantTemplate
    from tenuo.local_cli.warrants import encode_chain
    from tenuo.local_cli.workspace import Workspace

    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    warrant = WarrantTemplate({"version": 2, "ttl": "1h", "capabilities": {"web_search": {}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("agent"))
    path = tmp_path / "job.warrant"
    path.write_text(encode_chain([warrant]))
    monkeypatch.setenv("TENUO_JSON", "0")

    def session(*argv):
        return cli.run(["session", "--home", str(workspace.path), *argv]), capsys.readouterr()

    code, out = session("attach", "--session", "cron_briefing", "--file", str(path))
    assert code == 0 and str(warrant.id) in out.out
    assert str(warrant.id) in session("list")[1].out
    assert str(warrant.id) in session("show", "--session", "cron_briefing")[1].out
    monkeypatch.setenv("TENUO_JSON", "1")
    code, out = session("show", "--session", "cron_briefing")
    assert code == 0 and str(warrant.id) in json.dumps(json.loads(out.out))
    monkeypatch.setenv("TENUO_JSON", "0")
    assert session("detach", "--session", "cron_briefing", "--id", str(warrant.id))[0] == 0
    code, out = session("show", "--session", "chat-x")
    assert code == 1 and "no attachments" in out.err

    # The same command as `tenuo-cli hermes session`, when the SDK routes integration commands (tenuo#976).
    from tenuo.local_cli import commands
    if hasattr(commands, "integrations"):
        assert commands.integrations()["hermes"].value == "hermes_tenuo.cli:tenuo_cli"
        assert commands.main(["--home", str(workspace.path), "--json", "hermes", "session", "list"]) == 0
        assert "sessions" in json.loads(capsys.readouterr().out)


def test_a_warrant_held_by_another_key_is_refused_with_both_keys_named(tmp_path):
    from tenuo import WarrantTemplate
    from tenuo.local import attach
    from tenuo.local_cli.workspace import Workspace

    from hermes_tenuo.local_guard import SharedLocalGuard

    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("enforce")
    from tenuo.local_cli.files import keygen

    keygen(workspace.path / "keys" / "reviewer")
    warrant = WarrantTemplate({"version": 2, "ttl": "1h", "capabilities": {"web_search": {}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("reviewer"))
    attach(workspace, "20261022_120000_5555ffff", [warrant], holder="reviewer")
    guard = SharedLocalGuard(workspace.path)
    blocked = guard.pre_tool_call("web_search", {"query": "x"}, session_id="20261022_120000_5555ffff",
                                  tool_call_id="t1")
    assert "is held by key" in blocked["message"] and "signs with 'agent'" in blocked["message"]
    assert "--holder agent" in blocked["message"]


def test_setup_installs_the_recipes_without_overwriting_edits(profile, tmp_path, monkeypatch, capsys):
    home = tmp_path / ".tenuo"
    assert run(monkeypatch, "--home", str(home)) == 0
    recipes = home / "recipes" / "hermes"
    names = sorted(p.stem for p in recipes.glob("*.yaml"))
    assert {"briefing", "house-sitter", "house-sitter-owner", "project-task", "reply-to-thread", "review-prs",
            "work-on-issues", "work-on-issues-one-issue"} <= set(names)
    out = capsys.readouterr().out
    assert "warrant issue --template" in out and "attach --session telegram:YOUR_ID --file project.warrant" in out
    (recipes / "project-task.yaml").write_text("# mine\n")
    assert run(monkeypatch, "--home", str(home)) == 0
    assert (recipes / "project-task.yaml").read_text() == "# mine\n"


def test_observe_records_with_an_sdk_that_does_not_tag_integrations(tmp_path, monkeypatch):
    """An SDK whose record() has no via= must still get every observation."""
    from tenuo.local_cli.runtime import LocalAuthority
    from tenuo.local_cli.workspace import Workspace

    from hermes_tenuo.local_guard import SharedLocalGuard

    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    seen = []

    def old_record(self, tool, arguments, *, decision=None, reason=None, warrant_id=None, argument=None,
                   run=None, step=None):
        seen.append(tool)

    monkeypatch.setattr(LocalAuthority, "record", old_record)
    guard = SharedLocalGuard(workspace.path)
    assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="s1", tool_call_id="t1") is None
    assert seen == ["web_search"]
