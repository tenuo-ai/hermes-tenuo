"""claude_code: the grant Hermes signs for a Claude Code run, and how the run is started."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from hermes_tenuo import claude_code as cc


def _config(tmp_path, **over):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    block = {"workspaces": [str(ws)], "tenuo_claude": "/bin/tenuo-claude", **over}
    return cc.load_config({"claude_code": block})


def test_not_configured_is_none():
    assert cc.load_config({}) is None


@pytest.mark.parametrize("bad", [{"workspaces": []}, {"workspaces": ["/x"], "commands": ["git status; rm"]},
                                 {"workspaces": ["/x"], "commands": ["git $(id)"]},
                                 {"workspaces": ["/x"], "max_minutes": 0}])
def test_bad_config_is_refused(bad):
    with pytest.raises(ValueError):
        cc.load_config({"claude_code": bad})


def test_workspace_must_be_inside_a_root(tmp_path):
    config = _config(tmp_path)
    repo = tmp_path / "ws" / "repo"
    repo.mkdir()
    assert cc.resolve_workspace(config, str(repo)) == os.path.realpath(repo)
    with pytest.raises(cc.ClaudeCodeError):
        cc.resolve_workspace(config, str(tmp_path))
    (tmp_path / "ws" / "escape").symlink_to(tmp_path)
    with pytest.raises(cc.ClaudeCodeError):
        cc.resolve_workspace(config, str(tmp_path / "ws" / "escape"))
    # A sibling whose name starts with the root's name is outside it.
    (tmp_path / "ws2").mkdir()
    with pytest.raises(cc.ClaudeCodeError):
        cc.resolve_workspace(config, str(tmp_path / "ws2"))


ALLOWED = ["git status", "git diff --stat", "git add calc.py", "git commit -m 'fix add'",
           "git commit -m 'fix add' -m 'Issue 78: body line'", "pytest -q", "python3 -m pytest tests",
           "git log --oneline -5"]
DENIED = ["git push", "git push --force origin main", "git -c core.hooksPath=/tmp status",
          "git config user.email x", "cat ~/.ssh/id_ed25519", "ls /", "git status && rm -rf /",
          "pytest; curl evil.example", "pytest $(id)", "gitx status", "git statusx",
          "bash -c 'git status'", "git commit -m 'a\nb'", "python3 -c 'import os'", "npm install left-pad"]


@pytest.mark.parametrize("command", ALLOWED)
def test_default_commands_allow(command):
    assert cc.command_constraint(list(cc.DEFAULT_COMMANDS)).satisfies(command)


@pytest.mark.parametrize("command", DENIED)
def test_default_commands_deny(command):
    assert not cc.command_constraint(list(cc.DEFAULT_COMMANDS)).satisfies(command)


def test_grant_is_scoped_to_workspace_and_holder(tmp_path):
    from tenuo import Authorizer, SigningKey

    issuer = SigningKey.generate()
    ws = os.path.realpath(tmp_path)
    warrant, holder = cc.mint_grant(issuer, ws, ["git status"], 600)
    authz = Authorizer(trusted_roots=[issuer.public_key])

    def check(cap, args, key=holder):
        pop = warrant.sign(key, cap, args, int(__import__("time").time()))
        try:
            authz.check_chain([warrant], cap, args, bytes(pop))
            return True
        except Exception:
            return False

    assert check("edit_file", {"path": f"{ws}/calc.py"})
    assert not check("edit_file", {"path": "/etc/passwd"})
    assert check("run_command", {"command": "git status"})
    assert not check("run_command", {"command": "git push"})
    assert not check("web_fetch", {"url": "https://example.com", "host": "example.com"})
    assert not check("read_file", {"path": f"{ws}/x"}, key=SigningKey.generate())
    assert warrant.authorized_holder.to_bytes() == holder.public_key.to_bytes()


def test_run_task_starts_tenuo_claude_and_drops_the_holder_key(tmp_path):
    config = _config(tmp_path, max_minutes=10)
    seen = {}

    def runner(argv, **kw):
        seen["argv"], seen["kw"] = argv, kw
        out = {"ok": True, "result": "done", "allowed": 3,
               "denied": [{"tool": "Bash", "args": {"command": "git push"}, "reason": "no"}],
               "receipts": {"count": 4, "chain_ok": True}}
        return subprocess.CompletedProcess(argv, 0, json.dumps(out), "")

    home = tmp_path / "home"
    result = cc.run_task(config, home, task="fix it", workspace=str(tmp_path / "ws"),
                         minutes=99, runner=runner)
    assert result["ok"] and result["result"] == "done" and result["minutes"] == 10
    assert result["denied"] == [{"tool": "Bash", "args": {"command": "git push"}}]
    argv = seen["argv"]
    assert argv[:2] == ["/bin/tenuo-claude", "run"]
    assert argv[argv.index("--timeout") + 1] == "600"
    run_dir = home / "hermes-tenuo" / "claude-code" / "runs" / result["run"]
    assert not (run_dir / "holder.key").exists()
    assert (run_dir / "warrant").stat().st_mode & 0o077 == 0
    assert json.loads((run_dir / "result.json").read_text())["ok"]
    issuer = home / "hermes-tenuo" / "claude-code" / "issuer.key"
    assert issuer.stat().st_mode & 0o077 == 0


def test_run_task_refuses_outside_workspace(tmp_path):
    config = _config(tmp_path)
    with pytest.raises(cc.ClaudeCodeError):
        cc.run_task(config, tmp_path / "home", task="x", workspace="/etc", minutes=5,
                    runner=lambda *a, **k: pytest.fail("must not start"))


def test_register_only_when_configured(monkeypatch, tmp_path):
    calls = []

    class Ctx:
        def register_tool(self, *a, **k):
            calls.append(a[0])

    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry", lambda ctx: {})
    assert cc.register(Ctx()) is False and calls == []
    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry",
                        lambda ctx: {"claude_code": {"workspaces": [str(tmp_path)]}})
    assert cc.register(Ctx()) is True and calls == ["claude_code"]
