"""Hands inside real Hermes: plugin loader, tool dispatch, file tools and `/hands`.

Skipped unless ``hermes_cli`` is importable (the ``upstream-hermes`` workflow installs
it). Runs in a subprocess with its own ``HERMES_HOME``, like ``test_upstream_hermes``,
and through whichever install route that workflow set up: the pip-installed package, or
a copy of the repo under ``$HERMES_HOME/plugins``.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytest.importorskip("hermes_cli.plugins")

from hermes_tenuo.hands import sandbox  # noqa: E402
from tests.test_upstream_hermes import _IGNORE, ROOT, _plugin_installed  # noqa: E402

pytestmark = pytest.mark.skipif(sandbox.available() is None, reason="needs sandbox-exec or bubblewrap")

SCRIPT = textwrap.dedent('''
    import json, os, sys, threading, time
    from pathlib import Path
    base, whole_profile = Path(sys.argv[1]), sys.argv[2] == "profile"
    device_dir, server_dir = base / "device-project", base / "server-dir"
    os.chdir(server_dir)

    from hermes_cli.plugins import discover_plugins
    discover_plugins(force=True)
    assert "hermes_tenuo" in sys.modules, "Hermes did not load the plugin"
    from model_tools import handle_function_call
    from hermes_tenuo.hands import chat, wire
    from hermes_tenuo.hands.device import Device
    wire.POLL_SECONDS = 2  # a stopped device leaves its open request quickly
    from hermes_tenuo.hands.hub import get_hub

    out = {}
    def tool(key, name, args, task="chat-1"):
        raw = handle_function_call(name, args, task_id=task, session_id="s1", tool_call_id=key)
        try:
            data = json.loads(raw)
        except ValueError:
            data = {"output": raw}
        out[key] = {"exit": data.get("exit_code"), "text": str(data.get("output", data.get("content", data))),
                    "pid": data.get("pid"), "session": data.get("session_id"),
                    "ran_on": data.get("ran_on"), "note": data.get("hands_note")}

    def up(folder, name="laptop", invite=None, state=None):
        if state:
            os.environ["TENUO_HANDS_HOME"] = str(state)
        device = Device(invite, str(folder), 600, name=name, say=lambda text: None)
        thread = threading.Thread(target=device.serve, daemon=True)
        thread.start()
        deadline = time.time() + 15
        while time.time() < deadline and not any(s.online and s.name == name for s in get_hub().sessions()):
            time.sleep(0.05)
        return device, thread

    if whole_profile:
        # The profile's backend is `hands`, and Hermes was started in a server folder.
        os.environ["TERMINAL_ENV"], os.environ["TERMINAL_CWD"] = "hands", str(server_dir)
        invite = get_hub().invite()
    else:
        tool("before", "terminal", {"command": "pwd"})
        out["on_without_device"] = chat.command("on")
        invite = chat.command("invite").split("'")[1]
    device, serving = up(device_dir, invite=invite)
    if not whole_profile:
        out["on"] = chat.command("on")
    # A relative write before any command has run must still land on the device.
    tool("first", "write_file", {"path": "first.txt", "content": "first\\n"})
    tool("pwd", "terminal", {"command": "pwd"})
    tool("cd", "terminal", {"command": "cd src && pwd"})
    tool("stays", "terminal", {"command": "pwd"})
    tool("read", "read_file", {"path": "../README.md"})
    tool("write", "write_file", {"path": "made.txt", "content": "through Hermes\\n"})
    tool("escape", "terminal", {"command": f"echo x > {server_dir}/escape.txt"})
    # A process left running: it starts, a later command sees it, and it can be stopped.
    tool("bg", "terminal", {"command": "sleep 300", "background": True})
    tool("bg_poll", "process", {"action": "poll", "session_id": out["bg"]["session"]})
    tool("bg_stop", "terminal", {"command": f"kill {out['bg']['pid']} && echo stopped"})
    # The device goes down and comes back: the same conversation carries on.
    device.stop(); serving.join(20)
    tool("down", "terminal", {"command": "pwd"})
    device, serving = up(device_dir)
    tool("back", "terminal", {"command": "pwd"})
    if not whole_profile:
        out["status"] = chat.command("status")
        # A second machine: switching sends this conversation's commands there, and back.
        other, other_serving = up(base / "device-project-2", name="desktop",
                                  invite=chat.command("invite").split("'")[1], state=base / "device-state-2")
        out["on_other"] = chat.command("on desktop")
        tool("other", "terminal", {"command": "pwd"})
        tool("other_write", "write_file", {"path": "there.txt", "content": "x\\n"})
        out["on_first"] = chat.command("on laptop")
        tool("first_again", "terminal", {"command": "pwd"})
        # A conversation that has only ever run on a device still returns to the server.
        tool("fresh", "terminal", {"command": "pwd"}, task="chat-2")
        # A conversation with settings of its own gets them back when Hands is switched off.
        from tools.terminal_tool import register_task_env_overrides, resolve_task_overrides
        register_task_env_overrides("chat-3", {"cwd": str(server_dir)})
        tool("kept", "terminal", {"command": "pwd"}, task="chat-3")
        out["off"] = chat.command("off")
        tool("after", "terminal", {"command": "pwd"})
        tool("fresh_after", "terminal", {"command": "pwd"}, task="chat-2")
        out["restored"] = resolve_task_overrides("chat-3")
        other.stop()
    else:
        # The whole profile runs on the device: /hands off must say so, not claim a switch.
        out["off"] = chat.command("off")
        tool("after", "terminal", {"command": "pwd"})
        out["status"] = chat.command("status")
    device.stop()
    print("RESULT " + json.dumps(out))
''')


def _run(tmp_path, mode):
    home = tmp_path / "hermes-home"
    (home / "plugins").mkdir(parents=True)
    if not _plugin_installed():
        shutil.copytree(ROOT, home / "plugins" / "hermes-tenuo", ignore=_IGNORE)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - hermes-tenuo\n  entries:\n    hermes-tenuo:\n      hands:\n"
        f"        listen: '127.0.0.1:{port}'\n")
    (tmp_path / "device-project-2").mkdir()
    project = tmp_path / "device-project"
    (project / "src").mkdir(parents=True)
    (project / "README.md").write_text("device readme\n")
    server_dir = tmp_path / "server-dir"
    server_dir.mkdir()
    env = dict(os.environ, HERMES_HOME=str(home), TENUO_HANDS_HOME=str(tmp_path / "device-state"))
    for name in ("TERMINAL_ENV", "TERMINAL_CWD", "TENUO_WARRANT", "TENUO_SIGNING_KEY"):
        env.pop(name, None)
    done = subprocess.run([sys.executable, "-c", SCRIPT, str(tmp_path), mode], capture_output=True, text=True,
                          env=env, timeout=180, cwd=str(tmp_path))
    lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    assert lines, done.stdout[-2000:] + done.stderr[-4000:]
    return json.loads(lines[-1][7:]), project, server_dir


def _on_the_device(out, project, server_dir):
    there = os.path.realpath(project)
    assert (project / "first.txt").read_text() == "first\n", out["first"]
    assert out["pwd"]["text"].strip() == there
    assert out["cd"]["text"].strip() == os.path.join(there, "src")
    assert out["stays"]["text"].strip() == os.path.join(there, "src")
    assert "device readme" in out["read"]["text"]
    assert (project / "src" / "made.txt").read_text() == "through Hermes\n"
    assert out["escape"]["exit"] != 0
    assert not list(Path(server_dir).iterdir())
    # Each result says which machine it ran on; a refusal there also says what it shares.
    for key in ("first", "pwd", "read", "write", "escape"):
        assert out[key]["ran_on"] and "laptop" in out[key]["ran_on"] and there in out[key]["ran_on"], (key, out[key])
    assert out["escape"]["note"] and "shares only" in out["escape"]["note"], out["escape"]
    assert out["pwd"]["note"] is None
    log = (project.parent / "device-state" / "log.jsonl").read_text()
    assert '"command": "pwd"' in log and '"command": "cd src && pwd"' in log
    assert out["bg"]["pid"], out["bg"]
    assert "running" in out["bg_poll"]["text"], out["bg_poll"]
    assert out["bg_stop"]["text"].strip() == "stopped", out["bg_stop"]
    assert out["down"]["exit"] != 0 and "hands up" in out["down"]["text"], out["down"]
    assert out["back"]["text"].strip().startswith(there), out["back"]


def test_one_conversation_switches_to_the_device_and_back(tmp_path):
    out, project, server_dir = _run(tmp_path, "chat")
    here = os.path.realpath(server_dir)
    assert out["before"]["text"].strip() == here
    assert out["before"]["ran_on"] is None and out["after"]["ran_on"] is None  # on the server: not marked
    assert "desktop" in out["other"]["ran_on"], out["other"]
    assert "no device is up" in out["on_without_device"]
    assert "laptop" in out["on"]
    _on_the_device(out, project, server_dir)
    assert "laptop: up" in out["status"] and "runs on: laptop" in out["status"]
    second = os.path.realpath(tmp_path / "device-project-2")
    assert out["other"]["text"].strip() == second, out["other"]
    assert (tmp_path / "device-project-2" / "there.txt").exists()
    assert out["first_again"]["text"].strip().startswith(os.path.realpath(project)), out["first_again"]
    assert out["fresh"]["text"].strip() == os.path.realpath(project)
    assert out["after"]["text"].strip() == here
    assert out["fresh_after"]["text"].strip() == here, out["fresh_after"]
    assert out["kept"]["text"].strip() == os.path.realpath(project), out["kept"]
    assert out["restored"] == {"cwd": str(server_dir)}, out["restored"]


def test_a_profile_whose_backend_is_hands(tmp_path):
    out, project, server_dir = _run(tmp_path, "profile")
    _on_the_device(out, project, server_dir)
    assert "cannot move" in out["off"] and "server again" not in out["off"], out["off"]
    assert out["after"]["text"].strip().startswith(os.path.realpath(project)), out["after"]
    assert "the server" not in out["status"].splitlines()[-1], out["status"]
