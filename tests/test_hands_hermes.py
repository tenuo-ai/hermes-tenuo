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
    base = Path(sys.argv[1])
    device_dir, server_dir = base / "device-project", base / "server-dir"
    os.chdir(server_dir)

    from hermes_cli.plugins import discover_plugins
    discover_plugins(force=True)
    assert "hermes_tenuo" in sys.modules, "Hermes did not load the plugin"
    from model_tools import handle_function_call
    from hermes_tenuo.hands import chat
    from hermes_tenuo.hands.device import Device
    from hermes_tenuo.hands.hub import get_hub

    out = {}
    def tool(key, name, args):
        raw = handle_function_call(name, args, task_id="chat-1", session_id="s1", tool_call_id=key)
        try:
            data = json.loads(raw)
        except ValueError:
            data = {"output": raw}
        out[key] = {"exit": data.get("exit_code"), "text": str(data.get("output", data.get("content", data)))}

    tool("before", "terminal", {"command": "pwd"})
    out["on_without_device"] = chat.command("on")
    invite = chat.command("invite").split("'")[1]
    device = Device(invite, str(device_dir), 600, name="laptop", say=lambda text: None)
    threading.Thread(target=device.serve, daemon=True).start()
    deadline = time.time() + 15
    while time.time() < deadline and not any(s.online for s in get_hub().sessions()):
        time.sleep(0.05)
    out["on"] = chat.command("on")
    tool("pwd", "terminal", {"command": "pwd"})
    tool("cd", "terminal", {"command": "cd src && pwd"})
    tool("stays", "terminal", {"command": "pwd"})
    tool("read", "read_file", {"path": "../README.md"})
    tool("write", "write_file", {"path": "made.txt", "content": "through Hermes\\n"})
    tool("escape", "terminal", {"command": f"echo x > {server_dir}/escape.txt"})
    out["status"] = chat.command("status")
    out["off"] = chat.command("off")
    tool("after", "terminal", {"command": "pwd"})
    device.stop()
    print("RESULT " + json.dumps(out))
''')


def test_one_conversation_switches_to_the_device_and_back(tmp_path):
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
    project = tmp_path / "device-project"
    (project / "src").mkdir(parents=True)
    (project / "README.md").write_text("device readme\n")
    server_dir = tmp_path / "server-dir"
    server_dir.mkdir()
    env = dict(os.environ, HERMES_HOME=str(home), TENUO_HANDS_HOME=str(tmp_path / "device-state"))
    for name in ("TERMINAL_ENV", "TERMINAL_CWD", "TENUO_WARRANT", "TENUO_SIGNING_KEY"):
        env.pop(name, None)
    done = subprocess.run([sys.executable, "-c", SCRIPT, str(tmp_path)], capture_output=True, text=True,
                          env=env, timeout=180, cwd=str(tmp_path))
    lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    assert lines, done.stdout[-2000:] + done.stderr[-4000:]
    out = json.loads(lines[-1][7:])
    here, there = os.path.realpath(server_dir), os.path.realpath(project)

    assert out["before"]["text"].strip() == here
    assert "no device is up" in out["on_without_device"]
    assert "laptop" in out["on"]
    assert out["pwd"]["text"].strip() == there
    assert out["cd"]["text"].strip() == os.path.join(there, "src")
    assert out["stays"]["text"].strip() == os.path.join(there, "src")
    assert "device readme" in out["read"]["text"]
    assert (project / "src" / "made.txt").read_text() == "through Hermes\n"
    assert out["escape"]["exit"] != 0 and not (server_dir / "escape.txt").exists()
    assert "laptop: up" in out["status"] and "runs on: laptop" in out["status"]
    assert out["after"]["text"].strip() == here
    assert not list(Path(server_dir).iterdir())
