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

    os.environ["XDG_CONFIG_HOME"] = str(base / "personal-config")
    config = base / "personal-config" / "hermes-tenuo"
    config.mkdir(parents=True)
    private = device_dir / "private.txt"
    private.write_text("PRIVATE_HERMES_FILE")
    diagnostic = device_dir / "diagnostic.txt"
    diagnostic.write_text("diagnostic token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    from hermes_tenuo.hands import device as device_module
    sent_outputs = []
    original_post = device_module._post
    def capture(url, body, **kwargs):
        if url.endswith("/result"):
            sent_outputs.append(body["output"])
        return original_post(url, body, **kwargs)
    device_module._post = capture
    (config / "never-share").write_text(str(private))
    out = {}
    def tool(key, name, args, task="chat-1"):
        raw = handle_function_call(name, args, task_id=task, session_id="s1", tool_call_id=key)
        try:
            data = json.loads(raw)
        except ValueError:
            data = {"output": raw}
        out[key] = {"exit": data.get("exit_code"), "text": str(data.get("output", data.get("content", data))),
                    "pid": data.get("pid"), "session": data.get("session_id"),
                    "ran_on": data.get("ran_on"), "note": data.get("hands_note"),
                    "hint": data.get("hint"), "status": data.get("status")}

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

    if sys.argv[2] == "gateway":
        import inspect
        from gateway.session_context import set_session_vars
        params = dict(platform="telegram", source="telegram", chat_id="123", chat_type="dm",
                      user_id="alice", session_key="first-session-gateway", session_id="s1")
        if "actor_id" in inspect.signature(set_session_vars).parameters:
            params["actor_id"] = "alice"
        set_session_vars(**params)
        assert chat._owner() == "telegram:alice"

    if whole_profile:
        # The profile's backend is `hands`, and Hermes was started in a server folder.
        os.environ["TERMINAL_ENV"], os.environ["TERMINAL_CWD"] = "hands", str(server_dir)
        invite = get_hub().invite()
    else:
        tool("before", "terminal", {"command": "pwd"})
        out["on_without_device"] = chat.command("on")
        invite = chat.command("setup edit").split("'")[1]
    device, serving = up(device_dir, invite=invite)
    if not whole_profile:
        out["on"] = chat.command("on")
    out["verified"] = chat.command("verify")
    from hermes_cli.plugins import invoke_hook
    out["execution_context"] = next(item for item in invoke_hook("pre_llm_call")
                                    if isinstance(item, dict) and item.get("context", "").startswith("Hands"))
    # A relative write before any command has run must still land on the device.
    tool("first", "write_file", {"path": "first.txt", "content": "first\\n"})
    tool("pwd", "terminal", {"command": "pwd"})
    tool("cd", "terminal", {"command": "cd src && pwd"})
    tool("stays", "terminal", {"command": "pwd"})
    tool("read", "read_file", {"path": "../README.md"})
    tool("write", "write_file", {"path": "made.txt", "content": "through Hermes\\n"})
    tool("escape", "terminal", {"command": f"echo x > {server_dir}/escape.txt"})
    # A system folder: the sandbox refuses this in words on macOS and on Linux alike.
    tool("refused", "terminal", {"command": "echo x > /usr/hands-refusal-probe"})
    # The actual Hermes guard stops these calls before the backend sees them.
    import tools.terminal_tool as terminal_module
    real_guards = terminal_module._check_all_guards
    try:
        for status in ("pending_approval", "blocked"):
            terminal_module._check_all_guards = lambda *a, **kw: {"approved": False, "status": status}
            tool(status, "terminal", {"command": "touch never-approved"})
    finally:
        terminal_module._check_all_guards = real_guards
    assert not (device_dir / "src" / "never-approved").exists()
    # A real device executes once, but its result cannot reach Hermes before the deadline.
    from hermes_tenuo.hands import device as device_module
    real_post = device_module._post
    def lose_result(url, body, timeout):
        if url.endswith("/result"):
            raise ConnectionError("test: result connection dropped")
        return real_post(url, body, timeout=timeout)
    try:
        device_module._post = lose_result
        tool("unknown", "terminal", {"command": "echo once >> once.txt", "timeout": 3})
    finally:
        device_module._post = real_post
    assert (device_dir / "src" / "once.txt").read_text() == "once\\n"
    # A process left running: it starts, a later command sees it, and it can be stopped.
    tool("bg", "terminal", {"command": "sleep 300", "background": True})
    tool("bg_poll", "process", {"action": "poll", "session_id": out["bg"]["session"]})
    tool("private_read", "read_file", {"path": str(private)})
    tool("private_shell", "terminal", {"command": "cat " + str(private)})
    tool("redacted_file", "read_file", {"path": str(diagnostic)})
    tool("redacted", "terminal", {"command": "printf 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"})
    tool("bg_poll_named", "process_manage", {"action": "poll", "session_id": out["bg"]["session"]})
    tool("bg_stop", "terminal", {"command": f"kill {out['bg']['pid']} && echo stopped"})
    # The device goes down and comes back: the same conversation carries on.
    device.stop(); serving.join(20)
    tool("down", "terminal", {"command": "pwd"})
    device, serving = up(device_dir)
    tool("back", "terminal", {"command": "pwd"})
    # Someone else's machine: neither the tool call nor the backend itself runs a stranger's command.
    from hermes_tenuo.hands.backend import HandsEnvironment
    session, asking = get_hub().pick("laptop"), chat._owner
    session.owner = "telegram:alice"
    chat._owner = lambda: "telegram:bob"
    tool("stranger", "terminal", {"command": "echo x > stranger.txt"})
    # A tool that only runs on the server is not theirs to lose.
    out["stranger_server_tool"] = chat.around_tool(tool_name="web_search", args={}, next_call=lambda: "on the server",
                                                   task_id="chat-1")
    shell = HandsEnvironment(cwd=str(device_dir), timeout=30, device="laptop")
    out["stranger_backend"] = str(shell.execute("echo x > stranger2.txt"))
    chat._owner = lambda: "telegram:alice"
    tool("owner", "terminal", {"command": "echo mine"})
    if whole_profile:
        # Each sender has exactly one usable default even with both machines online.
        second, second_thread = up(base / "device-project-2", name="bobs-machine",
                                   invite=get_hub().invite("telegram:bob"), state=base / "device-state-bob")
        try:
            default = HandsEnvironment(cwd=str(server_dir), timeout=30)
            assert default._session.name == "laptop"
            assert "alice-default" in str(default.execute("echo alice-default"))
            chat._owner = lambda: "telegram:bob"
            assert default._current().name == "bobs-machine"
            assert "bob-default" in str(default.execute("echo bob-default"))
            tool("bob_default", "terminal", {"command": "pwd"}, task="bob-chat")
            assert "bobs-machine" in out["bob_default"]["ran_on"], out["bob_default"]
            assert out["bob_default"]["text"].strip() == str(base / "device-project-2")
            chat._owner = lambda: "telegram:alice"
            assert default._current().name == "laptop"
        finally:
            second.stop(); second_thread.join(20)
            get_hub().revoke("bobs-machine")
            os.environ["TENUO_HANDS_HOME"] = str(base / "device-state")
    chat._owner, session.owner = asking, ""
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
    import base64
    token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    encoded = base64.b64encode(("diagnostic token " + token).encode()).decode()
    assert not any(token in result or encoded in result for result in sent_outputs), "secret crossed the device boundary"
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
    assert "PRIVATE_HERMES_FILE" not in out["private_read"]["text"]
    assert "PRIVATE_HERMES_FILE" not in out["private_shell"]["text"]
    assert out["redacted_file"]["text"] == "1|diagnostic token [redacted]", out["redacted_file"]
    assert "ghp_" not in out["redacted"]["text"] and "[redacted]" in out["redacted"]["text"]
    there = os.path.realpath(project)
    assert "Shared folder verified: " + there in out["verified"], out["verified"]
    assert "laptop" in out["execution_context"]["context"]
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
        if out[key]["status"] in ("pending_approval", "blocked"):
            # Hermes held this call for approval (it does for a chat sender): it never
            # reached the machine, so the result must not say it ran there.
            assert out[key]["ran_on"] is None and out[key]["note"] is None, (key, out[key])
            continue
        assert out[key]["ran_on"] and "laptop" in out[key]["ran_on"] and there in out[key]["ran_on"], (key, out[key])
    for key in ("bg_poll", "bg_poll_named"):  # the process tool reports on an earlier process: not marked
        assert out[key]["ran_on"] is None, (key, out[key])
    assert not (project / "stranger.txt").exists() and not (project / "stranger2.txt").exists()
    assert "belongs to the person who paired it" in out["stranger_backend"], out["stranger_backend"]
    assert out["stranger_server_tool"] == "on the server"
    assert out["owner"]["text"].strip() == "mine", out["owner"]
    assert out["refused"]["exit"] != 0 and not os.path.exists("/usr/hands-refusal-probe")
    assert out["refused"]["note"] and "shares only" in out["refused"]["note"], out["refused"]
    assert out["pwd"]["note"] is None
    for key in ("pending_approval", "blocked"):
        assert out[key]["status"] == key and out[key]["ran_on"] is None, out[key]
        assert out[key]["note"] is None, out[key]
    assert out["unknown"]["exit"] == 125, out["unknown"]
    assert "check before running it again" in out["unknown"]["text"], out["unknown"]
    assert "Command timed out" not in out["unknown"]["text"], out["unknown"]
    assert not out["unknown"]["hint"], out["unknown"]
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


@pytest.mark.parametrize("captured", ["captured\n[Command timed out after 3s]", "[Command timed out after 3s]"])
@pytest.mark.parametrize("reply, expected", [
    (("lost reply", 125), 125),
    (("finished", 0), 0),
    (("device timed out", 124), 124),
    (None, 125),
])
def test_adapter_preserves_confirmed_outcome_after_outer_timeout(monkeypatch, reply, expected, captured):
    from types import SimpleNamespace
    from hermes_tenuo.hands.backend import HandsEnvironment, BaseEnvironment
    # Exercise the deadline/drain race without depending on OS scheduling. The
    # full tool-dispatch tests above also drop actual HTTP result submissions.
    # A command that printed nothing gets the marker with no line break before it.
    monkeypatch.setattr(BaseEnvironment, "_wait_for_process", lambda *a, **kw: {
        "output": captured, "returncode": 124, "hermes_timed_out": True,
        "full_output_path": "/tmp/retained-output", "output_total_chars": 10000,
    })
    proc = SimpleNamespace(_hands_reply={} if reply is None else {"result": reply})
    env = object.__new__(HandsEnvironment)
    result = env._wait_for_process(proc, timeout=3, bounded_capture=True)
    assert result["returncode"] == expected
    if expected != 124:
        assert "Command timed out" not in result["output"]
        assert "hermes_timed_out" not in result      # Hermes counts outcomes by this flag first
    else:
        assert result["hermes_timed_out"] is True and "Command timed out" in result["output"]
    if reply is None:
        assert "check before running it again" in result["output"]
    else:
        assert result["full_output_path"] == "/tmp/retained-output"


def _environment(monkeypatch, tmp_path, answer):
    """A Hands environment on Hermes's real `execute`, with a stand-in for the device."""
    import collections
    from hermes_tenuo.hands.backend import HandsEnvironment, BaseEnvironment
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    class Session:
        name, folder, tmp, owner, device = "laptop", "/work/app", "/work/tmp", "", "d1"

    class Hub:
        def pick(self, device, owner):
            return Session()

        def run(self, session, command, **kwargs):
            return answer()

    env = object.__new__(HandsEnvironment)
    env._hub, env._task, env._device = Hub(), "t", "laptop"
    env._session, env._folder = Session(), Session.folder
    env._wrapped = collections.deque(maxlen=32)
    BaseEnvironment.__init__(env, cwd=Session.folder, timeout=1)
    return env


def _after(seconds, answer):
    import time

    def run():
        time.sleep(seconds)
        return answer
    return run


@pytest.mark.parametrize("answer, code, says", [
    (_after(0, ("quick\n", 0)), 0, "quick"),
    # The device answers just after Hermes's deadline, while Hermes is collecting output.
    (_after(1.3, ("done-late\n", 0)), 0, "done-late"),
    (_after(1.2, ("hands: no result came back\n", 125)), 125, "no result came back"),
    # No answer at all: Hermes's outer deadline answers for the wait.
    (_after(30, ("never\n", 0)), 125, "check before running it again"),
])
def test_execute_reports_what_the_device_answered_not_hermes_timeout(monkeypatch, tmp_path, answer, code, says):
    result = _environment(monkeypatch, tmp_path, answer).execute("echo hi", timeout=1)
    assert result["returncode"] == code and says in result["output"], result
    assert "Command timed out" not in result["output"] and "hermes_timed_out" not in result, result


class _SlowToDeliver(str):
    """An answer that is known at once but whose text takes a while to reach Hermes."""

    def encode(self, *args, **kwargs):
        import time
        time.sleep(4)
        return super().encode(*args, **kwargs)


@pytest.mark.parametrize("text, code", [
    ("done, with output\n", 0),
    ("device timeout diagnostics\n", 124),
    ("hands: no result came back: check before running it again\n", 125),
])
def test_an_answer_known_before_its_text_arrives_keeps_its_text(monkeypatch, tmp_path, text, code):
    # Hermes's inner wait and its outer deadline both end before the text is delivered.
    env = _environment(monkeypatch, tmp_path, _after(0.2, (_SlowToDeliver(text), code)))
    result = env.execute("echo hi", timeout=1)
    assert result["returncode"] == code and result["output"] == text, result
    assert bool(result.get("hermes_timed_out")) == (code == 124)
    assert "Command timed out" not in result["output"]


def test_partly_collected_output_is_replaced_by_the_whole_answer(monkeypatch):
    from types import SimpleNamespace
    from hermes_tenuo.hands.backend import HandsEnvironment, BaseEnvironment
    from tools.environments.base_output import _BoundedOutputCollector
    whole = "line one\nline two\nline three\n"
    collected = _BoundedOutputCollector(50_000)
    collected.append("line one\n")                       # all Hermes had when its deadline passed
    monkeypatch.setattr(BaseEnvironment, "_wait_for_process", lambda *a, **kw: {
        "output": "line one\n\n[Command timed out after 3s]", "returncode": 124, "hermes_timed_out": True})
    proc = SimpleNamespace(_hands_reply={"result": (whole, 0)})
    env = object.__new__(HandsEnvironment)
    result = env._wait_for_process(proc, timeout=3, output=collected, bounded_capture=False)
    assert result == {"output": whole, "returncode": 0}
    # Fully collected output is kept as Hermes captured it, with what it knows about it.
    collected.append("line two\nline three\n")
    monkeypatch.setattr(BaseEnvironment, "_wait_for_process", lambda *a, **kw: {
        "output": whole + "\n[Command timed out after 3s]", "returncode": 124, "hermes_timed_out": True,
        "full_output_path": "/tmp/retained-output"})
    result = env._wait_for_process(proc, timeout=3, output=collected, bounded_capture=True)
    assert result == {"output": whole, "returncode": 0, "full_output_path": "/tmp/retained-output"}


def test_a_large_answer_rebuilt_after_the_deadline_is_capped_like_any_output(monkeypatch, tmp_path):
    big = "x" * 400_000 + "\nEND\n"
    env = _environment(monkeypatch, tmp_path, _after(0.2, (_SlowToDeliver(big), 0)))
    result = env.execute("echo hi", timeout=1, bounded_capture=True)
    assert result["returncode"] == 0 and result["output"].endswith("END\n"), result["output"][-80:]
    assert len(result["output"]) < len(big) and result.get("output_total_chars") == len(big), {
        k: v for k, v in result.items() if k != "output"}


def test_a_command_that_exits_124_by_itself_is_not_a_timeout(monkeypatch, tmp_path):
    # It answers at once, long before either deadline: an ordinary nonzero exit.
    env = _environment(monkeypatch, tmp_path, _after(0, ("my own exit\n", 124)))
    result = env.execute("exit 124", timeout=5)
    assert result["returncode"] == 124 and result["output"] == "my own exit\n", result
    assert "hermes_timed_out" not in result and "Command timed out" not in result["output"]


def test_a_large_confirmed_timeout_keeps_its_whole_output_recoverable(monkeypatch, tmp_path):
    import os
    big = "y" * 400_000 + "\nhands: stopped after 1 seconds\n"
    env = _environment(monkeypatch, tmp_path, _after(0.2, (_SlowToDeliver(big), 124)))
    result = env.execute("long job", timeout=1, bounded_capture=True)
    assert result["returncode"] == 124 and result.get("hermes_timed_out") is True
    assert len(result["output"]) < len(big) and result["output"].rstrip().endswith("stopped after 1 seconds")
    assert result.get("output_total_chars") == len(big), {k: v for k, v in result.items() if k != "output"}
    assert os.path.getsize(result["full_output_path"]) >= len(big)      # rebuilt once, spilled once


def test_two_rebuilt_answers_in_one_second_each_keep_their_spill(monkeypatch, tmp_path):
    from hermes_tenuo.hands.backend import _from_answer
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    big, proc = "z" * 300_000, object()
    first = _from_answer((big, 0), True, proc)
    second = _from_answer((big, 0), True, proc)                 # same process, same second
    assert first["full_output_path"] != second["full_output_path"]
    assert first["output_total_chars"] == second["output_total_chars"] == len(big)


def test_a_timeout_the_device_confirms_stays_a_timeout(monkeypatch, tmp_path):
    env = _environment(monkeypatch, tmp_path, _after(1.2, ("hands: stopped after 1 seconds\n", 124)))
    result = env.execute("sleep 9", timeout=1)
    assert result["returncode"] == 124 and result.get("hermes_timed_out") is True, result


def test_calls_sharing_an_environment_are_settled_separately(monkeypatch, tmp_path):
    import threading
    answers = iter([_after(1.3, ("first-late\n", 0)), _after(30, ("never\n", 0))])
    lock = threading.Lock()

    def answer():
        with lock:
            mine = next(answers)
        return mine()
    env = _environment(monkeypatch, tmp_path, answer)
    results = {}

    def call(name):
        results[name] = env.execute(f"echo {name}", timeout=1)
    first = threading.Thread(target=call, args=("a",))
    first.start()
    import time
    time.sleep(0.2)
    second = threading.Thread(target=call, args=("b",))
    second.start()
    first.join(20)
    second.join(20)
    assert results["a"]["returncode"] == 0 and "first-late" in results["a"]["output"], results
    assert results["b"]["returncode"] == 125 and "check before running it again" in results["b"]["output"], results


def test_first_session_with_real_gateway_identity(tmp_path):
    out, project, server_dir = _run(tmp_path, "gateway")
    _on_the_device(out, project, server_dir)
    assert out["after"]["text"].strip() == os.path.realpath(server_dir), out["after"]
    assert out["fresh_after"]["text"].strip() == os.path.realpath(server_dir), out["fresh_after"]


@pytest.mark.parametrize("whole, captured", [("x", ""), ("xy", "x"), ("\ufeffxy", "x")])
@pytest.mark.parametrize("code", [0, 124, 125])
def test_one_missing_character_rebuilds_confirmed_reply(monkeypatch, whole, captured, code):
    from types import SimpleNamespace
    from hermes_tenuo.hands.backend import HandsEnvironment, BaseEnvironment
    from tools.environments.base_output import _BoundedOutputCollector
    collected = _BoundedOutputCollector(50_000)
    collected.append(captured)
    monkeypatch.setattr(BaseEnvironment, "_wait_for_process", lambda *a, **kw: {
        "output": captured + "\n[Command timed out after 3s]", "returncode": 124,
        "hermes_timed_out": True})
    proc = SimpleNamespace(_hands_reply={"result": (whole, code)})
    result = object.__new__(HandsEnvironment)._wait_for_process(proc, timeout=3, output=collected)
    assert result["output"] == whole and result["returncode"] == code
    assert bool(result.get("hermes_timed_out")) == (code == 124)
