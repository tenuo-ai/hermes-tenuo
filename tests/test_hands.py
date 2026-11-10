"""Hands: a server hub and a device talking over real local HTTP."""

from __future__ import annotations

import builtins
import json
import os
import subprocess
import sys
import threading
import time

from pathlib import Path

import pytest

from hermes_tenuo.hands import device as device_module
from hermes_tenuo.hands import hub as hub_module
from hermes_tenuo.hands import chat, sandbox, wire
from hermes_tenuo.hands.device import Device, HandsError
from hermes_tenuo.hands.hub import HandsUnavailable, Hub, Refused

sandboxed = pytest.mark.skipif(sandbox.available() is None, reason="needs sandbox-exec or bubblewrap")


@pytest.fixture
def hub(tmp_path):
    h = Hub(state_dir=tmp_path / "server-state")
    h.listen("127.0.0.1:0")
    yield h
    h.close()


@pytest.fixture
def folder(tmp_path, monkeypatch):
    monkeypatch.setenv("TENUO_HANDS_HOME", str(tmp_path / "device-state"))
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "README.md").write_text("device readme\n")
    return project


class Running:
    """A device serving in a background thread."""

    def __init__(self, device: Device):
        self.device, self.lines = device, []
        device.say = self.lines.append
        self.thread = threading.Thread(target=device.serve, daemon=True)
        self.thread.start()

    def stop(self):
        self.device.stop()


def up(hub: Hub, folder, ttl=600, name="laptop", invite=True, **kwargs) -> Running:
    running = Running(Device(hub.invite() if invite else None, str(folder), ttl, name=name, **kwargs))
    deadline = time.time() + 10
    while time.time() < deadline and not any(s.online and s.name == name for s in hub.sessions()):
        time.sleep(0.05)
    return running


def run(hub: Hub, cmd: str, name="laptop", **kwargs):
    kwargs.setdefault("login", False)
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("stdin", None)
    return hub.run(hub.pick(name), cmd, **kwargs)


# --- the happy path -------------------------------------------------------------

@sandboxed
def test_command_runs_in_the_device_folder(hub, folder):
    device = up(hub, folder)
    out, code = run(hub, "pwd && cat README.md")
    assert code == 0
    assert out.splitlines() == [os.path.realpath(folder), "device readme"]
    out, code = run(hub, "cat > note.txt", stdin="from the server\n")
    assert code == 0 and (folder / "note.txt").read_text() == "from the server\n"
    assert run(hub, "exit 7")[1] == 7
    device.stop()


@sandboxed
def test_writes_outside_the_folder_fail(hub, folder, tmp_path):
    up(hub, folder)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    out, code = run(hub, f"echo x > {outside}/escape.txt")
    assert code != 0 and not (outside / "escape.txt").exists()
    home_file = os.path.expanduser("~/.hermes-tenuo-hands-test-escape")
    assert run(hub, f"echo x > {home_file}")[1] != 0 and not os.path.exists(home_file)


@sandboxed
@pytest.mark.skipif(sys.platform != "darwin", reason="private paths differ per platform")
def test_private_files_are_unreadable(hub, folder):
    up(hub, folder)
    ssh = os.path.expanduser("~/.ssh")
    if not os.path.isdir(ssh):
        pytest.skip("no ~/.ssh on this machine")
    out, code = run(hub, f"ls {ssh}")
    assert code != 0


@sandboxed
def test_device_log_shows_the_plain_command(hub, folder, tmp_path):
    device = up(hub, folder)
    run(hub, "true # wrapped by Hermes", shown="true")
    log = (tmp_path / "device-state" / "log.jsonl").read_text()
    assert '"command": "true"' in log and '"exit": 0' in log
    assert any("exit 0" in line for line in device.lines)


# --- pairing ----------------------------------------------------------------------

def test_invite_works_once(hub, folder):
    invite = hub.invite()
    Device(invite, str(folder), 60, name="one", allow_unsandboxed=True).pair()
    os.environ["TENUO_HANDS_HOME"] = str(folder.parent / "second-device")
    with pytest.raises(HandsError, match="isn't paired"):
        Device(invite, str(folder), 60, name="two", allow_unsandboxed=True).pair()


def test_paired_device_comes_back_without_an_invite(hub, folder):
    Device(hub.invite(), str(folder), 60, allow_unsandboxed=True).pair()
    Device(None, str(folder), 60, allow_unsandboxed=True).pair()
    assert len(hub.sessions()) == 1


def test_unknown_device_needs_an_invite(hub, folder):
    with pytest.raises(HandsError, match="no server paired"):
        Device(None, str(folder), 60, allow_unsandboxed=True)
    bogus = wire.Invite(hub.public_url, "not-a-real-secret", wire.key_text(hub.key.public_key)).render()
    with pytest.raises(HandsError, match="isn't paired"):
        Device(bogus, str(folder), 60, allow_unsandboxed=True).pair()


def test_grant_for_another_server_is_refused(hub, folder):
    from tenuo import SigningKey
    other = wire.key_text(SigningKey.generate().public_key)
    invite = wire.Invite.parse(hub.invite())
    wrong = wire.Invite(invite.url, invite.secret, other).render()
    with pytest.raises(HandsError, match="not from this device to this server"):
        Device(wrong, str(folder), 60, allow_unsandboxed=True).pair()


def test_two_devices_cannot_share_a_name(hub, folder, tmp_path, monkeypatch):
    Device(hub.invite(), str(folder), 60, name="laptop", allow_unsandboxed=True).pair()
    monkeypatch.setenv("TENUO_HANDS_HOME", str(tmp_path / "other-device"))
    with pytest.raises(HandsError, match="already called"):
        Device(hub.invite(), str(folder), 60, name="laptop", allow_unsandboxed=True).pair()


def test_revoked_device_is_cut_off(hub, folder):
    device = Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    device.pair()
    assert hub.revoke(device.name)
    with pytest.raises(HandsError, match="no session"):
        device.poll()
    with pytest.raises(HandsError, match="isn't paired"):
        Device(None, str(folder), 60, allow_unsandboxed=True).pair()


def test_home_and_root_are_not_shareable(hub):
    for bad in ("~", "/"):
        with pytest.raises(HandsError, match="project folder"):
            Device(hub.invite(), bad, 60, allow_unsandboxed=True)


def test_no_sandbox_refuses_unless_asked(hub, folder, monkeypatch):
    monkeypatch.setattr(sandbox, "available", lambda: None)
    with pytest.raises(sandbox.SandboxUnavailable):
        Device(hub.invite(), str(folder), 60)


# --- what the device refuses, whatever the server sends -------------------------------

def _job(hub: Hub, device: Device, **changes):
    """A correctly signed job from the hub, then tampered with."""
    session = hub.pick(device.name)
    job_id = changes.pop("id", "job-1")
    cmd = "echo ok"
    args = {"dir": session.folder, "cmd": wire.digest(job_id, cmd, False, None, 30, "", 0, "")}
    job = {"id": job_id, "cmd": cmd, "login": False, "timeout": 30, "stdin": None, "shown": "",
           "dir": session.folder, "chain": [session.grant.to_base64()],
           "pop": wire.sign(session.grant, hub.key, wire.TOOL, args)}
    job.update(changes)
    return job


@pytest.fixture
def paired(hub, folder):
    device = Device(hub.invite(), str(folder), 600, allow_unsandboxed=True)
    device.pair()
    return device


def test_device_accepts_a_signed_command(hub, paired):
    assert paired.verify(_job(hub, paired)) == paired.folder


def test_device_refuses_a_changed_command(hub, paired):
    with pytest.raises(Exception):
        paired.verify(_job(hub, paired, cmd="rm -rf ."))


def test_device_refuses_a_replayed_command(hub, paired):
    job = _job(hub, paired)
    paired.verify(job)
    with pytest.raises(HandsError, match="already run"):
        paired.verify(job)


def test_device_refuses_a_replayed_command_after_restart(hub, folder, paired):
    job = _job(hub, paired)
    paired.verify(job)
    restarted = Device(None, str(folder), 600, allow_unsandboxed=True)
    with pytest.raises(HandsError, match="old Hands session"):
        restarted.verify(job)


def test_device_refuses_another_folder(hub, paired, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(Exception):
        paired.verify(_job(hub, paired, dir=str(other)))


def test_device_refuses_a_command_signed_by_someone_else(hub, paired):
    from tenuo import SigningKey
    session = hub.pick(paired.name)
    args = {"dir": session.folder, "cmd": wire.digest("job-9", "echo ok", False, None, 30, "", 0, "")}
    forged = wire.sign(session.grant, SigningKey.generate(), wire.TOOL, args)
    with pytest.raises(Exception):
        paired.verify(_job(hub, paired, id="job-9", pop=forged))


def test_device_refuses_a_grant_it_did_not_sign(hub, paired):
    from tenuo import SigningKey
    stranger = SigningKey.generate()
    grant = wire.mint_grant(stranger, hub.key.public_key, paired.folder, 600)
    args = {"dir": paired.folder, "cmd": wire.digest("job-8", "echo ok", False, None, 30, "", 0, "")}
    job = _job(hub, paired, id="job-8", chain=[grant.to_base64()], pop=wire.sign(grant, hub.key, wire.TOOL, args))
    with pytest.raises(Exception):
        paired.verify(job)


def test_device_refuses_after_its_window(hub, paired):
    paired.expires = time.time() - 1
    with pytest.raises(HandsError, match="window has ended"):
        paired.verify(_job(hub, paired))


def test_device_commands_do_not_inherit_exported_secrets(hub, paired, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-reach-a-command")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "also-must-not-reach-a-command")
    monkeypatch.setenv("PATH", "/safe/bin")
    env = paired._env()
    # The person's own path, after this machine's developer tools where there are any.
    assert env["PATH"] == os.pathsep.join(["/safe/bin", *paired._tools[0]])
    assert env["HOME"] == paired.tmp
    assert env["TMPDIR"] == paired.tmp
    assert "OPENAI_API_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_selected_device_routing_failure_does_not_run_on_server(monkeypatch):
    monkeypatch.setitem(chat._wanted, "", "laptop")
    real_import = builtins.__import__

    def broken_import(name, *args, **kwargs):
        if name == "hermes_tenuo.hands.backend":
            raise ImportError("simulated incompatible Hermes integration")
        return real_import(name, *args, **kwargs)

    called = []
    monkeypatch.setattr(builtins, "__import__", broken_import)
    with pytest.raises(HandsUnavailable, match="was not run"):
        chat.around_tool(next_call=lambda: called.append(True))
    assert not called


@sandboxed
def test_subfolder_grant_limits_writes_to_the_subfolder(hub, folder):
    """A narrower warrant (what a subagent would hold) is enforced by the device alone."""
    from tenuo import Subpath, Wildcard
    device = Device(hub.invite(), str(folder), 600)
    device.pair()
    session = hub.pick(device.name)
    sub = os.path.join(session.folder, "src")
    builder = session.grant.attenuate_builder()
    builder.with_capability(wire.TOOL, {"dir": Subpath(sub), "cmd": Wildcard()})
    child = builder.delegate(hub.key)
    cmd = "echo in > inside.txt; echo out > ../outside.txt; true"
    args = {"dir": sub, "cmd": wire.digest("job-sub", cmd, False, None, 30, "", 0, "")}
    job = {"id": "job-sub", "cmd": cmd, "login": False, "timeout": 30, "stdin": None, "shown": "", "dir": sub,
           "chain": [session.grant.to_base64(), child.to_base64()], "pop": wire.sign(child, hub.key, wire.TOOL, args)}
    where = device.verify(job)
    device.run(job, where)
    assert (folder / "src" / "inside.txt").exists() and not (folder / "outside.txt").exists()
    # The narrowed warrant cannot be used for the parent folder.
    args = {"dir": session.folder, "cmd": wire.digest("job-up", cmd, False, None, 30, "", 0, "")}
    wider = dict(job, id="job-up", dir=session.folder, pop=wire.sign(child, hub.key, wire.TOOL, args))
    with pytest.raises(Exception):
        device.verify(wider)


# --- what the server refuses ----------------------------------------------------------

def test_server_refuses_unsigned_polls_and_results(hub, paired):
    with pytest.raises(Refused):
        hub.poll({"device": paired.me, "nonce": "n", "sig": wire.b64(b"x" * 64)})
    with pytest.raises(Refused):
        hub.result({"device": paired.me, "job": "j", "output": "forged", "returncode": 0, "sig": wire.b64(b"x" * 64)})


def test_server_refuses_a_reused_poll(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.05)
    body = {"device": paired.me, "nonce": "once", "sig": wire.sign(paired.identity, paired.key, wire.TOOL_POLL, wire.request("poll", "once"))}
    assert hub.poll(dict(body)) == {"job": None}
    with pytest.raises(Refused, match="already used"):
        hub.poll(dict(body))


def test_no_device_gives_a_useful_message(hub):
    with pytest.raises(HandsUnavailable, match="hands up"):
        hub.pick()


def test_invite_round_trips():
    from tenuo import SigningKey
    key = wire.key_text(SigningKey.generate().public_key)
    for url in ("http://vps.example:8765", "https://hermes.example"):
        assert wire.Invite.parse(wire.Invite(url, "s3cret", key).render()) == wire.Invite(url, "s3cret", key)
    for bad in ("http://x/y#z", "hands://host:1/", "hands://host:1/secret", "hands://host:1/secret#not-a-key"):
        with pytest.raises(Exception):
            wire.Invite.parse(bad)


# --- one sandbox for the whole session ----------------------------------------------------

@sandboxed
def test_background_process_outlives_its_command_and_a_later_one_can_stop_it(hub, folder):
    up(hub, folder)
    started = time.time()
    out, code = run(hub, "(sleep 1; echo late > late.txt) >/dev/null 2>&1 & sleep 300 >/dev/null 2>&1 & echo $!")
    assert code == 0 and time.time() - started < 10, "a command that leaves a process running must still return"
    pid = out.strip().splitlines()[-1]
    deadline = time.time() + 10
    while time.time() < deadline and not (folder / "late.txt").exists():
        time.sleep(0.1)
    assert (folder / "late.txt").exists()
    assert run(hub, f"kill {pid} && echo stopped")[0].strip() == "stopped"
    assert run(hub, f"kill -0 {pid} 2>/dev/null; echo $?")[0].strip() != "0"


@sandboxed
def test_background_processes_stop_when_the_device_goes_down(hub, folder, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    run(hub, "(while true; do date +%s%N > tick.txt; sleep 0.2; done) >/dev/null 2>&1 &")
    time.sleep(1)
    assert (folder / "tick.txt").exists()
    device.stop()
    device.thread.join(wire.POLL_SECONDS + 20)
    time.sleep(1)
    seen = (folder / "tick.txt").read_text()
    time.sleep(1)
    assert (folder / "tick.txt").read_text() == seen


@sandboxed
def test_command_cannot_signal_a_process_outside_the_sandbox(hub, folder):
    up(hub, folder)
    outside = subprocess.Popen(["sleep", "60"])
    try:
        run(hub, f"kill -9 {outside.pid}")
        time.sleep(0.3)
        assert outside.poll() is None
    finally:
        outside.kill()


@sandboxed
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS services")
def test_command_cannot_ask_macos_to_run_something_outside(hub, folder, tmp_path):
    up(hub, folder)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    app = folder / "Run.app" / "Contents" / "MacOS"
    app.mkdir(parents=True)
    (app / "Run").write_text(f"#!/bin/sh\necho out > {outside}/launched.txt\n")
    (app / "Run").chmod(0o755)
    (folder / "Run.app" / "Contents" / "Info.plist").write_text(
        '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>Run</string>'
        "<key>CFBundleIdentifier</key><string>test.hands.run</string><key>LSUIElement</key><true/></dict></plist>")
    run(hub, "open -g -j ./Run.app; sleep 2; pbpaste >/dev/null && echo clipboard")
    assert not (outside / "launched.txt").exists()
    assert "clipboard" not in run(hub, "pbpaste >/dev/null 2>&1 && echo clipboard")[0]


@sandboxed
def test_temp_files_work_with_the_default_state_folder(hub, tmp_path, monkeypatch):
    """The default state folder is inside a path commands cannot read; their temp folder still works."""
    monkeypatch.delenv("TENUO_HANDS_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    project = tmp_path / "project"
    project.mkdir()
    up(hub, project)
    out, code = run(hub, 'mkdir -p "$TMPDIR" && f="$TMPDIR/probe.txt"; echo kept > "$f" && cat "$f"')
    assert (out.strip(), code) == ("kept", 0)
    key = tmp_path / "home" / ".hermes-tenuo" / "hands" / "device.key"
    assert key.exists() and run(hub, f"cat {key}")[1] != 0


# --- a command never runs after the caller was told it did not ------------------------------

def test_command_that_reaches_the_device_too_late_is_refused(hub, paired):
    job = _job(hub, paired)  # signed with a 30 second budget
    paired._polled_at = time.time() - 10
    assert 18 <= paired.budget(job) <= 20
    paired._polled_at = time.time() - 31
    with pytest.raises(HandsError, match="too late"):
        paired.budget(job)


def test_command_nobody_waits_for_is_never_handed_over(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    monkeypatch.setattr(hub_module, "GRACE_SECONDS", 0.2)
    session = hub.pick(paired.name)
    out, code = hub.run(session, "echo never", login=False, timeout=1, stdin=None)
    assert code == 124 and "did not answer" in out
    assert paired.poll() is None


def test_command_not_started_in_time_is_reported_as_not_run(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    session = hub.pick(paired.name)
    result = {}
    waiter = threading.Thread(target=lambda: result.update(r=hub.run(session, "echo never", login=False, timeout=1, stdin=None)))
    waiter.start()
    time.sleep(1.3)
    assert paired.poll() is None
    waiter.join(5)
    assert result["r"][1] == 124 and "was not run" in result["r"][0]


def test_device_counts_as_up_while_it_runs_a_long_command(hub, paired):
    session = hub.pick(paired.name)
    session.last_seen = time.time() - 600
    assert not session.online
    session.running_until = time.time() + 60
    assert session.online


def test_device_going_down_is_known_at_once(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    session = hub.pick(paired.name)
    result = {}
    waiter = threading.Thread(target=lambda: result.update(r=hub.run(session, "echo x", login=False, timeout=60, stdin=None)))
    waiter.start()
    time.sleep(0.2)
    paired.bye()
    waiter.join(5)
    assert result["r"][1] == 127 and "went down" in result["r"][0]
    with pytest.raises(HandsUnavailable):
        hub.pick(paired.name)


def test_waiting_command_follows_a_device_that_comes_back(hub, folder, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    old = hub.pick(paired.name)
    result = {}
    waiter = threading.Thread(target=lambda: result.update(r=hub.run(old, "echo x", login=False, timeout=30, stdin=None)))
    waiter.start()
    time.sleep(0.2)
    again = Device(None, str(folder), 600, allow_unsandboxed=True)  # the device restarted
    again.pair()
    job = again.poll()
    assert job is not None and again.verify(job) == again.folder
    again.report(job["id"], "x\n", 0)
    waiter.join(5)
    assert result["r"] == ("x\n", 0)


def test_command_a_restarted_device_had_is_reported_as_unknown(hub, folder, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    result = {}
    waiter = threading.Thread(target=lambda: result.update(
        r=hub.run(hub.pick(paired.name), "echo x", login=False, timeout=30, stdin=None)))
    waiter.start()
    assert paired.poll() is not None  # the device took the command, then died
    Device(None, str(folder), 600, allow_unsandboxed=True).pair()
    waiter.join(5)
    assert result["r"][1] == 125 and "not known whether it ran" in result["r"][0]


# --- what a command cannot do to the device itself ------------------------------------------

@sandboxed
def test_device_state_is_hidden_wherever_it_is_kept(hub, folder, tmp_path):
    up(hub, folder)
    key = tmp_path / "device-state" / "device.key"
    assert key.exists()
    # macOS refuses to open the folder; Linux shows it with only the temp folder inside.
    out, _ = run(hub, f"cat {key}; echo cat=$?; ls {key.parent} 2>/dev/null")
    assert "cat=0" not in out and key.read_text().strip() not in out
    assert "device.key" not in out.split("cat=")[1] and "log.jsonl" not in out


def test_shared_folder_and_state_folder_must_be_separate(hub, folder, monkeypatch):
    monkeypatch.setenv("TENUO_HANDS_HOME", str(folder / ".hands"))
    with pytest.raises(HandsError, match="must be separate"):
        Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    monkeypatch.setenv("TENUO_HANDS_HOME", str(folder.parent))
    with pytest.raises(HandsError, match="must be separate"):
        Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)


@sandboxed
def test_output_is_not_read_through_a_swapped_file(hub, folder, tmp_path):
    up(hub, folder)
    secret = tmp_path / "device-state" / "device.key"
    out, code = run(hub, f'for f in "$TMPDIR"/.hands-out-*; do rm -f "$f"; ln -s {secret} "$f"; done; echo swapped')
    assert secret.read_text().strip() not in out
    assert run(hub, "echo fine")[0].strip() == "fine"


@sandboxed
def test_everything_left_running_stops_with_the_device(hub, folder, monkeypatch):
    """Also what ignores a request to stop, and what moved to a session of its own."""
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    run(hub, "(trap '' TERM; while true; do date +%s%N > stubborn.txt; sleep 0.2; done) >/dev/null 2>&1 &")
    run(hub, "python3 -c \"import os, time\nos.setsid()\nwhile True:\n    open('detached.txt', 'w').write(str(time.time()))\n"
             "    time.sleep(0.2)\" >/dev/null 2>&1 &")
    time.sleep(1.5)
    assert (folder / "stubborn.txt").exists() and (folder / "detached.txt").exists()
    device.stop()
    device.thread.join(30)
    time.sleep(1)
    seen = [(folder / name).read_text() for name in ("stubborn.txt", "detached.txt")]
    time.sleep(1)
    assert [(folder / name).read_text() for name in ("stubborn.txt", "detached.txt")] == seen


def test_command_never_runs_past_the_time_window(hub, paired):
    job = _job(hub, paired)  # asks for 30 seconds
    paired.expires = time.time() + 5
    assert paired.budget(job) <= 5
    paired.expires = time.time() - 1
    with pytest.raises(HandsError, match="window has ended"):
        paired.budget(job)


def test_goodbye_reports_unknown_for_a_command_the_device_had(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    result = {}
    waiter = threading.Thread(target=lambda: result.update(
        r=hub.run(hub.pick(paired.name), "echo x", login=False, timeout=30, stdin=None)))
    waiter.start()
    assert paired.poll() is not None  # handed over; its result never arrives
    paired.bye()
    waiter.join(5)
    assert result["r"][1] == 125 and "not known whether it ran" in result["r"][0]


# --- requests and commands are tied to what they are for ------------------------------------

def test_signature_for_one_request_is_no_use_for_another(hub, paired):
    nonce = "fresh-value"
    for_a_poll = wire.sign(paired.identity, paired.key, wire.TOOL_POLL, wire.request("poll", nonce))
    with pytest.raises(Refused, match="isn't signed"):
        hub.bye({"device": paired.me, "nonce": nonce, "sig": for_a_poll})
    assert hub.pick(paired.name).online


def test_pairing_request_cannot_be_replayed_as_another_request(hub, folder):
    sent = {}
    from hermes_tenuo.hands import device as device_module
    real = device_module._post
    device = Device(hub.invite(), str(folder), 600, allow_unsandboxed=True)

    def capture(url, body, timeout):
        sent.update(body)
        return real(url, body, timeout)

    device_module._post = capture
    try:
        device.pair()
    finally:
        device_module._post = real
    replay = {"device": sent["device"], "nonce": sent["nonce"], "sig": sent["sig"]}
    for request in (hub.bye, hub.poll):
        with pytest.raises(Refused):
            request(dict(replay))
    assert hub.pick(device.name).online


def test_command_must_answer_the_devices_open_request(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    session = hub.pick(paired.name)
    waiter = threading.Thread(target=lambda: hub.run(session, "echo x", login=False, timeout=5, stdin=None))
    waiter.start()
    job = paired.poll()
    assert job is not None and job["poll"]
    paired.poll()  # a later request is open now; the earlier command arrives as its answer
    with pytest.raises(HandsError, match="does not answer"):
        paired.verify(job)
    waiter.join(10)


# --- stopping a command ------------------------------------------------------------------------

def test_stopped_before_it_started_never_runs(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    stop = threading.Event()
    stop.set()
    out, code = hub.run(hub.pick(paired.name), "echo never", login=False, timeout=30, stdin=None, cancelled=stop)
    assert code == 130 and "before it started" in out
    assert paired.poll() is None


@sandboxed
def test_stopping_a_running_command_stops_it_on_the_device(hub, folder):
    up(hub, folder)
    stop, result = threading.Event(), {}
    waiter = threading.Thread(target=lambda: result.update(r=hub.run(
        hub.pick("laptop"), "sleep 3; echo late > late.txt", login=False, timeout=60, stdin=None, cancelled=stop)))
    started = time.time()
    waiter.start()
    time.sleep(1)
    stop.set()
    waiter.join(15)
    assert result["r"][1] == 130 and time.time() - started < 12, result
    time.sleep(3)
    assert not (folder / "late.txt").exists()
    assert run(hub, "echo next")[0].strip() == "next"


@sandboxed
def test_leftovers_are_cleared_when_a_command_ends_the_runner(hub, folder, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    run(hub, "(while true; do date +%s%N > tick.txt; sleep 0.2; done) >/dev/null 2>&1 & kill -KILL $PPID", timeout=5)
    assert run(hub, "echo again")[0].strip() == "again"  # a new sandbox; the old one's leftovers are gone
    time.sleep(0.5)
    seen = (folder / "tick.txt").read_text() if (folder / "tick.txt").exists() else ""
    time.sleep(1)
    assert ((folder / "tick.txt").read_text() if (folder / "tick.txt").exists() else "") == seen
    device.stop()


@sandboxed
def test_a_process_in_its_own_session_does_not_outlive_a_stopped_runner(hub, folder, monkeypatch):
    """No process group leads back to it, and the runner that would stop it is gone."""
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    out, code = run(hub, "python3 -c \"import os, time\nos.setsid()\nwhile True:\n"
                         "    open('stray.txt', 'w').write(str(time.time()))\n    time.sleep(0.2)\" >/dev/null 2>&1 &"
                         " sleep 1; kill -KILL $PPID", timeout=8)
    assert code == 137 and "supervisor" in out, (out, code)
    assert any("supervisor" in line for line in device.lines)
    time.sleep(0.5)
    seen = (folder / "stray.txt").read_text()
    time.sleep(1)
    assert (folder / "stray.txt").read_text() == seen  # stopped at once, not only when the device stops
    assert run(hub, "echo again")[0].strip() == "again"
    device.stop()


@pytest.mark.skipif(sys.platform != "darwin" or sandbox.available() is None, reason="asks the macOS sandbox")
def test_only_processes_in_this_sandbox_are_found(tmp_path):
    from hermes_tenuo.hands.device import _in_sandbox
    state, shared = tmp_path / "state", tmp_path / "shared"
    for path in (state / "tmp", state / "other", shared):
        path.mkdir(parents=True)
    tmp = str(state / "tmp")
    detach = "nohup /usr/bin/perl -e 'use POSIX; POSIX::setsid(); sleep 30' >/dev/null 2>&1 & exec sleep 30"
    ours = [subprocess.Popen(sandbox.wrap(str(shared), tmp, ["/bin/sleep", "30"], hidden=[str(state)])),
            subprocess.Popen(sandbox.wrap(str(shared), tmp, ["/bin/bash", "-c", detach], hidden=[str(state)]))]
    others = [subprocess.Popen(["/bin/sleep", "30"]),  # not in any sandbox
              subprocess.Popen(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/bin/sleep", "30"]),
              subprocess.Popen(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny file-write*)",
                                "/bin/sleep", "30"]),
              # a narrower Hands sandbox of the same device has a temp folder of its own
              subprocess.Popen(sandbox.wrap(str(shared), str(state / "other"), ["/bin/sleep", "30"],
                                            hidden=[str(state)]))]
    try:
        time.sleep(1)
        found = set(_in_sandbox(tmp, str(state)))
        assert {p.pid for p in ours} <= found
        assert len(found) == 3  # the two started here and the one that moved to its own session
        assert not found & {p.pid for p in others} and os.getpid() not in found
    finally:
        for pid in set(_in_sandbox(tmp, str(state))) | {p.pid for p in ours + others}:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        for p in ours + others:
            p.wait(5)


@sandboxed
def test_the_device_never_writes_through_a_link_left_as_its_temp_folder(hub, folder, tmp_path, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    device = up(hub, folder)
    tmp = tmp_path / "device-state" / "tmp"
    out, _ = run(hub, f'cd /; rm -rf "$TMPDIR"; ln -s {elsewhere} "$TMPDIR"; echo swapped=$?')
    if tmp.is_symlink():  # where the sandbox lets a command do this at all
        assert run(hub, "echo next")[0].strip() == "next"  # the device made its folder again
        assert tmp.is_dir() and not tmp.is_symlink()
        run(hub, f'cd /; rm -rf "$TMPDIR"; ln -s {elsewhere} "$TMPDIR"')
    device.stop()
    device.thread.join(30)
    again = up(hub, folder, invite=False)  # `hands up` again sets the stand-in home up
    assert run(hub, "echo back")[0].strip() == "back"
    assert tmp.is_dir() and not tmp.is_symlink()
    assert list(elsewhere.iterdir()) == []
    again.stop()


def test_own_folder_replaces_a_link_or_a_file_and_keeps_a_folder(tmp_path):
    from hermes_tenuo.hands.device import _own_folder
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("x")
    for make in (lambda p: p.symlink_to(target), lambda p: p.write_text("a file"), lambda p: None):
        path = tmp_path / "t"
        make(path)
        assert _own_folder(str(path)) is True
        assert path.is_dir() and not path.is_symlink() and list(path.iterdir()) == []
        assert _own_folder(str(path)) is False  # already a folder: left as it is
        path.rmdir()
    assert (target / "keep").read_text() == "x"


# --- easier to use -----------------------------------------------------------------------------

class _Where:
    name, folder, mode = "laptop", "/work/app", "sandboxed"


def test_results_say_which_machine_they_ran_on():
    marked = json.loads(chat._marked(json.dumps({"output": "ok", "exit_code": 0}), "terminal", _Where()))
    assert marked["output"] == "ok" and marked["exit_code"] == 0
    assert "laptop" in marked["ran_on"] and "/work/app" in marked["ran_on"] and "hands_note" not in marked
    refused = json.loads(chat._marked(json.dumps({"output": "sh: x: Operation not permitted", "exit_code": 1}),
                                      "terminal", _Where()))
    assert "shares only /work/app" in refused["hands_note"]
    error = json.loads(chat._marked(json.dumps({"error": "Permission denied: /etc/x"}), "write_file", _Where()))
    assert "hands_note" in error
    linux = json.loads(chat._marked(json.dumps({"output": "bash: /usr/x: Read-only file system", "exit_code": 1}),
                                    "terminal", _Where()))
    assert "hands_note" in linux
    missing = json.loads(chat._marked(json.dumps({"output": "cat: nope: No such file or directory", "exit_code": 1}),
                                      "terminal", _Where()))
    assert "hands_note" not in missing  # an ordinary failure is not explained as a refusal


@pytest.mark.parametrize("mode", ["none", ""])
def test_no_sandbox_promise_for_a_machine_without_one(mode):
    class Open(_Where):
        pass
    Open.mode = mode
    denied = json.loads(chat._marked(json.dumps({"output": "sh: /etc/x: Permission denied", "exit_code": 1}),
                                     "terminal", Open()))
    assert "laptop" in denied["ran_on"] and "hands_note" not in denied


def test_read_only_machine_is_described_as_such():
    class Look(_Where):
        mode = "read-only"
    denied = json.loads(chat._marked(json.dumps({"output": "sh: new.txt: Operation not permitted", "exit_code": 1}),
                                     "terminal", Look()))
    assert "to read, not to change" in denied["hands_note"] and "shares only" not in denied["hands_note"]


def test_the_server_learns_how_a_machine_holds_commands(hub, folder, monkeypatch):
    monkeypatch.setattr(sandbox, "_probe", [None])
    Device(hub.invite(), str(folder), 60, name="open", allow_unsandboxed=True).pair()
    assert hub.pick("open").mode == "none"
    monkeypatch.setattr(chat, "get_hub", lambda: hub)
    assert "open: up" in chat.command("status") and "no sandbox" in chat.command("status")


def test_a_pairing_request_cannot_claim_another_mode(hub, folder, monkeypatch):
    sent = {}
    real = device_module._post
    monkeypatch.setattr(device_module, "_post", lambda url, body, timeout: sent.update(body) or real(url, body, timeout))
    monkeypatch.setattr(sandbox, "_probe", [None])
    Device(hub.invite(), str(folder), 60, allow_unsandboxed=True).pair()
    hub._paired.clear()
    with pytest.raises(Refused, match="doesn't match"):
        hub.pair(dict(sent, mode="sandboxed"))


def test_only_device_tools_and_plain_results_are_marked():
    result = json.dumps({"results": []})
    assert chat._marked(result, "web_search", _Where()) == result      # runs on the server
    assert chat._marked(result, "terminal", None) == result           # no device took the call
    assert chat._marked("not json", "terminal", _Where()) == "not json"
    assert chat._marked(json.dumps([1, 2]), "terminal", _Where()) == "[1, 2]"
    once = chat._marked(json.dumps({"output": "x"}), "terminal", _Where())
    assert chat._marked(once, "terminal", _Where()) == once           # never marked twice


@sandboxed
def test_read_only_lets_commands_look_and_not_change(hub, folder):
    device = up(hub, folder, read_only=True)
    out, code = run(hub, "cat README.md && echo x > new.txt; echo write=$?; echo t > \"$TMPDIR/scratch\" && echo tmp-ok")
    assert "device readme" in out and "write=0" not in out and "tmp-ok" in out, out
    assert not (folder / "new.txt").exists()
    out, _ = run(hub, "rm README.md; echo rm=$?")
    assert "rm=0" not in out and (folder / "README.md").exists()
    assert any("--read-only" in line for line in device.lines)
    assert hub.pick("laptop").mode == "read-only"
    device.stop()


def test_read_only_needs_a_sandbox(hub, folder, monkeypatch):
    monkeypatch.setattr(sandbox, "_probe", [None])
    with pytest.raises(sandbox.SandboxUnavailable, match="read-only"):
        Device(hub.invite(), str(folder), 60, allow_unsandboxed=True, read_only=True)


@sandboxed
def test_hands_up_says_what_commands_can_do(hub, folder):
    device = up(hub, folder)
    said = " ".join(device.lines)
    assert "change files only in this folder" in said and "network" in said
    assert "cannot read the rest of your home folder" in said
    device.stop()


@sandboxed
def test_device_pairs_again_when_the_server_forgot_it(hub, folder, monkeypatch):
    """What a restart of Hermes looks like to a device that is up."""
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    assert run(hub, "echo before")[0].strip() == "before"
    with hub._lock:
        hub._sessions.clear()  # the hub's memory is gone; its list of known devices is on disk
        hub._paired.clear()
    deadline = time.time() + 15
    while time.time() < deadline and not any(s.online for s in hub.sessions()):
        time.sleep(0.1)
    assert run(hub, "echo after")[0].strip() == "after"
    assert any("paired with it again" in line for line in device.lines)
    # And again straight away: a second restart is waited out, not taken as the end.
    with hub._lock:
        hub._sessions.clear()
        hub._paired.clear()
    deadline = time.time() + 20
    while time.time() < deadline and not any(s.online for s in hub.sessions()):
        time.sleep(0.1)
    assert run(hub, "echo twice")[0].strip() == "twice"
    assert device.thread.is_alive()
    device.stop()


@sandboxed
def test_device_keeps_trying_when_pairing_again_cannot_reach_the_server(hub, folder, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    real, lost = device_module._post, {"n": 0}

    def flaky(url, body, timeout):
        if url.endswith("/pair") and lost["n"] < 2:
            lost["n"] += 1
            raise ConnectionError("timed out")
        return real(url, body, timeout)

    monkeypatch.setattr(device_module, "_post", flaky)
    with hub._lock:
        hub._sessions.clear()
        hub._paired.clear()
    deadline = time.time() + 30
    while time.time() < deadline and not any(s.online for s in hub.sessions()):
        time.sleep(0.1)
    assert lost["n"] == 2 and device.thread.is_alive()
    assert run(hub, "echo back")[0].strip() == "back"
    device.stop()


@sandboxed
def test_a_proxy_error_while_pairing_again_is_not_a_refusal(hub, folder, monkeypatch):
    import urllib.error
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    real, failed = device_module.urllib.request.urlopen, {"n": 0}

    def flaky(request, timeout=None):
        if request.full_url.endswith("/pair") and failed["n"] < 3:
            failed["n"] += 1
            raise urllib.error.HTTPError(request.full_url, 502 if failed["n"] % 2 else 503, "Bad Gateway", {}, None)
        return real(request, timeout=timeout)

    monkeypatch.setattr(device_module.urllib.request, "urlopen", flaky)
    with hub._lock:
        hub._sessions.clear()
        hub._paired.clear()
    deadline = time.time() + 40
    while time.time() < deadline and not any(s.online for s in hub.sessions()):
        time.sleep(0.1)
    assert failed["n"] == 3 and device.thread.is_alive()
    assert run(hub, "echo back")[0].strip() == "back"
    assert not any("ended this session" in line for line in device.lines)
    device.stop()


def test_a_server_error_is_a_lost_connection_and_a_refusal_is_not(monkeypatch):
    import io
    import urllib.error

    def answer(code, body=b""):
        def urlopen(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, code, "x", {}, io.BytesIO(body))
        return urlopen

    for code in (500, 502, 503, 504):
        monkeypatch.setattr(device_module.urllib.request, "urlopen", answer(code))
        with pytest.raises(ConnectionError):
            device_module._post("http://127.0.0.1:1/x", {}, timeout=1)
    monkeypatch.setattr(device_module.urllib.request, "urlopen", answer(403, b'{"error": "this device is not paired"}'))
    with pytest.raises(HandsError, match="not paired"):
        device_module._post("http://127.0.0.1:1/x", {}, timeout=1)


@sandboxed
def test_a_revoked_device_does_not_pair_again(hub, folder, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 1)
    device = up(hub, folder)
    assert hub.revoke("laptop")
    device.thread.join(20)
    assert not device.thread.is_alive()
    assert not hub.sessions()
    assert any("ended this session" in line for line in device.lines)


def test_check_reports_what_is_missing_without_pairing(hub, folder, tmp_path, monkeypatch):
    from hermes_tenuo.hands.device import check
    monkeypatch.setattr(sandbox, "_probe", ["sandbox-exec"])  # the same on a machine with no sandbox
    found = check(hub.invite(), str(folder))
    assert all(ok is not False for ok, _ in found), found
    assert any(ok and "server reachable" in text for ok, text in found)
    assert not hub.sessions() and not (tmp_path / "device-state" / "device.key").exists()  # nothing was paired or made
    missing = check(None, str(folder))
    assert any(ok is False and "/hands invite" in text for ok, text in missing)
    assert any(ok is False and "not a folder" in text for ok, text in check(hub.invite(), str(folder / "nope")))
    assert any(ok is False and "home folder" in text for ok, text in check(hub.invite(), "~"))
    assert any(ok is False and "damaged" in text for ok, text in check("hands://127.0.0.1:1/x#nope", str(folder)))
    port_closed = hub.invite().replace(hub.public_url.split("//")[1], "127.0.0.1:1")
    assert any(ok is False and "cannot reach" in text for ok, text in check(port_closed, str(folder)))
    monkeypatch.setattr(sandbox, "_probe", [None])
    assert any(ok is False and "no sandbox" in text for ok, text in check(hub.invite(), str(folder)))


def test_check_does_not_take_another_service_for_a_hands_server(hub, folder, monkeypatch):
    """A proxy's 502, or some other program at that address, is not a server that is ready."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from hermes_tenuo.hands.device import check
    monkeypatch.setattr(sandbox, "_probe", ["sandbox-exec"])

    class Other(BaseHTTPRequestHandler):
        status = 502

        def log_message(self, *args):
            pass

        def do_POST(self):
            self.send_response(self.status)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        invite = hub.invite().replace(hub.public_url.split("//")[1], f"127.0.0.1:{server.server_address[1]}")
        for status in (502, 404, 200):
            Other.status = status
            found = check(invite, str(folder))
            assert any(ok is False and f"HTTP {status}" in text and "not as a Hands server" in text
                       for ok, text in found), (status, found)
            assert not any(ok and "server reachable" in text for ok, text in found)
    finally:
        server.shutdown()
        server.server_close()


# --- before strangers use it -------------------------------------------------------------------

def test_private_and_public_addresses():
    for host in ("127.0.0.1", "localhost", "10.1.2.3", "192.168.1.9", "172.20.0.4", "100.101.102.103",
                 "169.254.1.1", "::1", "[::1]", "fd7a:115c:a1e0::1"):
        assert wire.private_host(host), host
    for host in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        assert not wire.private_host(host), host
    assert wire.plain_and_public("http://8.8.8.8:8765")
    assert not wire.plain_and_public("https://8.8.8.8") and not wire.plain_and_public("http://10.0.0.2:8765")


def test_device_refuses_an_unencrypted_public_server(hub, folder):
    key = wire.key_text(hub.key.public_key)
    public = wire.Invite("http://8.8.8.8:8765", "secret", key).render()
    with pytest.raises(HandsError, match="not encrypted"):
        Device(public, str(folder), 60, allow_unsandboxed=True)
    Device(public, str(folder), 60, allow_unsandboxed=True, plain_http=True)   # the person said so
    Device(wire.Invite("https://8.8.8.8", "secret", key).render(), str(folder), 60, allow_unsandboxed=True)
    Device(wire.Invite("http://192.168.1.20:8765", "secret", key).render(), str(folder), 60, allow_unsandboxed=True)
    from hermes_tenuo.hands.device import check
    assert any(ok is False and "not encrypted" in text for ok, text in check(public, str(folder)))


def test_invite_says_when_its_address_is_public_and_plain(hub, monkeypatch):
    monkeypatch.setattr(chat, "get_hub", lambda: hub)
    assert "not encrypted" not in chat.command("invite")   # the test hub listens on this machine
    hub.public_url = "http://8.8.8.8:8765"
    assert "not encrypted" in chat.command("invite")


def test_a_machine_belongs_to_whoever_invited_it(hub, folder, monkeypatch):
    switched = []
    hub.joined = lambda conversation, name: switched.append((conversation, name))
    device = Device(hub.invite("telegram:alice", "chat-a"), str(folder), 60, allow_unsandboxed=True)
    device.pair()
    assert switched == [("chat-a", device.name)]          # the conversation that asked starts using it
    assert hub.pick(device.name).owner == "telegram:alice"
    assert [s.name for s in hub.sessions("telegram:alice")] == [device.name]
    assert hub.sessions("telegram:bob") == [] and hub.sessions("") == []
    with pytest.raises(HandsUnavailable):
        hub.pick(device.name, "telegram:bob")
    assert not hub.revoke(device.name, "telegram:bob") and hub.sessions("telegram:alice")
    # Coming up again with no invite, it is still hers, and nobody is switched again.
    Device(None, str(folder), 60, allow_unsandboxed=True).pair()
    assert hub.pick(device.name, "telegram:alice").owner == "telegram:alice" and len(switched) == 1
    assert hub.revoke(device.name, "telegram:alice") and not hub.sessions()


def test_a_machine_paired_with_no_one_asking_is_for_anyone(hub, folder):
    device = Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)   # a single-user Hermes
    device.pair()
    assert hub.pick(device.name, "telegram:bob").owner == "" and hub.sessions("")
    assert hub.revoke(device.name, "telegram:bob")


def test_chat_commands_only_see_your_own_machines(hub, folder, monkeypatch):
    monkeypatch.setattr(chat, "get_hub", lambda: hub)
    monkeypatch.setattr(chat, "can_switch", True)
    monkeypatch.setattr(chat, "_conversation", lambda: "chat-a")
    monkeypatch.setattr(chat, "_owner", lambda: "telegram:alice")
    hub.joined = chat.joined
    line = chat.command("invite")
    assert "starts using the machine as soon as it is up" in line
    Device(line.split("'")[1], str(folder), 60, name="laptop", allow_unsandboxed=True).pair()
    assert chat._wanted.get("chat-a") == "laptop"          # no /hands on needed
    assert "laptop: up" in chat.command("status")
    monkeypatch.setattr(chat, "_owner", lambda: "telegram:bob")
    monkeypatch.setattr(chat, "_conversation", lambda: "chat-b")
    assert "laptop" not in chat.command("status")
    assert "no device named 'laptop'" in chat.command("on laptop") and "chat-b" not in chat._wanted
    assert "No machine of yours" in chat.command("revoke laptop")
    chat._wanted.pop("chat-a", None)


@pytest.fixture
def home_base(tmp_path):
    """Where a stand-in home folder can live. On Linux a sandbox has its own /tmp, so a
    home folder under /tmp could not be told apart from a hidden one."""
    if sys.platform != "linux":
        yield tmp_path
        return
    import shutil
    import tempfile
    base = Path(tempfile.mkdtemp(prefix="hands-test-", dir="/var/tmp"))
    yield base
    shutil.rmtree(base, ignore_errors=True)


@sandboxed
def test_commands_cannot_read_the_rest_of_the_home_folder(hub, home_base, monkeypatch):
    home = home_base / "home"
    project, shown = home / "work" / "app", home / "notes"
    for path in (project, shown, home / "Documents", home / "work" / "other"):
        path.mkdir(parents=True)
    (home / "Documents" / "taxes.txt").write_text("papers")
    (home / "work" / "other" / ".env").write_text("TOKEN=abc")
    (shown / "ok.txt").write_text("fine")
    (project / "README.md").write_text("project")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("TENUO_HANDS_HOME", raising=False)   # the default place, inside the home folder
    device = up(hub, project)
    out, code = run(hub, "cat README.md && echo t > \"$TMPDIR/x\" && cat \"$TMPDIR/x\"")
    assert code == 0 and "project" in out
    out, _ = run(hub, f"(cat {home}/Documents/taxes.txt {home}/work/other/.env {shown}/ok.txt; ls {home} {home}/work"
                      ") 2>/dev/null")
    assert not any(word in out for word in ("papers", "TOKEN", "fine", "Documents", "other")), out
    assert any("cannot read the rest of your home folder" in line for line in device.lines)
    device.stop()
    device.thread.join(30)
    # A folder the person names is readable (and still not writable); the rest stays hidden.
    device = up(hub, project, invite=False, read=[str(shown)])
    out, _ = run(hub, f"(cat {shown}/ok.txt; echo x > {shown}/new.txt; cat {home}/Documents/taxes.txt) 2>/dev/null")
    assert "fine" in out and "papers" not in out and not (shown / "new.txt").exists()
    # A write into the hidden home folder fails; it does not seem to work and then vanish.
    out, _ = run(hub, f"echo x > {home}/stray.txt; echo write=$?; mkdir {home}/newdir; echo mkdir=$?")
    assert "write=0" not in out and "mkdir=0" not in out and not (home / "stray.txt").exists()
    device.stop()
    device.thread.join(30)
    # --read-home shows the home folder again, except the protected paths.
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id").write_text("KEYMATERIAL")
    device = up(hub, project, invite=False, read_home=True)
    out, _ = run(hub, f"(cat {home}/Documents/taxes.txt; cat {home}/.ssh/id) 2>/dev/null")
    assert "papers" in out and "KEYMATERIAL" not in out
    assert any("--read-home" in line for line in device.lines)
    device.stop()


def test_folders_shown_in_the_home_folder(tmp_path, monkeypatch):
    from hermes_tenuo.hands.device import shown_in_home
    home = tmp_path / "home"
    for sub in (".rustup", ".cargo/bin", ".local/share/uv", "notes", "elsewhere"):
        (home / sub).mkdir(parents=True)
    outside = tmp_path / "opt-tools"
    outside.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", os.pathsep.join([str(home / ".cargo" / "bin"), str(outside), "/usr/bin"]))
    for name in ("RUSTUP_HOME", "PYENV_ROOT", "NVM_DIR", "RBENV_ROOT", "ASDF_DATA_DIR", "VOLTA_HOME", "SDKMAN_DIR",
                 "JAVA_HOME", "ANDROID_HOME", "GOROOT"):
        monkeypatch.delenv(name, raising=False)
    real = os.path.realpath
    assert set(shown_in_home()) == {real(home / ".rustup"), real(home / ".cargo" / "bin"), real(home / ".local/share/uv")}
    assert real(home / "notes") in shown_in_home([str(home / "notes")])
    for bad in (str(home), "/", str(home / "missing")):
        with pytest.raises(HandsError):
            shown_in_home([bad])


def test_why_there_is_no_sandbox(monkeypatch):
    monkeypatch.setattr(sandbox, "_probe", [None])
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    assert "not installed" in sandbox.why_not() and "apt install bubblewrap" in sandbox.why_not()
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(sandbox, "_refusal", ["bwrap: setting up uid map: Permission denied"])
    said = sandbox.why_not()
    assert "is installed, but" in said and "uid map: Permission denied" in said and "Hands on Ubuntu" in said
    with pytest.raises(sandbox.SandboxUnavailable, match="is installed, but"):
        sandbox.wrap("/x", "/y", ["true"])
    monkeypatch.setattr(sandbox, "_probe", ["bwrap"])
    assert sandbox.why_not() == ""


@pytest.mark.skipif(not sandbox.scopes_sockets() or sandbox.available() != "bwrap",
                    reason="needs Linux 6.12 or later and bubblewrap")
def test_commands_cannot_reach_another_programs_named_socket(hub, folder):
    import socket
    name = f"hands-test-{os.getpid()}"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind("\0" + name)
    listener.listen(1)
    try:
        device = up(hub, folder)
        out, _ = run(hub, "python3 -c \"import socket\ns = socket.socket(socket.AF_UNIX)\n"
                          f"try:\n    s.connect('\\0{name}'); print('reached')\n"
                          "except OSError as e:\n    print('refused')\"")
        assert "refused" in out and "reached" not in out, out
        # Sockets made inside the sandbox still work between its own processes.
        out, _ = run(hub, "python3 -c \"import socket\na = socket.socket(socket.AF_UNIX); a.bind('\\0inside'); a.listen(1)\n"
                          "b = socket.socket(socket.AF_UNIX); b.connect('\\0inside'); print('own-ok')\"")
        assert "own-ok" in out, out
        device.stop()
    finally:
        listener.close()


# --- the listener and protected paths ----------------------------------------------------------

def test_connection_that_stops_sending_is_dropped(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(hub_module, "READ_SECONDS", 0.5)
    h = Hub(state_dir=tmp_path / "server-state")
    h.listen("127.0.0.1:0")
    try:
        host, port = h.public_url.split("//")[1].split(":")
        with socket.create_connection((host, int(port)), timeout=5) as s:
            s.sendall(b"POST /hands/v1/poll HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n")
            started = time.time()
            s.settimeout(5)
            try:
                data = s.recv(4096)
            except OSError:
                data = b""
            assert time.time() - started < 4
            assert data == b"" or b" 4" in data.split(b"\r\n")[0] or b" 5" in data.split(b"\r\n")[0]
    finally:
        h.close()


def test_protected_path_that_is_a_link_is_hidden_at_its_real_place(tmp_path, monkeypatch):
    home, elsewhere = tmp_path / "home", tmp_path / "vault" / "keys"
    home.mkdir()
    elsewhere.mkdir(parents=True)
    (home / ".ssh").symlink_to(elsewhere)
    monkeypatch.setenv("HOME", str(home))
    paths = sandbox._private_paths()
    assert os.path.realpath(elsewhere) in paths and os.path.join(os.path.realpath(home), ".ssh") in paths
    if sys.platform == "darwin":
        assert os.path.realpath(elsewhere) in sandbox._mac_profile(str(tmp_path / "p"), str(tmp_path / "t"))
    else:
        argv = sandbox._bwrap(str(tmp_path / "p"), str(tmp_path / "t"), ["true"])
        assert os.path.realpath(elsewhere) in argv and os.path.join(str(home), ".ssh") not in argv


def test_folder_named_through_a_link_is_refused(hub, paired, tmp_path):
    """A narrower warrant is checked against the folder as written; a link must not widen it."""
    from tenuo import Subpath, Wildcard
    session = hub.pick(paired.name)
    src, other = os.path.join(session.folder, "src"), os.path.join(session.folder, "other")
    os.makedirs(other)
    os.symlink(other, os.path.join(src, "escape"))
    builder = session.grant.attenuate_builder()
    builder.with_capability(wire.TOOL, {"dir": Subpath(src), "cmd": Wildcard()})
    child = builder.delegate(hub.key)
    where = os.path.join(src, "escape")
    args = {"dir": where, "cmd": wire.digest("job-link", "echo x", False, None, 30, "", 0, "")}
    job = {"id": "job-link", "cmd": "echo x", "login": False, "timeout": 30, "stdin": None, "shown": "", "dir": where,
           "chain": [session.grant.to_base64(), child.to_base64()], "pop": wire.sign(child, hub.key, wire.TOOL, args)}
    with pytest.raises(HandsError, match="through a link"):
        paired.verify(job)


def test_output_that_grows_when_sent_still_arrives(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    monkeypatch.setattr(wire, "MAX_TEXT", 60_000)
    result = {}
    waiter = threading.Thread(target=lambda: result.update(
        r=hub.run(hub.pick(paired.name), "echo x", login=False, timeout=30, stdin=None)))
    waiter.start()
    job = paired.poll()
    paired.report(job["id"], "\x00" * 50_000, 0)  # six bytes each once sent
    waiter.join(5)
    out, code = result["r"]
    assert code == 0 and "cut to fit" in out and wire.sent_size(out) < 70_000
    big, code = hub.run(hub.pick(paired.name), "cat", login=False, timeout=5, stdin="\x00" * 50_000)
    assert code == 126 and "too large" in big


# --- third review round ---------------------------------------------------------------------------

def _capture_pair(device):
    from hermes_tenuo.hands import device as device_module
    sent, real = {}, device_module._post

    def capture(url, body, timeout):
        sent.update(body)
        return real(url, body, timeout)

    device_module._post = capture
    try:
        device.pair()
    finally:
        device_module._post = real
    return sent


def test_pairing_request_works_once(hub, folder):
    first = Device(hub.invite(), str(folder), 600, allow_unsandboxed=True)
    sent = _capture_pair(first)
    session = hub.pick(first.name)
    assert hub.pair(dict(sent)) == {"ok": True, "name": first.name}  # the device's own retry
    assert hub.pick(first.name) is session
    Device(None, str(folder), 600, allow_unsandboxed=True).pair()  # the device came back
    newer = hub.pick(first.name)
    with pytest.raises(Refused, match="already used"):
        hub.pair(dict(sent))
    assert hub.pick(first.name) is newer


def test_call_stopped_before_it_is_sent_is_never_put_in_line(hub, paired):
    stop = threading.Event()
    stop.set()
    session = hub.pick(paired.name)
    assert hub.run(session, "echo never", login=False, timeout=30, stdin=None, cancelled=stop)[1] == 130
    assert session.jobs.empty() and not session.waiting


def test_runner_lines_are_read_one_at_a_time():
    both = subprocess.Popen(["/bin/sh", "-c", "printf 'first\\nsecond\\n'; sleep 1"], stdout=subprocess.PIPE)
    try:
        time.sleep(0.3)  # both lines are waiting in the pipe
        assert Device._line(both, 2) == "first"
        assert Device._line(both, 2) == "second"
        with pytest.raises(EOFError):
            Device._line(both, 5)
    finally:
        both.kill()


@sandboxed
def test_stopping_the_device_stops_the_command_it_is_running(hub, folder):
    device = up(hub, folder)
    result = {}
    waiter = threading.Thread(target=lambda: result.update(r=hub.run(
        hub.pick("laptop"), "sleep 4; echo late > late.txt", login=False, timeout=120, stdin=None)))
    waiter.start()
    time.sleep(1.5)
    started = time.time()
    device.stop()
    waiter.join(15)
    assert time.time() - started < 10 and result["r"][1] == 130, result
    assert "stopped on the device" in result["r"][0]
    time.sleep(4)
    assert not (folder / "late.txt").exists()


@sandboxed
def test_narrower_command_cannot_touch_the_sessions_temp_folder(hub, folder):
    from tenuo import Subpath, Wildcard
    device = Device(hub.invite(), str(folder), 600)
    device.pair()
    session = hub.pick(device.name)
    planted = os.path.join(device.tmp, "hermes-snap-planted.sh")
    sub = os.path.join(session.folder, "src")
    builder = session.grant.attenuate_builder()
    builder.with_capability(wire.TOOL, {"dir": Subpath(sub), "cmd": Wildcard()})
    child = builder.delegate(hub.key)
    cmd = f"echo planted > {planted}; ls {device.tmp}; echo own > $TMPDIR/own.txt && cat $TMPDIR/own.txt"
    args = {"dir": sub, "cmd": wire.digest("job-tmp", cmd, False, None, 30, "", 0, "")}
    job = {"id": "job-tmp", "cmd": cmd, "login": False, "timeout": 30, "stdin": None, "shown": "", "dir": sub,
           "chain": [session.grant.to_base64(), child.to_base64()], "pop": wire.sign(child, hub.key, wire.TOOL, args)}
    out, code = device.run(job, device.verify(job))
    assert not os.path.exists(planted)
    assert out.strip().endswith("own") and code == 0, out  # it has a temp folder of its own
    assert not [name for name in os.listdir(device.state) if name.startswith("narrow-")]


def test_switching_drops_the_device_shell_under_the_key_hermes_uses(monkeypatch):
    """On a host serving several profiles Hermes keys a task's shell with the profile."""
    import types
    from hermes_tenuo.hands import chat

    class HandsEnvironment:
        pass

    server_shell, cache = object(), {}
    cache.update({"profile-a:task-1": HandsEnvironment(), "default": server_shell, "task-1": server_shell})
    terminal_tool = types.SimpleNamespace(
        _active_environments=cache,
        _qualify_task_key=lambda key: f"profile-a:{key}",
        _resolve_container_task_id=lambda task: f"profile-a:{task}")
    lifecycle = types.SimpleNamespace(cleanup_vm=lambda key: cache.pop(key, None))
    tools = types.ModuleType("tools")
    tools.terminal_tool, tools.terminal_tool_lifecycle = terminal_tool, lifecycle
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "tools.terminal_tool", terminal_tool)
    monkeypatch.setitem(sys.modules, "tools.terminal_tool_lifecycle", lifecycle)
    monkeypatch.setitem(sys.modules, "hermes_tenuo.hands.backend",
                        types.SimpleNamespace(HandsEnvironment=HandsEnvironment, NAME="hands"))
    chat._drop_shell("task-1")
    assert "profile-a:task-1" not in cache  # the device shell is gone
    assert cache == {"default": server_shell, "task-1": server_shell}  # shells on the server are untouched


# --- fourth review round ----------------------------------------------------------------------------

def test_late_stop_request_cannot_stop_another_command(paired):
    paired._job = "job-b"  # job-a is over; job-b is being handled now
    paired.cancel("job-a")
    assert paired._stop_job is None
    paired.cancel("job-b")
    assert paired._stop_job == "job-b"


def test_command_stopped_before_it_started_does_not_start(hub, paired, folder):
    job = _job(hub, paired, id="job-early")
    where = paired.verify(job)
    paired._job = "job-early"
    paired.cancel("job-early")  # arrives while the sandbox is still starting
    job["cmd"] = "echo ran > ran.txt"
    out, code = paired.run(job, where)
    assert code == 130 and not (folder / "ran.txt").exists()


def test_what_a_command_is_called_cannot_drive_the_terminal(paired):
    from hermes_tenuo.hands import device as device_module
    hostile = "ls\x1b]52;c;aGk=\x07 \x1b[2J\u202e\r\nfake line"
    shown = device_module.printable(hostile)
    assert not any(ord(ch) < 32 or ch in "\x7f\u202e" for ch in shown) and shown.startswith("ls\\x1b")
    lines = []
    paired.say = lines.append
    paired._record(hostile, 0, "")
    assert "\x1b" not in lines[-1] and "\n" not in lines[-1]
    assert json.loads(paired._log.read_text().splitlines()[-1])["command"] == hostile  # the record keeps the original


def test_server_key_is_created_once(tmp_path):
    h = Hub(state_dir=tmp_path / "server-state")
    keys = []
    threads = [threading.Thread(target=lambda: keys.append(wire.key_text(h.key.public_key))) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    again = Hub(state_dir=tmp_path / "server-state")
    assert len(set(keys)) == 1 and wire.key_text(again.key.public_key) == keys[0]


def test_display_text_counts_toward_the_size_limit(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "MAX_TEXT", 1000)
    out, code = hub.run(hub.pick(paired.name), "echo x", login=False, timeout=5, stdin=None, shown="y" * 50_000)
    assert code == 126 and "too large" in out


def test_result_is_still_accepted_just_after_the_window_ends(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    session, result = hub.pick(paired.name), {}
    waiter = threading.Thread(target=lambda: result.update(
        r=hub.run(session, "echo x", login=False, timeout=60, stdin=None)))
    waiter.start()
    job = paired.poll()
    session.expires = time.time() - 1  # the window ended while the command ran
    paired.report(job["id"], "stopped at the end of the window\n", 124)
    waiter.join(5)
    assert result["r"] == ("stopped at the end of the window\n", 124)


def test_caller_is_told_when_the_window_ends_without_a_result(hub, paired, monkeypatch):
    monkeypatch.setattr(wire, "POLL_SECONDS", 0.2)
    session, result = hub.pick(paired.name), {}
    waiter = threading.Thread(target=lambda: result.update(
        r=hub.run(session, "echo x", login=False, timeout=600, stdin=None)))
    waiter.start()
    assert paired.poll() is not None
    session.expires = time.time() - wire.REPORT_GRACE - 1
    waiter.join(5)
    assert not waiter.is_alive() and result["r"][1] == 125 and "end of its time window" in result["r"][0]


# --- what a command's stand-in home starts with ------------------------------------------------

def test_commands_are_told_where_toolchains_live_but_get_no_secrets(hub, folder, tmp_path, monkeypatch):
    real_home = tmp_path / "real-home"
    (real_home / ".rustup").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(real_home))
    monkeypatch.delenv("NVM_DIR", raising=False)
    monkeypatch.setenv("JAVA_HOME", "/opt/java")
    monkeypatch.setenv("PYENV_ROOT", str(tmp_path))  # set by the person: passed on as is
    monkeypatch.setenv("NPM_TOKEN", "must-not-reach-a-command")
    device = Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    env = device._env()
    assert env["RUSTUP_HOME"] == str(real_home / ".rustup") and env["PYENV_ROOT"] == str(tmp_path)
    assert env["JAVA_HOME"] == "/opt/java" and "NVM_DIR" not in env  # no such folder here
    assert env["HOME"] == device.tmp and "NPM_TOKEN" not in env
    assert not [name for name in env if any(word in name for word in ("KEY", "TOKEN", "SECRET", "PASSWORD"))]


def test_commits_made_through_hands_carry_the_persons_name(hub, folder, tmp_path, monkeypatch):
    import shutil
    if not shutil.which("git"):
        pytest.skip("needs git")
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    (real_home / ".gitconfig").write_text(
        '[user]\n\tname = "Ada O\'Brien #1; Lovelace"\n\temail = ada@example.com\n'
        "[alias]\n\tdanger = !touch should-not-be-copied\n[credential]\n\thelper = store\n")
    monkeypatch.setenv("HOME", str(real_home))
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    device = Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    copied = (Path(device.tmp) / ".gitconfig").read_text()
    assert "ada@example.com" in copied and "alias" not in copied and "credential" not in copied
    done = subprocess.run("git init -q . && git add -A && git commit -q -m first && git log -1 --format='%an <%ae>'",
                          shell=True, cwd=folder, env=device._env(), capture_output=True, text=True)
    assert done.stdout.strip() == "Ada O'Brien #1; Lovelace <ada@example.com>", done.stdout + done.stderr
    (Path(device.tmp) / ".gitconfig").write_text("[user]\n\tname = Changed By A Command\n")
    Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)  # started again: it leaves the file alone
    assert "Changed By A Command" in (Path(device.tmp) / ".gitconfig").read_text()


@sandboxed
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS developer tools")
def test_macos_developer_tools_run_without_cache_errors(hub, folder):
    device = up(hub, folder)
    if not device.device._tools[0]:
        pytest.skip("no developer tools on this machine")
    for login in (False, True):
        out, code = run(hub, "git --version; make -v | head -1; cc --version | head -1", login=login)
        assert code == 0 and "git version" in out and "xcrun_db" not in out and "error" not in out.lower(), out


def test_one_address_cannot_take_every_connection(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(hub_module, "MAX_PER_ADDRESS", 5)
    monkeypatch.setattr(hub_module, "READ_SECONDS", 30)
    h = Hub(state_dir=tmp_path / "server-state")
    h.listen("127.0.0.1:0")
    held = []
    try:
        host, port = h.public_url.split("//")[1].split(":")
        for _ in range(12):
            held.append(socket.create_connection((host, int(port)), timeout=5))
        time.sleep(0.5)
        open_now = 0
        for s in held:
            s.setblocking(False)
            try:
                if s.recv(1) != b"":
                    open_now += 1
            except BlockingIOError:
                open_now += 1  # still held open by the server
            except OSError:
                pass
        assert open_now == 5, open_now
    finally:
        for s in held:
            s.close()
        h.close()


def test_developer_tools_never_come_before_the_persons_own_path():
    from hermes_tenuo.hands import device as device_module
    placed = device_module._before_usr_bin("/opt/mine/bin:/usr/local/bin:/usr/bin:/bin", ["/dev/tools"])
    assert placed == "/opt/mine/bin:/usr/local/bin:/dev/tools:/usr/bin:/bin"
    assert device_module._before_usr_bin("/opt/mine/bin", ["/dev/tools"]) == "/opt/mine/bin:/dev/tools"


def test_profile_left_as_a_link_is_replaced_not_followed(hub, folder, tmp_path, monkeypatch):
    from hermes_tenuo.hands import device as device_module
    monkeypatch.setattr(device_module, "_developer_tools", lambda: (["/dev/tools"], ""))
    first = Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    secret = Path(first.state) / "device.key"
    profile = Path(first.tmp) / ".bash_profile"
    profile.unlink()
    profile.symlink_to(secret)  # what a command could leave behind
    Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)  # `hands up` again
    assert not profile.is_symlink() and secret.read_text().strip() not in profile.read_text()
    assert device_module.PROFILE in profile.read_text()
    # A profile a command wrote as an ordinary file is kept, with the one line added.
    profile.write_text("export MINE=1\n")
    Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    assert profile.read_text().startswith("export MINE=1\n") and device_module.PROFILE in profile.read_text()
    assert device_module._read_plain(str(tmp_path / "nothing-here")) == ""
    assert device_module._read_plain(str(tmp_path)) is None
