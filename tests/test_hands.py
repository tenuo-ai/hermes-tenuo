"""Hands: a server hub and a device talking over real local HTTP."""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

from hermes_tenuo.hands import sandbox, wire
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
    args = {"dir": session.folder, "cmd": wire.digest(job_id, cmd, False, None, 30, "")}
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


def test_device_refuses_another_folder(hub, paired, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(Exception):
        paired.verify(_job(hub, paired, dir=str(other)))


def test_device_refuses_a_command_signed_by_someone_else(hub, paired):
    from tenuo import SigningKey
    session = hub.pick(paired.name)
    args = {"dir": session.folder, "cmd": wire.digest("job-9", "echo ok", False, None, 30, "")}
    forged = wire.sign(session.grant, SigningKey.generate(), wire.TOOL, args)
    with pytest.raises(Exception):
        paired.verify(_job(hub, paired, id="job-9", pop=forged))


def test_device_refuses_a_grant_it_did_not_sign(hub, paired):
    from tenuo import SigningKey
    stranger = SigningKey.generate()
    grant = wire.mint_grant(stranger, hub.key.public_key, paired.folder, 600)
    args = {"dir": paired.folder, "cmd": wire.digest("job-8", "echo ok", False, None, 30, "")}
    job = _job(hub, paired, id="job-8", chain=[grant.to_base64()], pop=wire.sign(grant, hub.key, wire.TOOL, args))
    with pytest.raises(Exception):
        paired.verify(job)


def test_device_refuses_after_its_window(hub, paired):
    paired.expires = time.time() - 1
    with pytest.raises(HandsError, match="window has ended"):
        paired.verify(_job(hub, paired))


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
    args = {"dir": sub, "cmd": wire.digest("job-sub", cmd, False, None, 30, "")}
    job = {"id": "job-sub", "cmd": cmd, "login": False, "timeout": 30, "stdin": None, "shown": "", "dir": sub,
           "chain": [session.grant.to_base64(), child.to_base64()], "pop": wire.sign(child, hub.key, wire.TOOL, args)}
    where = device.verify(job)
    device.run(job, where)
    assert (folder / "src" / "inside.txt").exists() and not (folder / "outside.txt").exists()
    # The narrowed warrant cannot be used for the parent folder.
    args = {"dir": session.folder, "cmd": wire.digest("job-up", cmd, False, None, 30, "")}
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
    body = {"device": paired.me, "nonce": "once", "sig": wire.sign(paired.identity, paired.key, wire.TOOL_POLL, {"nonce": "once"})}
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
