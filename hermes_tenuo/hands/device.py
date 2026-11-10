"""The device side of Hands: `hermes-tenuo hands up` on the machine with your files.

It dials out to the Hermes server, hands over a warrant for one folder and a time
window, then runs the commands the server sends. Every command is checked here, against
the warrant this device signed, before it runs in a sandbox limited to that folder.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from hermes_tenuo.hands import sandbox, wire

MAX_OUTPUT = 8 * 1024 * 1024

# Commands get a useful shell environment, but never inherit credentials exported by
# the person who started Hands. Additions to this list are an expansion of authority:
# unlike files, environment variables cannot be hidden by the OS sandbox.
SAFE_ENV = {
    "COLORTERM", "FORCE_COLOR", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "LOGNAME", "NO_COLOR", "PATH", "SHELL", "TERM", "USER", "__CF_USER_TEXT_ENCODING",
}

# Runs inside a sandbox and starts the commands, so they share it: a later command can stop
# a server an earlier one started, and nothing can signal a process outside. Standard
# library only; it must start with no site packages. When the device closes it, it stops
# everything that runs in the sandbox, including what detached itself or ignores a polite
# request to stop.
RUNNER = r"""
import json, os, signal, subprocess, sys, time
outside = os.getppid()
groups = []
def stop(group, sig):
    try:
        os.killpg(group, sig)
        return True
    except OSError:
        return False
def confined():
    # True only when this process provably cannot touch anything outside the sandbox.
    try:
        os.kill(outside, 0)
        return False  # it can signal the device, so it is not confined
    except OSError:
        pass
    probe = "/private/tmp/.hands-probe-%d" % os.getpid()
    try:
        os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        os.unlink(probe)
        return False
    except PermissionError:
        return True
    except OSError:
        return False
sys.stdout.write("ready\n"); sys.stdout.flush()
for line in sys.stdin:
    job = json.loads(line)
    code = 127
    try:
        text = job.get("stdin")
        with open(job["out"], "wb") as out:
            p = subprocess.Popen(job["argv"], cwd=job["cwd"], stdout=out, stderr=subprocess.STDOUT,
                                 stdin=subprocess.PIPE if text is not None else subprocess.DEVNULL,
                                 start_new_session=True)
            groups.append(p.pid)
            try:
                p.communicate(text.encode() if text is not None else None, timeout=job["timeout"])
                code = p.returncode
            except subprocess.TimeoutExpired:
                stop(p.pid, signal.SIGKILL)
                p.wait()
                code = 124
    except Exception as e:
        try:
            with open(job["out"], "ab") as out:
                out.write(("hands: could not start the command: %s\n" % e).encode())
        except OSError:
            pass
    sys.stdout.write(json.dumps({"id": job["id"], "code": code}) + "\n"); sys.stdout.flush()
alive = [g for g in groups if stop(g, signal.SIGTERM)]
end = time.time() + 2
while alive and time.time() < end:
    time.sleep(0.1)
    alive = [g for g in alive if stop(g, 0)]
for g in groups:
    stop(g, signal.SIGKILL)
if sys.platform == "darwin" and confined():
    # In the macOS sandbox a signal reaches only processes in the same sandbox, so this
    # ends whatever is left in it and nothing else. (On Linux the sandbox has its own
    # process list, which ends with this process.)
    try:
        os.kill(-1, signal.SIGKILL)
    except OSError:
        pass
"""


class HandsError(RuntimeError):
    pass


class _Stopped(Exception):
    """Raised by the stop signal while the device is only waiting for work."""


def say(text: str) -> None:
    print(text, flush=True)  # visible at once, also when the output goes to a file or a service log


def _within(path: str, folder: str) -> bool:
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def home() -> Path:
    return Path(os.environ.get("TENUO_HANDS_HOME") or "~/.hermes-tenuo/hands").expanduser()


def _private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def device_key():
    """This device's key, created on first use and kept in a file only you can read."""
    from tenuo import SigningKey
    path = home() / "device.key"
    if path.is_file():
        return SigningKey.from_bytes(wire.unb64(path.read_text()))
    key = SigningKey.generate()
    _private_write(path, wire.b64(bytes(key.secret_key_bytes())) + "\n")
    return key


def _post(url: str, body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    request = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read(wire.MAX_BODY))
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read(65536)).get("error", "")
        except ValueError:
            detail = ""
        raise HandsError(detail or f"the server answered {e.code}") from e
    except (OSError, ValueError) as e:
        raise ConnectionError(str(getattr(e, "reason", e))) from e


class Device:
    def __init__(self, invite: Optional[str], folder: str, ttl_seconds: int, name: Optional[str] = None,
                 allow_unsandboxed: bool = False, say: Callable[[str], None] = say):
        self.folder = os.path.realpath(os.path.expanduser(folder))
        if not os.path.isdir(self.folder):
            raise HandsError(f"{folder} is not a folder")
        if self.folder in ("/", os.path.realpath(os.path.expanduser("~"))):
            raise HandsError("point Hands at a project folder, not your home folder or /")
        if ttl_seconds <= 0:
            raise HandsError("the time window must be positive")
        self.allow_unsandboxed = allow_unsandboxed
        # Where this device keeps its key, its log and the commands' temp folder. Commands
        # never see it (only the temp folder inside), so it cannot overlap what is shared.
        self.state = os.path.realpath(home())
        if _within(self.state, self.folder) or _within(self.folder, self.state):
            raise HandsError(f"the shared folder and Hands's own folder ({self.state}) must be separate: "
                             "share another folder, or set TENUO_HANDS_HOME to a folder outside it")
        self.tmp = os.path.join(self.state, "tmp")
        os.makedirs(self.tmp, mode=0o700, exist_ok=True)
        sandbox.wrap(self.folder, self.tmp, ["true"], allow_unsandboxed=allow_unsandboxed)  # fail before pairing
        self.say = say
        self.key = device_key()
        self.name = name or socket.gethostname().split(".")[0]
        saved = home() / "server.json"
        if invite:
            parsed = wire.Invite.parse(invite)
            self.url, self.secret, server = parsed.url, parsed.secret, parsed.server_key
        elif saved.is_file():
            data = json.loads(saved.read_text())
            self.url, self.secret, server = data["url"], "", data["server_key"]
        else:
            raise HandsError("no server paired yet: run `/hands invite` in a Hermes chat and pass the line it prints")
        self.server_key = wire.public_key(server)
        self.expires = time.time() + ttl_seconds
        self.grant = wire.mint_grant(self.key, self.server_key, self.folder, ttl_seconds)
        self.identity = wire.mint_identity(self.key, ttl_seconds)
        self.me = wire.key_text(self.key.public_key)
        self._seen: set = set()
        self._stop = False
        self._polled_at: Optional[float] = None
        self._waiting = False
        self._runner: Optional[subprocess.Popen] = None
        self._log = home() / "log.jsonl"

    # -- talking to the server ------------------------------------------------

    def _signed(self, tool: str, args: Dict[str, str]) -> str:
        return wire.sign(self.identity, self.key, tool, args)

    def pair(self) -> None:
        grant, identity = self.grant.to_base64(), self.identity.to_base64()
        nonce = wire.digest(grant, self.folder, self.name, self.tmp)
        _post(self.url + wire.API + "/pair", {
            "invite": self.secret, "device": self.me, "name": self.name, "folder": self.folder, "tmp": self.tmp,
            "grant": grant, "identity": identity, "nonce": nonce,
            "sig": self._signed(wire.TOOL_POLL, {"nonce": nonce}),
        }, timeout=30)
        _private_write(home() / "server.json", json.dumps(
            {"url": self.url, "server_key": wire.key_text(self.server_key)}) + "\n")

    def poll(self) -> Optional[Dict[str, Any]]:
        nonce = secrets.token_hex(16)
        self._polled_at = time.time()
        reply = _post(self.url + wire.API + "/poll", {
            "device": self.me, "nonce": nonce, "sig": self._signed(wire.TOOL_POLL, {"nonce": nonce}),
        }, timeout=min(wire.POLL_SECONDS + 15, max(1.0, self.expires - time.time() + 1)))
        return reply.get("job")

    def bye(self) -> None:
        """Tell the server this device is going down, so callers hear it now instead of waiting."""
        nonce = secrets.token_hex(16)
        try:
            _post(self.url + wire.API + "/bye", {
                "device": self.me, "nonce": nonce, "sig": self._signed(wire.TOOL_POLL, {"nonce": nonce}),
            }, timeout=5)
        except (HandsError, ConnectionError):
            pass

    def report(self, job_id: str, output: str, returncode: int) -> None:
        args = {"job": job_id, "digest": wire.digest(output, returncode)}
        _post(self.url + wire.API + "/result", {
            "device": self.me, "job": job_id, "output": output, "returncode": returncode,
            "sig": self._signed(wire.TOOL_RESULT, args),
        }, timeout=60)

    # -- checking and running one command ----------------------------------------

    def verify(self, job: Dict[str, Any]) -> str:
        """The folder this command may change, or raise. Nothing here trusts the server."""
        job_id, where = str(job["id"]), str(job["dir"])
        if job_id in self._seen:
            raise HandsError("this command was already run")
        if time.time() > self.expires:
            raise HandsError("the time window has ended")
        args = {"dir": where, "cmd": wire.digest(job_id, job["cmd"], bool(job.get("login")), job.get("stdin"),
                                                int(job["timeout"]), job.get("shown") or "",
                                                int(job.get("waited_ms") or 0))}
        chain = wire.load_chain(job["chain"])
        if chain[0].to_base64() != self.grant.to_base64():
            raise HandsError("this command belongs to an old Hands session")
        wire.check(chain, self.key.public_key, wire.TOOL, args, job["pop"])
        real = os.path.realpath(where)
        if not (real == self.folder or real.startswith(self.folder + os.sep)) or not os.path.isdir(real):
            raise HandsError("the command is for a folder this device isn't serving")
        self._seen.add(job_id)
        return real

    def budget(self, job: Dict[str, Any]) -> int:
        """Seconds this command may still run. The server signs how long it will wait and
        how long this device's request had been open when it handed the command over, so
        the device can tell, with its own clock only, that a command reached it too late
        (the machine slept, the network stalled) and must not run. Nothing runs past the
        end of this device's own time window either."""
        timeout = max(1, min(int(job["timeout"]), 24 * 3600))
        window = self.expires - time.time()
        if window <= 0:
            raise HandsError("the time window has ended")
        if self._polled_at is not None:
            late = (time.time() - self._polled_at) - int(job.get("waited_ms") or 0) / 1000.0
            if late >= timeout:
                raise HandsError("it reached this machine too late to run (asleep or offline), so it was not run")
            timeout = math.ceil(timeout - max(0.0, late))
        return max(1, min(timeout, math.ceil(window)))

    def _env(self) -> Dict[str, str]:
        env = {name: value for name, value in os.environ.items() if name in SAFE_ENV}
        env.setdefault("PATH", os.defpath)
        env["HOME"] = self.tmp  # a login shell must not source the user's real dotfiles
        env["TMPDIR"] = self.tmp
        return env

    def run(self, job: Dict[str, Any], folder: str, timeout: Optional[int] = None) -> tuple:
        shell = ["/bin/bash", "-lc" if job.get("login") else "-c", job["cmd"]]
        timeout = timeout or max(1, min(int(job["timeout"]), 24 * 3600))
        # The command writes its output to this file. It is read back through the handle
        # opened here, never by name: the name is in a folder the command can change.
        fd, out_path = tempfile.mkstemp(prefix=".hands-out-", dir=self.tmp)
        try:
            if folder == self.folder:
                if self._runner is None or self._runner.poll() is not None:
                    self._runner = self._start_runner(self.folder, shared=True)
                runner, own = self._runner, False
            else:
                # A narrower warrant gets its own, narrower sandbox for the one command.
                runner, own = self._start_runner(folder, shared=False), True
            if runner is None:
                return "hands: this machine could not start its sandbox, so the command was not run\n", 126
            code = self._ask(runner, shell, folder, job.get("stdin"), timeout, out_path)
            if own or code is None:
                self._close(runner)  # stops whatever the command left behind
                if not own:
                    self._runner = None
            os.lseek(fd, 0, os.SEEK_SET)
            data = b""
            while len(data) <= MAX_OUTPUT:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(fd)
            try:
                os.unlink(out_path)
            except OSError:
                pass
        text = data[:MAX_OUTPUT].decode("utf-8", errors="replace")
        if code is None:
            code = 124
        if code == 124:
            text += f"\nhands: stopped after {timeout} seconds\n"
        if len(data) > MAX_OUTPUT:
            text += "\nhands: output cut at 8 MB\n"
        return text, code

    # -- the sandbox the commands run in ---------------------------------------------

    def _start_runner(self, folder: str, shared: bool) -> Optional[subprocess.Popen]:
        python = os.path.realpath(getattr(sys, "_base_executable", None) or sys.executable)
        # The interpreter and its standard library, wherever they are installed.
        own = sorted({os.path.realpath(p) for p in (sys.base_prefix, sys.base_exec_prefix, os.path.dirname(python))})
        try:
            argv = sandbox.wrap(folder, self.tmp, [python, "-I", "-S", "-c", RUNNER],
                                allow_unsandboxed=self.allow_unsandboxed, shared=shared, readable=own,
                                hidden=[self.state])
            runner = subprocess.Popen(argv, cwd=folder, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, start_new_session=True, env=self._env(), bufsize=0)
        except (OSError, sandbox.SandboxUnavailable):
            return None
        if self._line(runner, 15) != "ready":
            self._close(runner)
            return None
        return runner

    @staticmethod
    def _line(runner: subprocess.Popen, seconds: float) -> Optional[str]:
        """One line from the runner, or None if it does not come in time."""
        data, end = b"", time.time() + seconds
        while not data.endswith(b"\n"):
            left = end - time.time()
            if left <= 0 or not select.select([runner.stdout], [], [], left)[0]:
                return None
            chunk = os.read(runner.stdout.fileno(), 65536)
            if not chunk:
                return None
            data += chunk
        return data.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _close(runner: Optional[subprocess.Popen]) -> None:
        """End a sandbox. The runner stops everything in it, then exits."""
        if runner is None:
            return
        try:
            runner.stdin.close()
            runner.wait(8)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            os.killpg(runner.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            runner.wait(2)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _stop_runner(self) -> None:
        runner, self._runner = self._runner, None
        self._close(runner)

    def _ask(self, runner: subprocess.Popen, shell: list, folder: str, stdin: Optional[str], timeout: int,
             out_path: str) -> Optional[int]:
        """Run one command in a sandbox; None if the sandbox hung or died."""
        job_id = secrets.token_hex(8)
        line = json.dumps({"id": job_id, "argv": shell, "cwd": folder, "stdin": stdin, "timeout": timeout,
                           "out": out_path}) + "\n"
        try:
            runner.stdin.write(line.encode())
            runner.stdin.flush()
            reply = self._line(runner, timeout + 20)
            answer = json.loads(reply) if reply else {}
        except (OSError, ValueError):
            answer = {}
        if answer.get("id") != job_id:
            return None
        return int(answer.get("code", 127))

    def handle(self, job: Dict[str, Any]) -> None:
        job_id = str(job.get("id", ""))
        shown = str(job.get("shown") or "(session setup)")[:500]
        try:
            folder = self.verify(job)
            timeout = self.budget(job)
        except Exception as e:  # a refusal is reported, never run
            reason = str(e) or type(e).__name__
            self._record(shown, None, f"refused: {reason}")
            self.report(job_id, f"hands: refused on the device: {reason}\n", 126)
            return
        output, code = self.run(job, folder, timeout)
        self._record(shown, code, "")
        self.report(job_id, output, code)

    def _record(self, shown: str, code: Optional[int], note: str) -> None:
        line = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "folder": self.folder, "command": shown,
                "exit": code, "note": note}
        with open(self._log, "a") as f:
            f.write(json.dumps(line) + "\n")
        self.say(f"  {time.strftime('%H:%M:%S')}  {'refused' if code is None else f'exit {code}'}  {shown[:100]}")

    # -- the loop ---------------------------------------------------------------

    def stop(self, *from_signal: Any) -> None:
        self._stop = True
        if from_signal and self._waiting:
            raise _Stopped()  # leave the open request now; a running command finishes first

    def serve(self) -> int:
        self.pair()
        until = time.strftime("%H:%M", time.localtime(self.expires))
        self.say(f"Hands is up: {self.url} can run commands in {self.folder} until {until}.")
        self.say("Press Ctrl-C to stop. Commands appear below as they run.")
        failures = 0
        while not self._stop and time.time() < self.expires:
            try:
                self._waiting = True
                try:
                    job = self.poll()
                finally:
                    self._waiting = False
                failures = 0
            except _Stopped:
                break
            except HandsError as e:
                self._stop_runner()
                self.say(f"The server ended this session: {e}")
                return 1
            except ConnectionError as e:
                if time.time() >= self.expires:
                    break
                failures += 1
                if failures == 1:
                    self.say(f"Can't reach the server ({e}); retrying.")
                time.sleep(min(30, 2 ** min(failures, 5)))
                continue
            if job:
                try:
                    self.handle(job)
                except (HandsError, ConnectionError) as e:
                    self.say(f"Couldn't report a result: {e}")
        self._stop_runner()
        self.bye()
        self.say("Hands is down: the time window ended." if not self._stop else "Hands is down.")
        return 0
