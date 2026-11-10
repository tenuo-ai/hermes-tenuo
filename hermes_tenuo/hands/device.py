"""The device side of Hands: `hermes-tenuo hands up` on the machine with your files.

It dials out to the Hermes server, hands over a warrant for one folder and a time
window, then runs the commands the server sends. Every command is checked here, against
the warrant this device signed, before it runs in a sandbox limited to that folder.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from hermes_tenuo.hands import sandbox, wire

MAX_OUTPUT = 8 * 1024 * 1024


class HandsError(RuntimeError):
    pass


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
                 allow_unsandboxed: bool = False, say: Callable[[str], None] = print):
        self.folder = os.path.realpath(os.path.expanduser(folder))
        if not os.path.isdir(self.folder):
            raise HandsError(f"{folder} is not a folder")
        if self.folder in ("/", os.path.realpath(os.path.expanduser("~"))):
            raise HandsError("point Hands at a project folder, not your home folder or /")
        if ttl_seconds <= 0:
            raise HandsError("the time window must be positive")
        self.allow_unsandboxed = allow_unsandboxed
        self.tmp = os.path.realpath(home() / "tmp")
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
        self._log = home() / "log.jsonl"

    # -- talking to the server ------------------------------------------------

    def _signed(self, tool: str, args: Dict[str, str]) -> str:
        return wire.sign(self.identity, self.key, tool, args)

    def pair(self) -> None:
        grant, identity = self.grant.to_base64(), self.identity.to_base64()
        nonce = wire.digest(grant, self.folder, self.name)
        _post(self.url + wire.API + "/pair", {
            "invite": self.secret, "device": self.me, "name": self.name, "folder": self.folder,
            "grant": grant, "identity": identity, "nonce": nonce,
            "sig": self._signed(wire.TOOL_POLL, {"nonce": nonce}),
        }, timeout=30)
        _private_write(home() / "server.json", json.dumps(
            {"url": self.url, "server_key": wire.key_text(self.server_key)}) + "\n")

    def poll(self) -> Optional[Dict[str, Any]]:
        nonce = secrets.token_hex(16)
        reply = _post(self.url + wire.API + "/poll", {
            "device": self.me, "nonce": nonce, "sig": self._signed(wire.TOOL_POLL, {"nonce": nonce}),
        }, timeout=wire.POLL_SECONDS + 15)
        return reply.get("job")

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
                                                int(job["timeout"]), job.get("shown") or "")}
        wire.check(wire.load_chain(job["chain"]), self.key.public_key, wire.TOOL, args, job["pop"])
        real = os.path.realpath(where)
        if not (real == self.folder or real.startswith(self.folder + os.sep)) or not os.path.isdir(real):
            raise HandsError("the command is for a folder this device isn't serving")
        self._seen.add(job_id)
        return real

    def run(self, job: Dict[str, Any], folder: str) -> tuple:
        shell = ["/bin/bash", "-lc" if job.get("login") else "-c", job["cmd"]]
        argv = sandbox.wrap(folder, self.tmp, shell, allow_unsandboxed=self.allow_unsandboxed)
        timeout = max(1, min(int(job["timeout"]), 24 * 3600))
        stdin = job.get("stdin")
        process = subprocess.Popen(argv, cwd=folder, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                                   env=dict(os.environ, TMPDIR=self.tmp))
        try:
            out, _ = process.communicate(stdin.encode() if stdin is not None else None, timeout=timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            out, _ = process.communicate()
            out, code = out + f"\nhands: stopped after {timeout} seconds\n".encode(), 124
        text = out.decode("utf-8", errors="replace")
        if len(text) > MAX_OUTPUT:
            text = text[:MAX_OUTPUT] + "\nhands: output cut at 8 MB\n"
        return text, code

    def handle(self, job: Dict[str, Any]) -> None:
        job_id = str(job.get("id", ""))
        shown = str(job.get("shown") or "")[:500]
        try:
            folder = self.verify(job)
        except Exception as e:  # a refusal is reported, never run
            reason = str(e) or type(e).__name__
            self._record(shown, None, f"refused: {reason}")
            self.report(job_id, f"hands: refused on the device: {reason}\n", 126)
            return
        output, code = self.run(job, folder)
        self._record(shown, code, "")
        self.report(job_id, output, code)

    def _record(self, shown: str, code: Optional[int], note: str) -> None:
        line = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "folder": self.folder, "command": shown,
                "exit": code, "note": note}
        with open(self._log, "a") as f:
            f.write(json.dumps(line) + "\n")
        self.say(f"  {time.strftime('%H:%M:%S')}  {'refused' if code is None else f'exit {code}'}  {shown[:100]}")

    # -- the loop ---------------------------------------------------------------

    def stop(self, *_: Any) -> None:
        self._stop = True

    def serve(self) -> int:
        self.pair()
        until = time.strftime("%H:%M", time.localtime(self.expires))
        self.say(f"Hands is up: {self.url} can run commands in {self.folder} until {until}.")
        self.say("Press Ctrl-C to stop. Commands appear below as they run.")
        failures = 0
        while not self._stop and time.time() < self.expires:
            try:
                job = self.poll()
                failures = 0
            except HandsError as e:
                self.say(f"The server ended this session: {e}")
                return 1
            except ConnectionError as e:
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
        self.say("Hands is down: the time window ended." if not self._stop else "Hands is down.")
        return 0
