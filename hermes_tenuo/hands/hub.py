"""The server side of Hands: where devices dial in and where commands wait for them.

One hub per Hermes process. It keeps the server's key, the invites it has handed out,
the devices that are up, and a queue of commands per device. Devices connect outward
to it, so a laptop behind a home router needs no open port.
"""

from __future__ import annotations

import json
import logging
import math
import os
import queue
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hermes_tenuo._home import hermes_home
from hermes_tenuo.hands import wire

logger = logging.getLogger("hermes_tenuo.hands")

INVITE_SECONDS = 600
ONLINE_SECONDS = wire.POLL_SECONDS + 20
GRACE_SECONDS = 20  # how long past a command's own time the server waits for its result


class HandsUnavailable(RuntimeError):
    """No device can take the command; the message says what to do."""


class Refused(Exception):
    def __init__(self, message: str, status: int = 403):
        super().__init__(message)
        self.status = status


@dataclass
class Session:
    """One device that is up: what it granted, and the commands waiting for it."""

    device: str
    name: str
    folder: str
    grant: Any
    identity: Any
    device_key: Any
    expires: float
    tmp: str = ""                # where the device keeps temp files for this session
    running_until: float = 0.0   # a command is with the device until about then
    gone: bool = False           # the device said it is going down
    last_seen: float = field(default_factory=time.time)
    jobs: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)
    waiting: Dict[str, "queue.Queue[Tuple[str, int]]"] = field(default_factory=dict)
    handed: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # commands the device has, by id
    nonces: List[str] = field(default_factory=list)

    @property
    def online(self) -> bool:
        # A device does not ask for more work while it runs a command, so a long command
        # counts as being up.
        now = time.time()
        return (not self.gone and now < self.expires
                and (now - self.last_seen < ONLINE_SECONDS or now < self.running_until))


class Hub:
    def __init__(self, state_dir: Optional[Path] = None, public_url: str = ""):
        self.dir = Path(state_dir) if state_dir else hermes_home() / "tenuo" / "hands"
        self.public_url = public_url.rstrip("/")
        self._lock = threading.RLock()
        self._invites: Dict[str, float] = {}
        self._sessions: Dict[str, Session] = {}
        self._server: Optional[ThreadingHTTPServer] = None
        self._key = None

    # -- keys and known devices ---------------------------------------------------

    @property
    def key(self):
        if self._key is None:
            from tenuo import SigningKey
            path = self.dir / "server.key"
            if path.is_file():
                self._key = SigningKey.from_bytes(wire.unb64(path.read_text()))
            else:
                self._key = SigningKey.generate()
                self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(wire.b64(bytes(self._key.secret_key_bytes())) + "\n")
        return self._key

    def _known(self) -> Dict[str, Dict[str, Any]]:
        try:
            return json.loads((self.dir / "devices.json").read_text())
        except (OSError, ValueError):
            return {}

    def _save_known(self, known: Dict[str, Dict[str, Any]]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.dir / f".devices.{os.getpid()}"
        tmp.write_text(json.dumps(known, indent=1) + "\n")
        os.replace(tmp, self.dir / "devices.json")

    # -- what the chat command and the backend call ----------------------------------

    def invite(self) -> str:
        if not self.public_url:
            raise HandsUnavailable("Hands has no address to give out. Set hands.url (or hands.listen) in the "
                                   "hermes-tenuo plugin config and restart Hermes.")
        secret = secrets.token_urlsafe(18)
        with self._lock:
            now = time.time()
            self._invites = {s: t for s, t in self._invites.items() if t > now}
            self._invites[secret] = now + INVITE_SECONDS
        return wire.Invite(self.public_url, secret, wire.key_text(self.key.public_key)).render()

    def sessions(self) -> List[Session]:
        with self._lock:
            return [s for s in self._sessions.values() if time.time() < s.expires]

    def pick(self, name: str = "") -> Session:
        """The device to use: the named one, or the only one that is up."""
        up = [s for s in self.sessions() if s.online]
        if name:
            match = [s for s in up if s.name == name]
            if not match:
                raise HandsUnavailable(f"hands: no device named '{name}' is up. Run `hermes-tenuo hands up` on it.")
            return match[0]
        if not up:
            raise HandsUnavailable("hands: no device is up. On your machine run `hermes-tenuo hands up --dir <folder>` "
                                   "(get the first line from `/hands invite`).")
        if len(up) > 1:
            names = ", ".join(sorted(s.name for s in up))
            raise HandsUnavailable(f"hands: several devices are up ({names}). Pick one with `/hands on <name>`.")
        return up[0]

    def revoke(self, name: str) -> bool:
        with self._lock:
            known = self._known()
            gone = [d for d, info in known.items() if info.get("name") == name]
            for device in gone:
                known.pop(device)
                self._sessions.pop(device, None)
            if gone:
                self._save_known(known)
            return bool(gone)

    def run(self, session: Session, cmd: str, *, login: bool, timeout: int, stdin: Optional[str],
            shown: str = "") -> Tuple[str, int]:
        """Queue one command for the device and wait for its checked result.

        `timeout` covers the whole wait: a command the device has not started by then is
        never handed over, and one it starts late runs only for the time that is left. So
        when this returns "timed out", nothing is still waiting to run."""
        if not session.online:
            raise HandsUnavailable(f"hands: device '{session.name}' is not up any more. "
                                   "Run `hermes-tenuo hands up` on it again.")
        job_id = uuid.uuid4().hex
        pending = {"id": job_id, "cmd": cmd, "login": bool(login), "stdin": stdin, "shown": shown,
                   "deadline": time.monotonic() + int(timeout)}
        answer: "queue.Queue[Tuple[str, int]]" = queue.Queue(maxsize=1)
        with self._lock:
            session = self._sessions.get(session.device, session)  # the device may just have come back
            session.waiting[job_id] = answer
            session.jobs.put(pending)
        try:
            return answer.get(timeout=int(timeout) + GRACE_SECONDS)
        except queue.Empty:
            return f"hands: device '{session.name}' did not answer in time\n", 124
        finally:
            with self._lock:
                self._sessions.get(session.device, session).waiting.pop(job_id, None)
                session.waiting.pop(job_id, None)

    def _hand_over(self, session: Session, pending: Dict[str, Any], poll_started: float) -> Optional[Dict[str, Any]]:
        """Sign a waiting command for the device now, or drop it if nobody waits for it."""
        with self._lock:
            answer = session.waiting.get(pending["id"])
        if answer is None:
            return None  # the caller gave up: it must not run later
        left = pending["deadline"] - time.monotonic()
        if left < 1:
            try:
                answer.put_nowait((f"hands: device '{session.name}' could not start this command in time, "
                                   "so it was not run\n", 124))
            except queue.Full:
                pass
            return None
        timeout, waited_ms = math.ceil(left), int((time.monotonic() - poll_started) * 1000)
        args = {"dir": session.folder,
                "cmd": wire.digest(pending["id"], pending["cmd"], pending["login"], pending["stdin"], timeout,
                                   pending["shown"], waited_ms)}
        session.running_until = time.time() + timeout + 30
        session.handed[pending["id"]] = pending
        return {"id": pending["id"], "cmd": pending["cmd"], "login": pending["login"], "timeout": timeout,
                "stdin": pending["stdin"], "shown": pending["shown"], "waited_ms": waited_ms,
                "dir": session.folder, "chain": [session.grant.to_base64()],
                "pop": wire.sign(session.grant, self.key, wire.TOOL, args)}

    # -- what devices send -----------------------------------------------------------

    def pair(self, body: Dict[str, Any]) -> Dict[str, Any]:
        from tenuo import Warrant
        device = str(body.get("device", ""))
        try:
            device_key = wire.public_key(device)
            grant = Warrant.from_base64(str(body["grant"]))
            identity = Warrant.from_base64(str(body["identity"]))
            nonce, folder, name = str(body["nonce"]), str(body["folder"]), str(body["name"])[:64]
            tmp = str(body.get("tmp") or "")
            wire.check([identity], device_key, wire.TOOL_POLL, {"nonce": nonce}, str(body["sig"]))
        except Refused:
            raise
        except Exception as e:
            raise Refused(f"this pairing request isn't valid ({type(e).__name__})") from e
        if nonce != wire.digest(grant.to_base64(), folder, name, tmp):
            raise Refused("this pairing request doesn't match what was signed")
        if tmp and (not tmp.startswith("/") or len(tmp) > 512 or any(c in tmp for c in "\n\r\0'\"\\$`")):
            raise Refused("this device's temp folder has a path Hands can't use")
        if not wire.same_key(grant.issuer, device_key) or not wire.same_key(grant.authorized_holder, self.key.public_key):
            raise Refused("the grant is not from this device to this server")
        if grant.is_expired() or wire.TOOL not in grant.tools:
            raise Refused("the grant has expired or doesn't allow running commands")
        with self._lock:
            known = self._known()
            secret = str(body.get("invite") or "")
            invited = bool(secret) and self._invites.pop(secret, 0) > time.time()
            if not invited and device not in known:
                raise Refused("this device isn't paired: run `/hands invite` in a Hermes chat and use the new line")
            others = {info.get("name") for d, info in known.items() if d != device}
            if name in others:
                raise Refused(f"another device is already called '{name}': pass --name to choose a different one")
            known[device] = {"name": name, "paired": known.get(device, {}).get("paired") or time.strftime("%Y-%m-%d")}
            self._save_known(known)
            new = Session(device, name, folder, grant, identity, device_key,
                          time.time() + grant.ttl_remaining.total_seconds(), tmp=tmp)
            old = self._sessions.get(device)
            if old is not None:
                # Commands still waiting for this device follow it to its new session; they
                # are signed when handed over, so the new grant covers them.
                new.waiting = old.waiting
                for job_id in list(old.handed):
                    # The device restarted while it had this command. Never send it again:
                    # say that the outcome is not known.
                    answer = new.waiting.pop(job_id, None)
                    if answer is not None:
                        try:
                            answer.put_nowait((f"hands: device '{name}' restarted while it had this command; "
                                               "it is not known whether it ran\n", 125))
                        except queue.Full:
                            pass
                old.handed.clear()
                while True:
                    try:
                        new.jobs.put(old.jobs.get_nowait())
                    except queue.Empty:
                        break
            self._sessions[device] = new
            if old is not None:
                old.jobs.put(None)  # wake a request the old session still has open
        logger.info("hermes-tenuo hands: device '%s' is up for %s", name, folder)
        return {"ok": True, "name": name}

    def _session(self, body: Dict[str, Any]) -> Session:
        with self._lock:
            session = self._sessions.get(str(body.get("device", "")))
        if session is None or time.time() > session.expires or session.device not in self._known():
            raise Refused("this device has no session here: run `hermes-tenuo hands up` again", 410)
        return session

    def poll(self, body: Dict[str, Any]) -> Dict[str, Any]:
        session = self._session(body)
        nonce = str(body.get("nonce", ""))
        try:
            wire.check([session.identity], session.device_key, wire.TOOL_POLL, {"nonce": nonce}, str(body.get("sig", "")))
        except Exception as e:
            raise Refused("this request isn't signed by the device") from e
        with self._lock:
            if nonce in session.nonces:
                raise Refused("this request was already used")
            session.nonces = (session.nonces + [nonce])[-256:]
        session.last_seen = time.time()
        started, job = time.monotonic(), None
        while job is None:
            try:
                pending = session.jobs.get(timeout=max(0.0, started + wire.POLL_SECONDS - time.monotonic()))
            except queue.Empty:
                break
            with self._lock:
                current = self._sessions.get(session.device)
            if current is not session:
                # The device has a newer session: this request is from before, and its
                # reply may go nowhere. The command waits for the new session instead.
                if pending is not None and current is not None:
                    current.jobs.put(pending)
                break
            if pending is not None:
                job = self._hand_over(session, pending, started)
        session.last_seen = time.time()
        return {"job": job}

    def undelivered(self, device: str, job_id: str) -> None:
        """The reply carrying a command could not be sent: the device never got it, so it
        goes back in line (for this session, or the one that replaced it)."""
        with self._lock:
            for session in self._sessions.values():
                pending = session.handed.pop(job_id, None) if session.device == device else None
                if pending is not None:
                    session.running_until = 0.0
                    session.jobs.put(pending)

    def bye(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """The device is going down: say so at once to anyone waiting for it."""
        session = self._session(body)
        nonce = str(body.get("nonce", ""))
        try:
            wire.check([session.identity], session.device_key, wire.TOOL_POLL, {"nonce": nonce}, str(body.get("sig", "")))
        except Exception as e:
            raise Refused("this request isn't signed by the device") from e
        with self._lock:
            if nonce in session.nonces:
                raise Refused("this request was already used")
            session.nonces = (session.nonces + [nonce])[-256:]
            session.gone = True
            waiting, session.waiting = dict(session.waiting), {}
        for answer in waiting.values():
            try:
                answer.put_nowait((f"hands: device '{session.name}' went down before running this command, "
                                   "so it was not run\n", 127))
            except queue.Full:
                pass
        return {"ok": True}

    def result(self, body: Dict[str, Any]) -> Dict[str, Any]:
        session = self._session(body)
        job_id, output = str(body.get("job", "")), body.get("output", "")
        try:
            returncode = int(body.get("returncode"))
            if not isinstance(output, str):
                raise ValueError("output")
            wire.check([session.identity], session.device_key, wire.TOOL_RESULT,
                       {"job": job_id, "digest": wire.digest(output, returncode)}, str(body.get("sig", "")))
        except Exception as e:
            raise Refused("this result isn't signed by the device") from e
        with self._lock:
            answer = session.waiting.pop(job_id, None)
            session.handed.pop(job_id, None)
        if answer is not None:
            answer.put((output, returncode))
        session.running_until = 0.0
        session.last_seen = time.time()
        return {"ok": True}

    # -- the listener ---------------------------------------------------------------

    def listen(self, address: str) -> None:
        host, _, port = address.rpartition(":")
        hub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                routes = {wire.API + "/pair": hub.pair, wire.API + "/poll": hub.poll, wire.API + "/result": hub.result,
                          wire.API + "/bye": hub.bye}
                handler = routes.get(self.path)
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if handler is None:
                        raise Refused("not found", 404)
                    if not 0 < length <= wire.MAX_BODY:
                        raise Refused("bad request size", 413)
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict):
                        raise Refused("bad request", 400)
                    reply = handler(body)
                    job = reply.get("job") if isinstance(reply, dict) else None
                    if not self._send(200, reply) and isinstance(job, dict):
                        hub.undelivered(str(body.get("device", "")), str(job.get("id", "")))
                except Refused as e:
                    self._send(e.status, {"error": str(e)})
                except ValueError:
                    self._send(400, {"error": "bad request"})
                except Exception:
                    logger.exception("hermes-tenuo hands: request failed")
                    self._send(500, {"error": "the server hit an error"})

            def _send(self, status: int, payload: Dict[str, Any]) -> bool:
                """False if the other side is gone."""
                data = json.dumps(payload).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    self.wfile.flush()
                    return True
                except OSError:
                    self.close_connection = True
                    return False

        server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
        server.daemon_threads = True
        self._server = server
        if not self.public_url:
            shown = "127.0.0.1" if server.server_address[0] in ("0.0.0.0", "") else server.server_address[0]
            self.public_url = f"http://{shown}:{server.server_address[1]}"
        threading.Thread(target=server.serve_forever, name="hermes-tenuo-hands", daemon=True).start()

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


_hub: Optional[Hub] = None
_hub_lock = threading.Lock()


def get_hub() -> Optional[Hub]:
    return _hub


def start_hub(listen: str, public_url: str = "") -> Optional[Hub]:
    """Start this process's hub. A port already taken (another Hermes process on this
    machine owns the hub) leaves this process without one."""
    global _hub
    with _hub_lock:
        if _hub is None:
            hub = Hub(public_url=public_url)
            try:
                hub.listen(listen)
            except OSError as e:
                logger.warning("hermes-tenuo hands: can't listen on %s (%s); Hands is off in this process", listen, e)
                return None
            _hub = hub
        return _hub
