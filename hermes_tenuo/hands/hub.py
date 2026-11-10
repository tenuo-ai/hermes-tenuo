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
from typing import Any, Callable, Dict, List, Optional, Tuple

from hermes_tenuo._home import hermes_home
from hermes_tenuo.hands import wire

logger = logging.getLogger("hermes_tenuo.hands")

INVITE_SECONDS = 600
ONLINE_SECONDS = wire.POLL_SECONDS + 20
GRACE_SECONDS = 20  # how long past a command's own time the server waits for its result
WATCH_SECONDS = 20  # how long a device's "should I stop this command?" request stays open
READ_SECONDS = 20   # how long a connection may take to send its request
MAX_CONNECTIONS = 128
MAX_PER_ADDRESS = 32  # one address cannot take every connection and lock other machines out


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
    mode: str = ""               # what holds commands there: "sandboxed", "read-only", "none"; "" = not said
    owner: str = ""              # who paired it, where the chat platform says who is asking; "" = anyone
    running_until: float = 0.0   # a command is with the device until about then
    gone: bool = False           # the device said it is going down
    last_seen: float = field(default_factory=time.time)
    jobs: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)
    waiting: Dict[str, "queue.Queue[Tuple[str, int]]"] = field(default_factory=dict)
    handed: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # commands the device has, by id
    cancels: set = field(default_factory=set)                         # of those, the ones to stop
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
        self._invites: Dict[str, Tuple[float, str, str]] = {}  # secret -> (until, who asked, in which conversation)
        # Called with (conversation, machine name) when a machine comes up on an invite.
        self.joined: Optional[Callable[[str, str], None]] = None
        self._paired: Dict[str, float] = {}  # pairing requests already used -> when
        self._sessions: Dict[str, Session] = {}
        self._server: Optional[ThreadingHTTPServer] = None
        self._key = None

    # -- keys and known devices ---------------------------------------------------

    @property
    def key(self):
        with self._lock:  # two first callers must end up with the one key that is on disk
            if self._key is None:
                from tenuo import SigningKey
                path = self.dir / "server.key"
                if not path.is_file():
                    self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                    created = SigningKey.generate()
                    try:
                        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    except FileExistsError:
                        pass  # another process made it first: use that one
                    else:
                        with os.fdopen(fd, "w") as f:
                            f.write(wire.b64(bytes(created.secret_key_bytes())) + "\n")
                self._key = SigningKey.from_bytes(wire.unb64(path.read_text()))
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

    def invite(self, owner: str = "", conversation: str = "") -> str:
        """A line that pairs one machine. `owner` is who asked for it: the machine is theirs,
        and only they can use or forget it. `conversation` is where they asked."""
        if not self.public_url:
            raise HandsUnavailable("Hands has no address to give out. Set hands.url (or hands.listen) in the "
                                   "hermes-tenuo plugin config and restart Hermes.")
        secret = secrets.token_urlsafe(18)
        with self._lock:
            now = time.time()
            self._invites = {s: entry for s, entry in self._invites.items() if entry[0] > now}
            self._invites[secret] = (now + INVITE_SECONDS, owner, conversation)
        return wire.Invite(self.public_url, secret, wire.key_text(self.key.public_key)).render()

    def sessions(self, owner: Optional[str] = None) -> List[Session]:
        """The machines that are paired and inside their time window. With `owner` (who is
        asking), only theirs and those that belong to nobody in particular."""
        with self._lock:
            return [s for s in self._sessions.values() if time.time() < s.expires
                    and (owner is None or s.owner in ("", owner))]

    def pick(self, name: str = "", owner: Optional[str] = None) -> Session:
        """The device to use: the named one, or the only one that is up."""
        up = [s for s in self.sessions(owner) if s.online]
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

    def revoke(self, name: str, owner: Optional[str] = None) -> bool:
        with self._lock:
            known = self._known()
            gone = [d for d, info in known.items() if info.get("name") == name
                    and (owner is None or info.get("owner", "") in ("", owner))]
            for device in gone:
                known.pop(device)
                self._sessions.pop(device, None)
            if gone:
                self._save_known(known)
            return bool(gone)

    def run(self, session: Session, cmd: str, *, login: bool, timeout: int, stdin: Optional[str],
            shown: str = "", cancelled: Optional[threading.Event] = None) -> Tuple[str, int]:
        """Queue one command for the device and wait for its checked result.

        `timeout` covers the whole wait: a command the device has not started by then is
        never handed over, and one it starts late runs only for the time that is left. So
        when this returns "timed out", nothing is still waiting to run. Setting `cancelled`
        stops it: a command still in line never runs, one the device has is stopped there."""
        if not session.online:
            raise HandsUnavailable(f"hands: device '{session.name}' is not up any more. "
                                   "Run `hermes-tenuo hands up` on it again.")
        shown = shown[:2000]  # only a label for the device's log
        if wire.sent_size(cmd) + wire.sent_size(stdin or "") + wire.sent_size(shown) > wire.MAX_TEXT:
            return "hands: this command and its input are too large to send to the device in one piece\n", 126
        if cancelled is not None and cancelled.is_set():
            return "hands: stopped before it started\n", 130  # never put in line at all
        job_id = uuid.uuid4().hex
        pending = {"id": job_id, "cmd": cmd, "login": bool(login), "stdin": stdin, "shown": shown,
                   "deadline": time.monotonic() + int(timeout)}
        answer: "queue.Queue[Tuple[str, int]]" = queue.Queue(maxsize=1)
        with self._lock:
            session = self._sessions.get(session.device, session)  # the device may just have come back
            session.waiting[job_id] = answer
            session.jobs.put(pending)
        give_up = time.monotonic() + int(timeout) + GRACE_SECONDS
        stop_by: Optional[float] = None
        try:
            while True:
                try:
                    return answer.get(timeout=0.2)
                except queue.Empty:
                    pass
                now = time.monotonic()
                with self._lock:
                    current = self._sessions.get(session.device, session)
                    over = time.time() > current.expires + wire.REPORT_GRACE
                    had = job_id in current.handed
                if over:
                    # The device's time window is over and its last chance to report has passed.
                    return ((f"hands: device '{session.name}' reached the end of its time window while it had "
                             "this command; it is not known whether it ran\n", 125) if had else
                            (f"hands: device '{session.name}' reached the end of its time window before this "
                             "command could run, so it was not run\n", 127))
                if cancelled is not None and cancelled.is_set() and stop_by is None:
                    with self._lock:
                        current = self._sessions.get(session.device, session)
                        if job_id not in current.handed:
                            # Still in line: taking the caller away means it is never handed over.
                            current.waiting.pop(job_id, None)
                            session.waiting.pop(job_id, None)
                            return "hands: stopped before it started\n", 130
                        current.cancels.add(job_id)  # the device is told to stop it
                    stop_by = now + 15
                if stop_by is not None and now > stop_by:
                    return f"hands: asked device '{session.name}' to stop this command; it has not confirmed\n", 130
                if now > give_up:
                    return f"hands: device '{session.name}' did not answer in time\n", 124
        finally:
            with self._lock:
                self._sessions.get(session.device, session).waiting.pop(job_id, None)
                session.waiting.pop(job_id, None)

    def _hand_over(self, session: Session, pending: Dict[str, Any], poll_started: float,
                   poll: str = "") -> Optional[Dict[str, Any]]:
        """Sign a waiting command for the device now, or drop it if nobody waits for it. The
        signature names the request that takes it, so it is no use as the answer to another."""
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
                                   pending["shown"], waited_ms, poll)}
        session.running_until = time.time() + timeout + 30
        session.handed[pending["id"]] = pending
        return {"id": pending["id"], "cmd": pending["cmd"], "login": pending["login"], "timeout": timeout,
                "stdin": pending["stdin"], "shown": pending["shown"], "waited_ms": waited_ms, "poll": poll,
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
            wire.check([identity], device_key, wire.TOOL_POLL, wire.request("pair", nonce), str(body["sig"]))
        except Refused:
            raise
        except Exception as e:
            raise Refused(f"this pairing request isn't valid ({type(e).__name__})") from e
        # How the device runs commands, and the invite it uses, are part of what it signs:
        # the first is repeated to the agent, and the second decides whose machine it is.
        mode = str(body.get("mode") or "")
        signed = (grant.to_base64(), folder, name, tmp, mode, str(body.get("invite") or ""))
        if nonce != wire.digest(*signed) or mode not in ("", "sandboxed", "read-only", "none"):
            raise Refused("this pairing request doesn't match what was signed")
        if tmp and (not tmp.startswith("/") or len(tmp) > 512 or any(c in tmp for c in "\n\r\0'\"\\$`")):
            raise Refused("this device's temp folder has a path Hands can't use")
        if not wire.same_key(grant.issuer, device_key) or not wire.same_key(grant.authorized_holder, self.key.public_key):
            raise Refused("the grant is not from this device to this server")
        if grant.is_expired() or wire.TOOL not in grant.tools:
            raise Refused("the grant has expired or doesn't allow running commands")
        with self._lock:
            # A pairing request works once. Sent again by the device itself (its first reply
            # was lost), it is answered without touching the session it made; sent again
            # by anyone else later, it cannot replace a newer session.
            now = time.time()
            self._paired = {n: t for n, t in self._paired.items() if now - t < 3600}
            if nonce in self._paired:
                current = self._sessions.get(device)
                if current is not None and current.grant.to_base64() == grant.to_base64():
                    return {"ok": True, "name": current.name}
                raise Refused("this pairing request was already used: run `hermes-tenuo hands up` again")
            known = self._known()
            secret = str(body.get("invite") or "")
            until, asked_by, asked_in = self._invites.pop(secret, (0.0, "", "")) if secret else (0.0, "", "")
            invited = until > time.time()
            if not invited and device not in known:
                raise Refused("this device isn't paired: run `/hands invite` in a Hermes chat and use the new line")
            others = {info.get("name") for d, info in known.items() if d != device}
            if name in others:
                raise Refused(f"another device is already called '{name}': pass --name to choose a different one")
            # A machine belongs to whoever's invite it last used; coming up again without
            # one, it stays theirs.
            owner = asked_by if invited else str(known.get(device, {}).get("owner") or "")
            known[device] = {"name": name, "owner": owner,
                             "paired": known.get(device, {}).get("paired") or time.strftime("%Y-%m-%d")}
            self._save_known(known)
            new = Session(device, name, folder, grant, identity, device_key,
                          time.time() + grant.ttl_remaining.total_seconds(), tmp=tmp, mode=mode, owner=owner)
            new.nonces = [nonce]
            self._paired[nonce] = now
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
        if invited and asked_in and self.joined is not None:
            try:
                self.joined(asked_in, name)  # the conversation that asked for it starts using it
            except Exception as e:  # pairing has succeeded; the switch can still be made by hand
                logger.warning("hermes-tenuo hands: could not switch the inviting conversation (%s)", e)
        return {"ok": True, "name": name}

    def _session(self, body: Dict[str, Any], grace: float = 0.0) -> Session:
        with self._lock:
            session = self._sessions.get(str(body.get("device", "")))
        if session is None or time.time() > session.expires + grace or session.device not in self._known():
            raise Refused("this device has no session here: run `hermes-tenuo hands up` again", 410)
        return session

    def _signed(self, body: Dict[str, Any], op: str, grace: float = 0.0) -> Tuple[Session, str]:
        """The session a device's request belongs to, once it is shown to be signed by the
        device for this operation and not used before."""
        session = self._session(body, grace)
        nonce = str(body.get("nonce", ""))
        try:
            wire.check([session.identity], session.device_key, wire.TOOL_POLL, wire.request(op, nonce),
                       str(body.get("sig", "")))
        except Exception as e:
            raise Refused("this request isn't signed by the device") from e
        with self._lock:
            if nonce in session.nonces:
                raise Refused("this request was already used")
            session.nonces = (session.nonces + [nonce])[-512:]
        return session, nonce

    def poll(self, body: Dict[str, Any]) -> Dict[str, Any]:
        session, nonce = self._signed(body, "poll")
        session.last_seen = time.time()
        started, job = time.monotonic(), None
        while job is None:
            try:
                pending = session.jobs.get(timeout=max(0.0, started + wire.POLL_SECONDS - time.monotonic()))
            except queue.Empty:
                break
            with self._lock:  # one step with pairing: a command is in line or handed, never neither
                current = self._sessions.get(session.device)
                if current is not session:
                    # The device has a newer session: this request is from before, and its
                    # reply may go nowhere. The command waits for the new session instead.
                    if pending is not None and current is not None:
                        current.jobs.put(pending)
                    break
                if pending is not None:
                    job = self._hand_over(session, pending, started, nonce)
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

    def watch(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """A device asks, while it runs a command, whether to stop it. The answer is signed
        like a command, so only this server can stop one."""
        session, _ = self._signed(body, "watch")
        job_id = str(body.get("job", ""))
        end = time.monotonic() + WATCH_SECONDS
        while time.monotonic() < end:
            with self._lock:
                if job_id in session.cancels:
                    args = {"dir": session.folder, "cmd": wire.digest("cancel", job_id)}
                    return {"cancel": True, "pop": wire.sign(session.grant, self.key, wire.TOOL, args)}
                if job_id not in session.handed:
                    break
            time.sleep(0.2)
        return {"cancel": False}

    def bye(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """The device is going down: say so at once to anyone waiting for it."""
        session, _ = self._signed(body, "bye", wire.REPORT_GRACE)  # also right after its window ends
        with self._lock:
            session.gone = True
            waiting, session.waiting = dict(session.waiting), {}
            handed, session.handed = set(session.handed), {}
        for job_id, answer in waiting.items():
            # Only a command the device never received is known not to have run.
            reply = ((f"hands: device '{session.name}' went down while it had this command; "
                      "it is not known whether it ran\n", 125) if job_id in handed else
                     (f"hands: device '{session.name}' went down before running this command, "
                      "so it was not run\n", 127))
            try:
                answer.put_nowait(reply)
            except queue.Full:
                pass
        return {"ok": True}

    def result(self, body: Dict[str, Any]) -> Dict[str, Any]:
        # A command stopped at the end of the window still gets to report, for a short while.
        session = self._session(body, wire.REPORT_GRACE)
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
            session.cancels.discard(job_id)
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
            timeout = READ_SECONDS  # a connection that stops sending is dropped

            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                routes = {wire.API + "/pair": hub.pair, wire.API + "/poll": hub.poll, wire.API + "/result": hub.result,
                          wire.API + "/bye": hub.bye, wire.API + "/watch": hub.watch}
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

        class Listener(ThreadingHTTPServer):
            """At most MAX_CONNECTIONS at once, and MAX_PER_ADDRESS from one address; more
            are closed, not queued."""
            daemon_threads = True
            request_queue_size = 128  # room for real connections to wait while others are turned away
            counting = threading.Lock()
            total = 0
            per_address: Dict[str, int] = {}

            def _take(self, address: str) -> bool:
                with self.counting:
                    if self.total >= MAX_CONNECTIONS or self.per_address.get(address, 0) >= MAX_PER_ADDRESS:
                        return False
                    self.total += 1
                    self.per_address[address] = self.per_address.get(address, 0) + 1
                    return True

            def _give(self, address: str) -> None:
                with self.counting:
                    self.total -= 1
                    left = self.per_address.get(address, 1) - 1
                    if left > 0:
                        self.per_address[address] = left
                    else:
                        self.per_address.pop(address, None)

            def process_request(self, request: Any, client_address: Any) -> None:
                address = str(client_address[0]) if client_address else ""
                if not self._take(address):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except Exception:
                    self._give(address)
                    raise

            def process_request_thread(self, request: Any, client_address: Any) -> None:
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self._give(str(client_address[0]) if client_address else "")

        server = Listener((host or "127.0.0.1", int(port)), Handler)
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
