"""Claude Code on another machine: a job hub the machine dials out to.

The machine runs ``tenuo-claude worker`` (from ``tenuo-claude-code``). It connects
out to this hub, so the machine opens no port. Each request waits up to ~25
seconds for a job (long poll). A job carries the task and a warrant held by the
machine's own key, so only that machine can use it; the machine checks the
warrant against Hermes's public key before it starts Claude Code, and sends back
progress and the result.

Endpoints (all need ``Authorization: Bearer <token>`` and ``X-Tenuo-Machine``)::

    GET  /claude/next            hello + wait for a job (X-Tenuo-Root: the machine's shared folder,
                                 X-Tenuo-Public-Key: its key, which must match the configured one)
    POST /claude/jobs/<id>/progress   {"line": "..."}
    POST /claude/jobs/<id>/result     the run summary

Machines are configured, never discovered::

    claude_code:
      listen: 0.0.0.0:9931           # put it behind your private network or HTTPS proxy
      machines:
        laptop:
          public_key: "<from `tenuo-claude worker --show-key`>"
          token_env: CLAUDE_WORKER_TOKEN_LAPTOP
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hermes_tenuo.claude_remote")

POLL_SECONDS = 25
MAX_BODY = 2_000_000
ONLINE_SECONDS = 60  # a machine that polled this recently counts as connected


@dataclass
class Machine:
    name: str
    public_key: str
    token_env: str
    root: str = ""
    last_seen: float = 0.0
    jobs: "queue.Queue[dict]" = field(default_factory=queue.Queue)

    def token(self) -> str:
        return os.environ.get(self.token_env, "")

    @property
    def online(self) -> bool:
        return bool(self.root) and time.time() - self.last_seen < ONLINE_SECONDS


@dataclass
class Job:
    id: str
    machine: str
    payload: dict
    done: threading.Event = field(default_factory=threading.Event)
    result: Optional[dict] = None
    progress: List[str] = field(default_factory=list)
    on_progress: Optional[Callable[[List[str]], None]] = None


def parse_machines(raw: Any) -> Dict[str, Machine]:
    from tenuo import PublicKey

    machines: Dict[str, Machine] = {}
    if not raw:
        return machines
    if not isinstance(raw, dict):
        raise ValueError("claude_code.machines must be a mapping")
    for name, spec in raw.items():
        if not isinstance(spec, dict):
            raise ValueError(f"claude_code.machines.{name} must be a mapping")
        key, token_env = str(spec.get("public_key") or ""), str(spec.get("token_env") or "")
        if not key or not token_env:
            raise ValueError(f"claude_code.machines.{name} needs public_key and token_env")
        PublicKey.from_bytes(base64.b64decode(key))  # raises on a bad key
        machines[str(name)] = Machine(str(name), key, token_env)
    return machines


class Hub:
    def __init__(self, machines: Dict[str, Machine]):
        self.machines = machines
        self.jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self.server: Optional[ThreadingHTTPServer] = None

    # -- Hermes side ---------------------------------------------------------

    def submit(self, job: Job) -> None:
        with self._lock:
            self.jobs[job.id] = job
        self.machines[job.machine].jobs.put(job.payload)

    def wait(self, job: Job, timeout: float) -> Optional[dict]:
        job.done.wait(timeout)
        return job.result

    # -- Machine side --------------------------------------------------------

    def authenticate(self, headers: Any) -> Optional[Machine]:
        machine = self.machines.get(str(headers.get("X-Tenuo-Machine") or ""))
        if machine is None:
            return None
        expected = machine.token()
        auth = str(headers.get("Authorization") or "")
        if not expected or not hmac.compare_digest(auth, f"Bearer {expected}"):
            return None
        return machine

    def next_job(self, machine: Machine, root: str, public_key: str, wait: float) -> Optional[dict]:
        if public_key and public_key != machine.public_key:
            raise PermissionError("this machine's key does not match the configured key")
        machine.root, machine.last_seen = root, time.time()
        try:
            return machine.jobs.get(timeout=wait)
        except queue.Empty:
            return None
        finally:
            machine.last_seen = time.time()

    def report(self, machine: Machine, job_id: str, kind: str, body: dict) -> bool:
        job = self.jobs.get(job_id)
        if job is None or job.machine != machine.name:
            return False
        if kind == "progress":
            line = str(body.get("line") or "")[:300]
            if line:
                job.progress.append(line)
                if job.on_progress:
                    try:
                        job.on_progress(list(job.progress))
                    except Exception:
                        logger.debug("claude_code progress callback failed", exc_info=True)
            return True
        job.result = body
        job.done.set()
        return True


def _handler(hub: Hub):
    class Handler(BaseHTTPRequestHandler):
        server_version = "hermes-tenuo-claude"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            logger.debug("claude hub: " + fmt, *args)

        def _send(self, status: int, body: Optional[dict] = None) -> None:
            data = json.dumps(body or {}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            machine = hub.authenticate(self.headers)
            if machine is None:
                return self._send(401, {"error": "unknown machine or wrong token"})
            if self.path.split("?")[0] != "/claude/next":
                return self._send(404)
            try:
                job = hub.next_job(machine, str(self.headers.get("X-Tenuo-Root") or ""),
                                   str(self.headers.get("X-Tenuo-Public-Key") or ""), POLL_SECONDS)
            except PermissionError as exc:
                return self._send(403, {"error": str(exc)})
            if job is None:
                return self._send(204)
            self._send(200, job)

        def do_POST(self) -> None:  # noqa: N802
            machine = hub.authenticate(self.headers)
            if machine is None:
                return self._send(401, {"error": "unknown machine or wrong token"})
            parts = self.path.strip("/").split("/")
            if len(parts) != 4 or parts[:2] != ["claude", "jobs"] or parts[3] not in ("progress", "result"):
                return self._send(404)
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(413)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400)
            if not isinstance(body, dict) or not hub.report(machine, parts[2], parts[3], body):
                return self._send(404)
            self._send(200, {"ok": True})

    return Handler


_HUB: Optional[Hub] = None


def start(listen: str, machines: Dict[str, Machine]) -> Optional[Hub]:
    """Start the hub once per process. ``listen`` is ``host:port``."""
    global _HUB
    if _HUB is not None:
        _HUB.machines.update({k: v for k, v in machines.items() if k not in _HUB.machines})
        return _HUB
    host, _, port = listen.rpartition(":")
    hub = Hub(machines)
    try:
        hub.server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), _handler(hub))
    except OSError as exc:
        logger.error("hermes-tenuo: claude_code machines hub could not listen on %s (%s)", listen, exc)
        return None
    hub.server.daemon_threads = True
    threading.Thread(target=hub.server.serve_forever, name="claude-code-hub", daemon=True).start()
    logger.info("hermes-tenuo: claude_code machines hub listening on %s", listen)
    _HUB = hub
    return hub


__all__ = ["Hub", "Job", "Machine", "parse_machines", "start"]
