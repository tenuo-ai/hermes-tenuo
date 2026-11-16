"""Hand a coding task to Claude Code under a narrow, signed, expiring grant.

The agent calls ``claude_code(task, workspace, minutes)``. Hermes signs a warrant
that lets Claude Code read and edit files inside that one workspace and run only
the listed commands (by default: git status/diff/log/show/add/commit and the
usual test runners; never ``git push``). It starts ``tenuo-claude run`` (from the
``tenuo-claude-code`` package), which runs ``claude -p`` headless and checks every
tool call against the warrant before it runs. The reply carries Claude's result,
every denied call, and the receipt log.

Configure it in the plugin entry; the tool is offered only when it is set::

    plugins:
      entries:
        hermes-tenuo:
          claude_code:
            workspaces: [/opt/data/workspace]   # task folders must be inside one of these
            max_minutes: 30
            # commands: ["git status", "git diff", "pytest"]   # optional; replaces the defaults
            # tenuo_claude: /path/to/tenuo-claude              # default: found on PATH
            # model: sonnet

Hermes signs the grant with its own key, kept in the Hermes home
(``hermes-tenuo/claude-code/issuer.key``). That is the easy-to-set-up choice: if
the Hermes host is compromised, an attacker can sign grants too, but such an
attacker can already run Claude Code directly.

What the grant can't stop: a granted command runs code from the repo (a test
suite, a git hook), and that code is not checked call by call. Keep the command
list short, and run Hermes in a container.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes_tenuo.claude_code")

TOOL_NAME = "claude_code"
DEFAULT_MINUTES = 15
DEFAULT_MAX_MINUTES = 30
MAX_TASK_CHARS = 8000

# Commands Claude Code may run, as prefixes of the whole command. Each is checked
# twice: Shlex (one program, literal arguments, no operators or $()) and an
# anchored pattern on the full command, so `git push` and `git -c ...` are refused
# even though `git` is allowed. Deliberately absent: cat, ls, find and other
# programs that take any path (Claude's Read/Glob/Grep tools are path-scoped).
DEFAULT_COMMANDS = (
    "git status", "git diff", "git log", "git show", "git add", "git commit",
    "git restore", "git rm", "git mv", "git ls-files", "git grep", "git branch", "git switch",
    "pytest", "python -m pytest", "python3 -m pytest",
    "python -m unittest", "python3 -m unittest",
    "npm test", "npm run test", "go test", "cargo test",
)
# Claude tool → capability, as tenuo-claude-code maps them.
FILE_CAPS = ("read_file", "write_file", "edit_file", "glob", "grep")
COMMAND_CAP = "run_command"
REPORT_TOOL = "claude_report"   # what the machine signs its report as (tenuo-claude-code worker)


class ClaudeCodeError(ValueError):
    """The task was not started. The message says why, for the model and the owner."""


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_config(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The ``claude_code`` block, validated, or None when not configured."""
    block = entry.get("claude_code")
    if not isinstance(block, dict):
        return None
    from hermes_tenuo.claude_remote import parse_machines

    roots = block.get("workspaces") or []
    if isinstance(roots, str):
        roots = [roots]
    machines = parse_machines(block.get("machines"))
    if not all(isinstance(r, str) and r for r in roots) or not (roots or machines):
        raise ValueError("claude_code needs workspaces (folders on this host) or machines")
    listen = str(block.get("listen") or "")
    if machines and not listen:
        raise ValueError("claude_code.machines needs claude_code.listen (host:port for machines to dial)")
    commands = block.get("commands", list(DEFAULT_COMMANDS))
    if not isinstance(commands, list) or not all(isinstance(c, str) and c.strip() for c in commands):
        raise ValueError("claude_code.commands must be a list of command prefixes")
    for c in commands:
        if not re.fullmatch(r"[A-Za-z0-9_./:=+-]+( [A-Za-z0-9_./:=+-]+)*", c.strip()):
            raise ValueError(f"claude_code.commands: {c!r} must be plain words (no shell syntax)")
    max_minutes = int(block.get("max_minutes", DEFAULT_MAX_MINUTES))
    if max_minutes <= 0:
        raise ValueError("claude_code.max_minutes must be positive")
    return {
        "workspaces": [os.path.realpath(os.path.expanduser(r)) for r in roots],
        "commands": [c.strip() for c in commands],
        "max_minutes": max_minutes,
        "tenuo_claude": str(block.get("tenuo_claude") or ""),
        "claude": str(block.get("claude") or ""),
        "model": str(block.get("model") or ""),
        "machines": machines,
        "listen": listen,
        # The owner approves each grant in chat before it is signed. Off only on purpose.
        "approval": block.get("approval", True) is not False,
    }


def resolve_workspace(config: Dict[str, Any], requested: str) -> str:
    """The requested folder, resolved, if it is inside a configured workspace root."""
    if not isinstance(requested, str) or not requested.strip():
        if len(config["workspaces"]) == 1:
            requested = config["workspaces"][0]
        else:
            raise ClaudeCodeError("say which workspace folder to use")
    path = os.path.realpath(os.path.expanduser(requested.strip()))
    for root in config["workspaces"]:
        if path == root or path.startswith(root.rstrip(os.sep) + os.sep):
            if not os.path.isdir(path):
                raise ClaudeCodeError(f"{path} is not a folder")
            return path
    raise ClaudeCodeError(
        f"{path} is outside the folders Claude Code may work in: {', '.join(config['workspaces'])}")


# ---------------------------------------------------------------------------
# The grant
# ---------------------------------------------------------------------------


def command_pattern(prefix: str) -> str:
    """Anchored pattern for a command prefix; arguments may follow (and span lines)."""
    return r"(?s)^" + r"\ ".join(re.escape(w) for w in prefix.split()) + r"( .*)?$"


def command_constraint(commands: List[str]) -> Any:
    import tenuo_core
    from tenuo import All, AnyOf, Regex

    binaries = sorted({c.split()[0] for c in commands})
    return All([tenuo_core.Shlex(allow=binaries),
                AnyOf([Regex(command_pattern(c)) for c in commands])])


def issuer_key(home: Path) -> Any:
    """Hermes's signing key for Claude Code grants, created on first use (0600)."""
    from tenuo import SigningKey

    path = home / "hermes-tenuo" / "claude-code" / "issuer.key"
    if path.exists():
        return SigningKey.from_bytes(base64.b64decode(path.read_text().strip()))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = SigningKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(bytes(key.secret_key_bytes())).decode())
    return key


def choose_commands(config: Dict[str, Any], requested: Any) -> List[str]:
    """The commands for this run: the owner's choice, each inside the configured list.

    A requested command must be one of the configured prefixes or a narrower form of
    one ("git commit" or "pytest tests/unit" when "pytest" is configured). None means
    the configured list; an empty list means no commands at all.
    """
    if requested is None:
        return list(config["commands"])
    if not isinstance(requested, list) or not all(isinstance(c, str) for c in requested):
        raise ClaudeCodeError("commands must be a list of command prefixes")
    chosen: List[str] = []
    for raw in requested:
        command = " ".join(raw.split())
        if not command:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_./:=+-]+( [A-Za-z0-9_./:=+-]+)*", command):
            raise ClaudeCodeError(f"{raw!r} must be plain words, without shell syntax")
        if not any(command == c or command.startswith(c + " ") for c in config["commands"]):
            raise ClaudeCodeError(
                f"{command!r} is not allowed here. Allowed: {', '.join(config['commands'])}")
        if command not in chosen:
            chosen.append(command)
    return chosen


def mint_grant(issuer: Any, workspace: str, commands: List[str], ttl_seconds: int,
               *, read_only: bool = False, holder_public_key: Any = None) -> Tuple[Any, Any]:
    """(warrant, holder key) for one run.

    With ``holder_public_key`` (another machine's key) the warrant is held by that
    machine and the returned holder key is None: only that machine can use it.
    """
    from tenuo import SigningKey, Subpath, Warrant

    holder = None if holder_public_key is not None else SigningKey.generate()
    builder = Warrant.mint_builder()
    for cap in FILE_CAPS:
        if read_only and cap in ("write_file", "edit_file"):
            continue
        builder = builder.capability(cap, {"path": Subpath(workspace)})
    if commands:
        builder = builder.capability(COMMAND_CAP, {"command": command_constraint(commands)})
    holder_pub = holder_public_key if holder_public_key is not None else holder.public_key
    warrant = builder.holder(holder_pub).ttl(int(ttl_seconds)).mint(issuer)
    return warrant, holder


# ---------------------------------------------------------------------------
# Running it
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def tenuo_claude_command(config: Dict[str, Any]) -> str:
    found = config["tenuo_claude"] or shutil.which("tenuo-claude")
    if not found:
        raise ClaudeCodeError("tenuo-claude-code is not installed on this Hermes host")
    return found


def run_task(config: Dict[str, Any], home: Path, *, task: str, workspace: str,
             minutes: int, commands: Any = None, read_only: bool = False,
             runner=subprocess.run) -> Dict[str, Any]:
    if not isinstance(task, str) or not task.strip():
        raise ClaudeCodeError("task is required")
    if len(task) > MAX_TASK_CHARS:
        raise ClaudeCodeError(f"task is longer than {MAX_TASK_CHARS} characters")
    try:
        minutes = int(minutes or DEFAULT_MINUTES)
    except (TypeError, ValueError) as exc:
        raise ClaudeCodeError("minutes must be a whole number") from exc
    minutes = max(1, min(minutes, config["max_minutes"]))
    ws = resolve_workspace(config, workspace)
    binary = tenuo_claude_command(config)

    issuer = issuer_key(home)
    chosen = choose_commands(config, commands)
    warrant, holder = mint_grant(issuer, ws, chosen, minutes * 60, read_only=bool(read_only))
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]
    run_dir = home / "hermes-tenuo" / "claude-code" / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    _write_private(run_dir / "warrant", warrant.to_base64())
    _write_private(run_dir / "holder.key", _b64(bytes(holder.secret_key_bytes())))
    root = _b64(issuer.public_key.to_bytes())

    argv = [binary, "run", "--warrant", f"@{run_dir / 'warrant'}",
            "--holder-key", f"@{run_dir / 'holder.key'}", "--trusted-root", root,
            "--workspace", ws, "--state", str(run_dir / "state"),
            "--timeout", str(minutes * 60), "-p", task.strip()]
    if config["claude"]:
        argv += ["--claude", config["claude"]]
    if config["model"]:
        argv += ["--model", config["model"]]
    logger.info("hermes-tenuo: claude_code run %s in %s for %d min (warrant %s)",
                run_id, ws, minutes, warrant.id)
    proc = runner(argv, capture_output=True, text=True, timeout=minutes * 60 + 60,
                  stdin=subprocess.DEVNULL)
    try:
        out = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        out = {"ok": False, "error": (proc.stderr or proc.stdout or "").strip()[-1000:]}
    if not out and proc.returncode:
        out = {"ok": False, "error": (proc.stderr or "").strip()[-1000:] or f"exit {proc.returncode}"}
    (run_dir / "result.json").write_text(json.dumps(out, indent=2))
    # The holder key is only needed during the run.
    try:
        (run_dir / "holder.key").unlink()
    except OSError:
        pass
    return {
        "ok": bool(out.get("ok")),
        "run": run_id,
        "workspace": ws,
        "minutes": minutes,
        "allowed_commands": chosen,
        "read_only": bool(read_only),
        "result": out.get("result"),
        "error": out.get("error"),
        "denied": [{"tool": d.get("tool"), "args": d.get("args")} for d in out.get("denied") or []][:20],
        "denied_count": len(out.get("denied") or []),
        "allowed_count": out.get("allowed"),
        "receipts": out.get("receipts"),
    }


# ---------------------------------------------------------------------------
# Requests, approval and machines
# ---------------------------------------------------------------------------

FOLDER_RE = re.compile(r"[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*")
LOCAL = "here"


@dataclass
class Request:
    id: str
    task: str
    machine: str            # LOCAL or a configured machine name
    workspace: str          # local: absolute path; machine: folder under its shared root
    commands: List[str]
    read_only: bool
    minutes: int
    session_key: str = ""
    branch: str = ""        # machine: the one branch the machine may push, or "" for none
    grant: Dict[str, Any] = field(default_factory=dict)  # machine: its standing grant's terms
    state: str = "waiting"  # waiting → approved → done / denied / failed
    created: float = field(default_factory=time.time)


def branch_for(push: Optional[str], name: Any, request_id: str) -> str:
    """The branch to push under the grant's pattern (``claude/*`` → ``claude/<name>``)."""
    if not push:
        return ""
    raw = str(name or "").strip().strip("/")
    if raw.startswith(push.split("*")[0]):
        raw = raw[len(push.split("*")[0]):]
    raw = re.sub(r"[^A-Za-z0-9._/-]+", "-", raw).strip("-./") or request_id
    if "*" not in push:
        return push
    return push.split("*")[0] + raw[:60]


def build_request(config: Dict[str, Any], args: Dict[str, Any], session_key: str = "",
                  machines: Optional[Dict[str, Any]] = None) -> Request:
    task = args.get("task", "")
    if not isinstance(task, str) or not task.strip():
        raise ClaudeCodeError("task is required")
    if len(task) > MAX_TASK_CHARS:
        raise ClaudeCodeError(f"task is longer than {MAX_TASK_CHARS} characters")
    try:
        minutes = int(args.get("minutes") or DEFAULT_MINUTES)
    except (TypeError, ValueError) as exc:
        raise ClaudeCodeError("minutes must be a whole number") from exc
    minutes = max(1, min(minutes, config["max_minutes"]))
    machine = str(args.get("machine") or "").strip()
    if not machine:
        if config["workspaces"]:
            machine = LOCAL
        elif len(config["machines"]) == 1:
            machine = next(iter(config["machines"]))
        else:
            raise ClaudeCodeError(f"say which machine: {', '.join(config['machines'])}")
    if machine == LOCAL:
        if not config["workspaces"]:
            raise ClaudeCodeError(f"Claude Code doesn't run on this host; machines: {', '.join(config['machines'])}")
        workspace = resolve_workspace(config, args.get("workspace", ""))
    else:
        if machine not in config["machines"]:
            raise ClaudeCodeError(f"unknown machine {machine!r}; configured: {', '.join(config['machines']) or 'none'}")
        workspace = str(args.get("workspace") or "").strip().rstrip("/")
        if not FOLDER_RE.fullmatch(workspace) or any(p in ("..", ".") for p in workspace.split("/")):
            raise ClaudeCodeError("workspace must be a folder name inside the machine's shared folder, "
                                  "e.g. \"calc-demo\"")
    request_id = uuid.uuid4().hex[:6]
    if machine == LOCAL:
        return Request(id=request_id, task=task.strip(), machine=machine, workspace=workspace,
                       commands=choose_commands(config, args.get("commands")),
                       read_only=bool(args.get("read_only")), minutes=minutes, session_key=session_key)
    m = (machines or {}).get(machine)
    info = dict(getattr(m, "grant_info", None) or {})
    if not getattr(m, "grant", "") or not info:
        raise ClaudeCodeError(
            f"{machine} hasn't given Hermes a grant. Its owner runs, on {machine}: "
            "tenuo-claude worker grant --to <key from /claude key> --share <folder>")
    granted = {**config, "commands": [str(c) for c in info.get("commands") or []]}
    read_only = bool(args.get("read_only"))
    push = None if read_only or args.get("push") is False else info.get("push")
    return Request(id=request_id, task=task.strip(), machine=machine, workspace=workspace,
                   commands=choose_commands(granted, args.get("commands")), read_only=read_only,
                   minutes=minutes, session_key=session_key,
                   branch=branch_for(push, args.get("branch"), request_id), grant=info)


def describe(request: Request) -> str:
    """The approval card. Written by the plugin from the request itself, never by the model."""
    where = "this Hermes host" if request.machine == LOCAL else request.machine
    may = ["read files in that folder" if request.read_only else "read and edit files in that folder"]
    if request.commands:
        may.append("run " + ", ".join(request.commands))
    task = request.task if len(request.task) <= 400 else request.task[:400] + "…"
    lines = [f"Claude Code request {request.id}", f"Machine: {where}", f"Folder: {request.workspace}",
             f"May: {'; '.join(may)}"]
    if request.branch:
        lines.append(f"Push: only branch {request.branch} to {request.grant.get('remote') or 'origin'}, "
                     f"done by {request.machine} itself (Claude can't push)")
        lines.append("Never: other branches, other programs, files outside the folder, web access")
    else:
        lines.append("Never: git push, other programs, files outside the folder, web access")
    lines.append(f"For: {request.minutes} min")
    if request.machine != LOCAL:
        back = "Claude's answer and denied calls" if request.grant.get("report") == "full" else \
            "status, branch, commit ids and counts"
        lines.append(f"Reports back: {back} ({request.machine}'s setting)")
    lines.append(f"Task: {task}")
    return "\n".join(lines) + "\n\nApprove or deny: /claude"


class Requests:
    """Pending and finished requests in this process (pending ones end with a restart)."""

    def __init__(self) -> None:
        self._items: Dict[str, Request] = {}
        self._lock = threading.Lock()

    def add(self, request: Request) -> None:
        with self._lock:
            self._items[request.id] = request

    def waiting(self, session_key: str = "") -> List[Request]:
        with self._lock:
            return [r for r in self._items.values() if r.state == "waiting"
                    and (not session_key or not r.session_key or r.session_key == session_key)]

    def take(self, request_id: str, session_key: str = "") -> Optional[Request]:
        """Move a waiting request to approved, once. None if it isn't waiting here."""
        with self._lock:
            request = self._items.get(request_id)
            if request is None or request.state != "waiting":
                return None
            if session_key and request.session_key and request.session_key != session_key:
                return None
            request.state = "approved"
            return request

    def deny(self, request_id: str, session_key: str = "") -> bool:
        with self._lock:
            request = self._items.get(request_id)
            if request is None or request.state != "waiting":
                return False
            if session_key and request.session_key and request.session_key != session_key:
                return False
            request.state = "denied"
            return True


def _summary(out: Dict[str, Any], request: Request, run_id: str) -> Dict[str, Any]:
    summary = {
        "ok": bool(out.get("ok")),
        "request": request.id,
        "run": run_id,
        "machine": request.machine,
        "workspace": request.workspace,
        "minutes": request.minutes,
        "allowed_commands": request.commands,
        "read_only": request.read_only,
        "error": out.get("error"),
        "allowed_count": out.get("allowed"),
        "denied_count": out.get("denied_count", len(out.get("denied") or [])),
        "receipts": out.get("receipts"),
    }
    if request.machine != LOCAL:
        summary.update(branch=out.get("branch") or request.branch or None, pushed=bool(out.get("pushed")),
                       commits=list(out.get("commits") or [])[:20], report=out.get("report") or "summary",
                       verified=out.get("verified") or "unsigned")
    if "result" in out:
        summary["result"] = out.get("result")
    if "denied" in out:
        summary["denied"] = [{"tool": d.get("tool"), "args": d.get("args")} for d in out.get("denied") or []][:20]
    return summary


def standing_grant(machine: Any, issuer: Any) -> Any:
    """The machine's grant to Hermes, checked: signed by the machine's key, to Hermes's key, unexpired."""
    from tenuo import Authorizer, PublicKey, Warrant

    if not machine.grant:
        raise ClaudeCodeError(f"{machine.name} hasn't given Hermes a grant (tenuo-claude worker grant)")
    root = Warrant.from_base64(machine.grant)
    try:
        Authorizer(trusted_roots=[PublicKey.from_bytes(base64.b64decode(machine.public_key))]).verify_chain([root])
    except Exception as exc:
        raise ClaudeCodeError(f"{machine.name}'s grant doesn't check out ({exc})") from exc
    if root.authorized_holder.to_bytes() != issuer.public_key.to_bytes():
        raise ClaudeCodeError(f"{machine.name}'s grant is for a different Hermes key; see /claude key")
    return root


def narrow(root: Any, issuer: Any, machine_key: Any, request: Request, folder: str) -> Any:
    """Hermes's part: the machine's grant, narrowed to this request, held by the machine.

    Tenuo refuses any widening (another branch, a command or folder the grant doesn't
    cover, a longer time), so a request outside the grant fails here, before the card.
    """
    from tenuo import Exact, Subpath

    caps: Dict[str, Any] = {}
    for cap in FILE_CAPS:
        if request.read_only and cap in ("write_file", "edit_file"):
            continue
        caps[cap] = {"path": Subpath(folder)}
    if request.commands:
        caps[COMMAND_CAP] = {"command": command_constraint(request.commands)}
    if request.branch:
        caps["git_push"] = {"remote": Exact(request.grant.get("remote") or "origin"),
                            "branch": Exact(request.branch)}
    ttl = min(request.minutes * 60, max(1, int(root.ttl_remaining.total_seconds())))
    try:
        return root.attenuate(caps, issuer, ttl_seconds=ttl, holder=machine_key)
    except Exception as exc:
        raise ClaudeCodeError(f"that is outside {request.machine}'s grant ({exc})") from exc


def machine_folder(machine: Any, request: Request) -> str:
    share = str(request.grant.get("share") or machine.root or "").rstrip("/")
    return share + "/" + request.workspace


def precheck(home: Path, hub: Any, request: Request) -> None:
    """Refuse up front what the machine's grant doesn't allow, so the owner never approves it."""
    from tenuo import PublicKey

    machine = hub.machines[request.machine]
    root = standing_grant(machine, issuer_key(home))
    narrow(root, issuer_key(home), PublicKey.from_bytes(base64.b64decode(machine.public_key)),
           request, machine_folder(machine, request))


APPROVAL_TOOL = "claude_approval"


def sign_approval(issuer: Any, root: Any, record: Dict[str, Any]) -> Dict[str, Any]:
    """The owner's approval, signed by Hermes as holder of the machine's grant (a Tenuo proof)."""
    import tenuo_core
    from tenuo.meta import argument_json

    ts = int(time.time())
    env = tenuo_core.sign_meta([root], issuer, APPROVAL_TOOL, argument_json(record), ts)
    return {**record, "proof": {"warrant": env["warrant"], "signature": env["signature"], "ts": ts}}


def approval_ok(record: Dict[str, Any], hermes_key: Any) -> bool:
    """True when Hermes's own key signed this approval and it hasn't changed since."""
    import tenuo_core
    from tenuo.meta import argument_json

    proof = record.get("proof")
    if not isinstance(proof, dict):
        return False
    body = {k: v for k, v in record.items() if k != "proof"}
    try:
        chain = list(tenuo_core.decode_warrant_stack_base64(proof["warrant"]))
        if chain[-1].authorized_holder.to_bytes() != hermes_key.public_key.to_bytes():
            return False
        return bool(tenuo_core.verify_meta(proof["warrant"], proof["signature"], APPROVAL_TOOL,
                                           argument_json(body), int(proof["ts"])))
    except Exception:
        return False


def verify_report(report: Dict[str, Any], machine_key_b64: str, grant_id: str) -> str:
    """'signed' when the machine signed this report under this job's grant; otherwise why not."""
    import tenuo_core
    from tenuo.meta import argument_json

    proof = report.get("proof")
    if not isinstance(proof, dict):
        return "unsigned"
    body = {k: v for k, v in report.items() if k != "proof"}
    try:
        chain = list(tenuo_core.decode_warrant_stack_base64(proof["warrant"]))
        if chain[-1].authorized_holder.to_bytes() != base64.b64decode(machine_key_b64):
            return "signed by another key"
        if chain[0].id != grant_id:
            return "signed under another grant"
        ok = tenuo_core.verify_meta(proof["warrant"], proof["signature"], REPORT_TOOL,
                                    argument_json(body), int(proof["ts"]))
    except Exception as exc:
        return f"bad signature ({type(exc).__name__})"
    return "signed" if ok else "bad signature"


def run_on_machine(config: Dict[str, Any], home: Path, hub: Any, request: Request,
                   on_progress=None) -> Dict[str, Any]:
    """Narrow the machine's grant to this request, hand it the job, and wait for its signed report."""
    import tenuo_core
    from tenuo import PublicKey
    from hermes_tenuo.claude_remote import Job

    machine = hub.machines[request.machine]
    if not machine.online:
        raise ClaudeCodeError(f"{request.machine} is not connected. On it, start: tenuo-claude worker")
    issuer = issuer_key(home)
    root = standing_grant(machine, issuer)
    leaf = narrow(root, issuer, PublicKey.from_bytes(base64.b64decode(machine.public_key)), request,
                  machine_folder(machine, request))
    stack = tenuo_core.encode_warrant_stack([root, leaf])
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + request.id
    run_dir = home / "hermes-tenuo" / "claude-code" / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    _write_private(run_dir / "warrant", stack)
    approval = sign_approval(issuer, root, {
        "type": "claude_code.approval", "request": request.id, "machine": request.machine,
        "task_sha256": hashlib.sha256(request.task.encode()).hexdigest(), "folder": request.workspace,
        "commands": request.commands, "read_only": request.read_only, "branch": request.branch,
        "minutes": request.minutes, "grant": root.id, "warrant": leaf.id,
        "session": hashlib.sha256(request.session_key.encode()).hexdigest()[:16] if request.session_key else "",
        "approved_at": int(time.time())})
    (run_dir / "approval.json").write_text(json.dumps(approval, indent=2))
    payload = {"id": run_id, "task": request.task, "folder": request.workspace, "warrant": stack,
               "minutes": request.minutes, "branch": request.branch or None}
    if config["model"]:
        payload["model"] = config["model"]
    job = Job(id=run_id, machine=request.machine, payload=payload, on_progress=on_progress)
    logger.info("hermes-tenuo: claude_code request %s sent to %s (grant %s → warrant %s)",
                request.id, request.machine, root.id, leaf.id)
    hub.submit(job)
    out = hub.wait(job, request.minutes * 60 + 120) or {"ok": False, "error": "no result from the machine in time"}
    out = dict(out)
    out["verified"] = verify_report(out, machine.public_key, root.id)
    (run_dir / "result.json").write_text(json.dumps(out, indent=2))
    return _summary(out, request, run_id)


def run_request(config: Dict[str, Any], home: Path, hub: Any, request: Request,
                on_progress=None, runner=subprocess.run) -> Dict[str, Any]:
    if request.machine == LOCAL:
        out = run_task(config, home, task=request.task, workspace=request.workspace,
                       minutes=request.minutes, commands=request.commands,
                       read_only=request.read_only, runner=runner)
        out["request"], out["machine"] = request.id, LOCAL
        return out
    return run_on_machine(config, home, hub, request, on_progress=on_progress)


def finished_text(request: Request, out: Dict[str, Any]) -> str:
    where = "this host" if request.machine == LOCAL else request.machine
    lines = [f"Claude Code on {where} {'finished' if out.get('ok') else 'stopped'} (request {request.id})."]
    if out.get("error"):
        lines.append(f"Problem: {out['error']}")
    if out.get("pushed"):
        commits = out.get("commits") or []
        lines.append(f"Pushed {out.get('branch')}: {', '.join(commits[:5])}"
                     + (f" (+{len(commits) - 5})" if len(commits) > 5 else ""))
    elif request.branch and out.get("ok"):
        lines.append(f"Nothing pushed: no new commits on {request.branch}.")
    lines.append(f"Checked calls: {out.get('allowed_count') or 0} allowed, {out.get('denied_count') or 0} denied.")
    for d in (out.get("denied") or [])[:5]:
        arg = next(iter((d.get("args") or {}).values()), "")
        lines.append(f"Denied: {d.get('tool')} {str(arg)[:120]}")
    receipts = out.get("receipts") or {}
    if receipts:
        lines.append(f"Receipts: {receipts.get('count')}, chain "
                     f"{'intact' if receipts.get('chain_ok') else 'BROKEN'}"
                     + (f", signed by {where}" if receipts.get("signed_by") else "") + ".")
    if request.machine != LOCAL:
        verified = out.get("verified") or "unsigned"
        lines.append(f"Report: {'signed by ' + where + ' ✓' if verified == 'signed' else verified.upper()}.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool and command registration
# ---------------------------------------------------------------------------

DESCRIPTION = (
    "Hand a coding task to Claude Code under a narrow, expiring grant the owner approves: it may "
    "read (and unless read_only, edit) files in one folder and run only the listed git and test "
    "commands. Claude Code itself never pushes; on a machine whose owner allows it, the machine "
    "pushes the work to one new branch afterwards. Use it when the owner asks for code work in a "
    "repository. Pass on what the owner said about scope: machine, folder (workspace), which "
    "commands, read_only, branch, and minutes. The owner then approves with /claude; this tool "
    "returns at once with the request id. Don't call it again for the same task; tell the owner it "
    "is waiting for their approval. The result arrives as a later message."
)


def schema(config: Dict[str, Any]) -> Dict[str, Any]:
    machines = list(config["machines"]) + ([LOCAL] if config["workspaces"] else [])
    return {
        "name": TOOL_NAME,
        "description": DESCRIPTION,
        "parameters": {
            "type": "object",
            "properties": {
                "task": {"type": "string",
                         "description": "What Claude Code should do, in full: the problem, the files "
                                        "if known, and what done looks like (e.g. tests pass, change committed)."},
                "machine": {"type": "string", "enum": machines,
                            "description": "Where Claude Code runs. "
                                           + (f"'{LOCAL}' is this Hermes host; " if config["workspaces"] else "")
                                           + "others are the owner's own machines."},
                "workspace": {"type": "string",
                              "description": "On a machine: the folder name inside its shared folder, e.g. "
                                             "\"calc-demo\". On this host: the folder's absolute path."},
                "commands": {"type": "array", "items": {"type": "string"},
                             "description": "Commands Claude Code may run, as the owner chose them, e.g. "
                                            "[\"git diff\", \"pytest\"]. Each must be one the host or "
                                            "machine allows (or a narrower form); /claude status lists "
                                            "them. Omit for all of them; [] for none."},
                "branch": {"type": "string",
                           "description": "On a machine that allows pushing: a short name for the branch "
                                          "the work is pushed to, e.g. \"issue-78\" (it becomes "
                                          "claude/issue-78). Omit to use the request id."},
                "push": {"type": "boolean",
                         "description": "False when the owner doesn't want the work pushed. Default: "
                                        "push to a new branch where the machine allows it."},
                "read_only": {"type": "boolean",
                              "description": "True when the owner only wants Claude Code to read and "
                                             "report (review, explain), not change files."},
                "minutes": {"type": "integer", "minimum": 1, "maximum": config["max_minutes"],
                            "description": f"How long the grant lasts (default {DEFAULT_MINUTES})."},
            },
            "required": ["task", "workspace"],
            "additionalProperties": False,
        },
    }


def status_text(hub: Any, waiting: List[Request]) -> str:
    lines = []
    for name, m in (hub.machines.items() if hub else []):
        if not m.online:
            lines.append(f"{name}: not connected")
            continue
        info = m.grant_info or {}
        if not m.grant or not info:
            lines.append(f"{name}: connected, no grant to Hermes yet (/claude key)")
            continue
        lines.append(f"{name}: connected; its grant runs until {str(info.get('expires_at', '?'))[:16]}\n"
                     f"  folders in {info.get('share')}\n"
                     f"  commands: {', '.join(info.get('commands') or []) or 'none'}\n"
                     f"  push: {info.get('push') or 'never'}; reports back: {info.get('report', 'summary')}")
    lines.append(f"Waiting for approval: {', '.join(r.id for r in waiting) or 'none'}")
    return "\n".join(lines)


def audit_text(home: Path, limit: int = 5) -> str:
    """The last few machine runs: who approved what, under which grant, and what came back."""
    runs = home / "hermes-tenuo" / "claude-code" / "runs"
    dirs = sorted((d for d in runs.glob("*") if (d / "approval.json").exists()), reverse=True)[:limit] \
        if runs.exists() else []
    if not dirs:
        return "No Claude Code runs on machines yet."
    key = issuer_key(home)
    lines = []
    for d in dirs:
        try:
            approval = json.loads((d / "approval.json").read_text())
            result = json.loads((d / "result.json").read_text()) if (d / "result.json").exists() else {}
        except (OSError, json.JSONDecodeError):
            continue
        receipts = result.get("receipts") or {}
        state = "running" if not result else ("ok" if result.get("ok") else "stopped")
        lines.append(
            f"{approval.get('request')} on {approval.get('machine')} · {state} · "
            f"{time.strftime('%m-%d %H:%M', time.localtime(approval.get('approved_at', 0)))}\n"
            f"  approved: {approval.get('folder')}, {len(approval.get('commands') or [])} commands, "
            f"push {approval.get('branch') or 'none'}, {approval.get('minutes')} min "
            f"(approval {'signed ✓' if approval_ok(approval, key) else 'BAD SIGNATURE'})\n"
            f"  grant {str(approval.get('grant'))[-8:]} → warrant {str(approval.get('warrant'))[-8:]}\n"
            + (f"  back: {'pushed ' + str(result.get('branch')) if result.get('pushed') else 'nothing pushed'}"
               f", {len(result.get('commits') or [])} commits, {receipts.get('count', 0)} receipts "
               f"(chain {'intact' if receipts.get('chain_ok') else 'BROKEN'}), report {result.get('verified')}"
               if result else "  back: nothing yet"))
    return "\n".join(lines)


def _bound_session_key() -> str:
    try:
        from gateway.session_context import bound_session_key
        return str(bound_session_key() or "")
    except Exception:
        return ""


def register(ctx: Any) -> bool:
    """Register ``claude_code`` and ``/claude`` when ``claude_code`` is configured."""
    from hermes_tenuo._config import _get_plugin_entry
    from hermes_tenuo._home import hermes_home

    try:
        config = load_config(_get_plugin_entry(ctx))
    except Exception as exc:
        logger.error("hermes-tenuo: claude_code is configured but unusable (%s); the tool is off", exc)
        return False
    if config is None or not hasattr(ctx, "register_tool"):
        return False
    hub = None
    if config["machines"]:
        from hermes_tenuo import claude_remote
        hub = claude_remote.start(config["listen"], config["machines"])
        if hub is None:
            config["machines"] = {}
            if not config["workspaces"]:
                return False
    requests = Requests()

    def available() -> bool:
        return bool(config["machines"]) or bool(config["tenuo_claude"] or shutil.which("tenuo-claude"))

    def execute(request: Request, post: Any = None, session_key: str = "") -> None:
        """Run an approved request; report progress into ``post`` and the end into the chat."""
        def progress(lines: List[str]) -> None:
            if post is not None:
                shown = "\n".join(lines[-8:])
                post.edit(f"Claude Code on {request.machine} is working (request {request.id})…\n{shown}")
        try:
            out = run_request(config, hermes_home(), hub, request, on_progress=progress)
            request.state = "done" if out.get("ok") else "failed"
        except ClaudeCodeError as exc:
            out, request.state = {"ok": False, "error": str(exc)}, "failed"
        except Exception as exc:
            logger.error("hermes-tenuo: claude_code request %s failed: %s", request.id, exc, exc_info=True)
            out, request.state = {"ok": False, "error": f"failed ({type(exc).__name__})"}, "failed"
        text = finished_text(request, out)
        if post is not None:
            post.edit(text)
        # Hand the result to the agent so it can report the work in the conversation.
        message = (f"[claude_code result for request {request.id}]\n{json.dumps(out)}\n"
                   "Tell the owner what Claude Code did, and what was denied.")
        try:
            injected = ctx.inject_message(message, session_key=session_key or None) if session_key else False
        except Exception:
            injected = False
        if not injected and post is None:
            logger.warning("hermes-tenuo: claude_code result for %s could not be delivered", request.id)

    def handler(args: Dict[str, Any], **_kw: Any) -> str:
        try:
            session_key = _bound_session_key()
            request = build_request(config, args, session_key, hub.machines if hub else None)
            if request.machine != LOCAL:
                if not hub.machines[request.machine].online:
                    raise ClaudeCodeError(
                        f"{request.machine} is not connected. On that machine, start `tenuo-claude worker`.")
                precheck(hermes_home(), hub, request)
            if not config["approval"]:
                request.state = "approved"
                out = run_request(config, hermes_home(), hub, request)
                return json.dumps(out)
            requests.add(request)
            card = getattr(ctx, "post_message", None)
            posted = card(describe(request)) if card else None
            return json.dumps({
                "ok": True, "status": "waiting_for_approval", "request": request.id,
                "card_shown": bool(getattr(posted, "ok", False)),
                "note": "The owner approves or denies with /claude. Tell them it is waiting; "
                        "don't call claude_code again for this task.",
                **({} if getattr(posted, "ok", False) else {"card": describe(request)}),
            })
        except ClaudeCodeError as exc:
            return json.dumps({"ok": False, "error": str(exc)})
        except Exception as exc:  # never crash the agent loop
            logger.error("hermes-tenuo: claude_code failed: %s", exc, exc_info=True)
            return json.dumps({"ok": False, "error": f"claude_code failed ({type(exc).__name__})"})

    def command(raw_args: str = "", session_key: str = "", **_kw: Any) -> str:
        """``/claude`` (buttons), ``approve|deny <id>``, ``status``, ``key``, ``audit``."""
        words = (raw_args or "").split()
        verb = words[0].lower() if words else ""
        if verb == "status":
            return status_text(hub, requests.waiting(session_key))
        if verb == "key":
            key = _b64(issuer_key(hermes_home()).public_key.to_bytes())
            return (f"Hermes's key for Claude Code grants:\n{key}\n\nOn your machine:\n"
                    f"tenuo-claude worker --name <name> grant --to {key} --share <folder>")
        if verb == "audit":
            return audit_text(hermes_home())
        if verb in ("approve", "deny") and len(words) == 2:
            choice, request_id = verb, words[1]
        else:
            waiting = requests.waiting(session_key)
            if not waiting:
                return "No Claude Code request is waiting for approval."
            request = waiting[-1]
            picked = ctx.ask_choice(describe(request).rsplit("\n\n", 1)[0], [
                {"value": "approve", "label": f"Approve {request.id}"},
                {"value": "deny", "label": f"Deny {request.id}"},
            ]) if hasattr(ctx, "ask_choice") else None
            if picked is None:
                return f"Reply /claude approve {request.id} or /claude deny {request.id}."
            choice, request_id = picked, request.id
        if choice == "deny":
            if not requests.deny(request_id, session_key):
                return f"No waiting request {request_id} here."
            if session_key:
                try:
                    ctx.inject_message(f"[claude_code request {request_id} was denied by the owner]",
                                       session_key=session_key)
                except Exception:
                    pass
            return f"Denied {request_id}. Nothing was signed."
        request = requests.take(request_id, session_key)
        if request is None:
            return f"No waiting request {request_id} here."
        post = None
        if hasattr(ctx, "post_message"):
            handle = ctx.post_message(f"Approved {request.id}. Signing the grant and starting Claude Code "
                                      f"on {request.machine}…")
            post = handle if getattr(handle, "ok", False) else None
        threading.Thread(target=execute, args=(request, post, session_key),
                         name=f"claude-code-{request.id}", daemon=True).start()
        return "" if post is not None else f"Approved {request.id}; Claude Code is starting."

    tool_schema = schema(config)
    try:
        ctx.register_tool(TOOL_NAME, "tenuo", tool_schema, handler, check_fn=available, description=DESCRIPTION)
    except TypeError:
        ctx.register_tool(TOOL_NAME, "tenuo", tool_schema, handler)
    if config["approval"] and hasattr(ctx, "register_command"):
        ctx.register_command("claude", command, description="Approve or deny Claude Code requests",
                             args_hint="[approve <id> | deny <id> | status | key | audit]")
    logger.info("hermes-tenuo: claude_code tool on (here: %s; machines: %s; approval %s)",
                ", ".join(config["workspaces"]) or "off", ", ".join(config["machines"]) or "none",
                "on" if config["approval"] else "off")
    return True


__all__ = ["ClaudeCodeError", "DEFAULT_COMMANDS", "Request", "Requests", "build_request",
           "command_constraint", "command_pattern", "describe", "load_config", "mint_grant",
           "register", "resolve_workspace", "run_request", "run_task"]
