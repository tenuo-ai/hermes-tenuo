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
import json
import logging
import os
import re
import shlex
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
    state: str = "waiting"  # waiting → approved → done / denied / failed
    created: float = field(default_factory=time.time)


def build_request(config: Dict[str, Any], args: Dict[str, Any], session_key: str = "") -> Request:
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
    return Request(id=uuid.uuid4().hex[:6], task=task.strip(), machine=machine, workspace=workspace,
                   commands=choose_commands(config, args.get("commands")),
                   read_only=bool(args.get("read_only")), minutes=minutes, session_key=session_key)


def describe(request: Request) -> str:
    """The approval card. Written by the plugin from the request itself, never by the model."""
    where = "this Hermes host" if request.machine == LOCAL else request.machine
    may = ["read files in that folder" if request.read_only else "read and edit files in that folder"]
    if request.commands:
        may.append("run " + ", ".join(request.commands))
    task = request.task if len(request.task) <= 400 else request.task[:400] + "…"
    return (
        f"Claude Code request {request.id}\n"
        f"Machine: {where}\n"
        f"Folder: {request.workspace}\n"
        f"May: {'; '.join(may)}\n"
        f"Never: git push, other programs, files outside the folder, web access\n"
        f"For: {request.minutes} min\n"
        f"Task: {task}\n\n"
        f"Approve or deny: /claude"
    )


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
    return {
        "ok": bool(out.get("ok")),
        "request": request.id,
        "run": run_id,
        "machine": request.machine,
        "workspace": request.workspace,
        "minutes": request.minutes,
        "allowed_commands": request.commands,
        "read_only": request.read_only,
        "result": out.get("result"),
        "error": out.get("error"),
        "denied": [{"tool": d.get("tool"), "args": d.get("args")} for d in out.get("denied") or []][:20],
        "denied_count": len(out.get("denied") or []),
        "allowed_count": out.get("allowed"),
        "receipts": out.get("receipts"),
    }


def run_on_machine(config: Dict[str, Any], home: Path, hub: Any, request: Request,
                   on_progress=None) -> Dict[str, Any]:
    """Sign a grant held by the machine's key and hand the job to it; wait for the result."""
    from tenuo import PublicKey
    from hermes_tenuo.claude_remote import Job

    machine = hub.machines[request.machine]
    if not machine.online:
        raise ClaudeCodeError(f"{request.machine} is not connected. On it, start: tenuo-claude worker")
    folder = machine.root.rstrip("/") + "/" + request.workspace
    issuer = issuer_key(home)
    warrant, _ = mint_grant(issuer, folder, request.commands, request.minutes * 60,
                            read_only=request.read_only,
                            holder_public_key=PublicKey.from_bytes(base64.b64decode(machine.public_key)))
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + request.id
    run_dir = home / "hermes-tenuo" / "claude-code" / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    _write_private(run_dir / "warrant", warrant.to_base64())
    payload = {"id": run_id, "task": request.task, "folder": request.workspace,
               "warrant": warrant.to_base64(), "minutes": request.minutes,
               "issuer": _b64(issuer.public_key.to_bytes())}
    if config["model"]:
        payload["model"] = config["model"]
    job = Job(id=run_id, machine=request.machine, payload=payload, on_progress=on_progress)
    logger.info("hermes-tenuo: claude_code request %s sent to %s (warrant %s)",
                request.id, request.machine, warrant.id)
    hub.submit(job)
    out = hub.wait(job, request.minutes * 60 + 120) or {"ok": False, "error": "no result from the machine in time"}
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
    lines.append(f"Checked calls: {out.get('allowed_count') or 0} allowed, {out.get('denied_count') or 0} denied.")
    for d in (out.get("denied") or [])[:5]:
        arg = next(iter((d.get("args") or {}).values()), "")
        lines.append(f"Denied: {d.get('tool')} {str(arg)[:120]}")
    receipts = out.get("receipts") or {}
    if receipts:
        lines.append(f"Receipt log: {receipts.get('count')} entries, chain "
                     f"{'intact' if receipts.get('chain_ok') else 'BROKEN'}.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool and command registration
# ---------------------------------------------------------------------------

DESCRIPTION = (
    "Hand a coding task to Claude Code under a narrow, expiring grant the owner approves: it may "
    "read (and unless read_only, edit) files in one folder and run only the listed git and test "
    "commands, never git push or other programs. Use it when the owner asks for code work in a "
    "repository. Pass on what the owner said about scope: machine, folder (workspace), which "
    "commands, read_only, and minutes. The owner then approves with /claude; this tool returns "
    "at once with the request id. Don't call it again for the same task; tell the owner it is "
    "waiting for their approval. The result arrives as a later message."
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
                                            "[\"git diff\", \"pytest\"]. Each must be one of: "
                                            + ", ".join(config["commands"])
                                            + " (or a narrower form). Omit for all of them; [] for none."},
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
            request = build_request(config, args, session_key)
            if request.machine != LOCAL and hub is not None and not hub.machines[request.machine].online:
                raise ClaudeCodeError(
                    f"{request.machine} is not connected. On that machine, start `tenuo-claude worker`.")
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
        """``/claude`` (buttons), ``/claude approve <id>``, ``/claude deny <id>``, ``/claude status``."""
        words = (raw_args or "").split()
        verb = words[0].lower() if words else ""
        if verb == "status":
            lines = [f"{name}: {'connected, sharing ' + m.root if m.online else 'not connected'}"
                     for name, m in (hub.machines.items() if hub else [])]
            waiting = requests.waiting(session_key)
            lines.append(f"Waiting for approval: {', '.join(r.id for r in waiting) or 'none'}")
            return "\n".join(lines)
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
                             args_hint="[approve <id> | deny <id> | status]")
    logger.info("hermes-tenuo: claude_code tool on (here: %s; machines: %s; approval %s)",
                ", ".join(config["workspaces"]) or "off", ", ".join(config["machines"]) or "none",
                "on" if config["approval"] else "off")
    return True


__all__ = ["ClaudeCodeError", "DEFAULT_COMMANDS", "Request", "Requests", "build_request",
           "command_constraint", "command_pattern", "describe", "load_config", "mint_grant",
           "register", "resolve_workspace", "run_request", "run_task"]
