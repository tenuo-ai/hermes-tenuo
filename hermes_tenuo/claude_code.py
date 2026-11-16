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
import uuid
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
    roots = block.get("workspaces")
    if isinstance(roots, str):
        roots = [roots]
    if not roots or not all(isinstance(r, str) and r for r in roots):
        raise ValueError("claude_code.workspaces must list at least one folder")
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
               *, read_only: bool = False) -> Tuple[Any, Any]:
    """(warrant, holder key) for one run."""
    from tenuo import SigningKey, Subpath, Warrant

    holder = SigningKey.generate()
    builder = Warrant.mint_builder()
    for cap in FILE_CAPS:
        if read_only and cap in ("write_file", "edit_file"):
            continue
        builder = builder.capability(cap, {"path": Subpath(workspace)})
    if commands:
        builder = builder.capability(COMMAND_CAP, {"command": command_constraint(commands)})
    warrant = builder.holder(holder.public_key).ttl(int(ttl_seconds)).mint(issuer)
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
# Tool registration
# ---------------------------------------------------------------------------

DESCRIPTION = (
    "Hand a coding task to Claude Code, running on this machine under a narrow grant: it may "
    "read and edit files in one workspace folder and run only git status/diff/log/show/add/"
    "commit and test commands (never git push or other programs), for a limited time. Use it "
    "when the owner asks for code changes in a repository. Pass on what the owner said about "
    "scope: which commands (commands), whether it may change files (read_only) and for how "
    "long (minutes). Blocks until Claude Code finishes. "
    "Report its result and any denied actions to the owner."
)

SCHEMA = {
    "name": TOOL_NAME,
    "description": DESCRIPTION,
    "parameters": {
        "type": "object",
        "properties": {
            "task": {"type": "string",
                     "description": "What Claude Code should do, in full: the problem, the files "
                                    "if known, and what done looks like (e.g. tests pass, change committed)."},
            "workspace": {"type": "string",
                          "description": "Absolute path of the repository folder to work in."},
            "commands": {"type": "array", "items": {"type": "string"},
                         "description": "Commands Claude Code may run, as the owner chose them, e.g. "
                                        "[\"git diff\", \"pytest\"]. Each must be one of the allowed "
                                        "commands or a narrower form of one. Omit for the default list; "
                                        "[] for no commands."},
            "read_only": {"type": "boolean",
                          "description": "True when the owner only wants Claude Code to read and "
                                         "report (review, explain), not change files."},
            "minutes": {"type": "integer", "minimum": 1,
                        "description": f"How long the grant lasts (default {DEFAULT_MINUTES})."},
        },
        "required": ["task", "workspace"],
        "additionalProperties": False,
    },
}


def register(ctx: Any) -> bool:
    """Register ``claude_code`` when ``claude_code`` is configured. Returns whether it is."""
    from hermes_tenuo._config import _get_plugin_entry
    from hermes_tenuo._home import hermes_home

    try:
        config = load_config(_get_plugin_entry(ctx))
    except Exception as exc:
        logger.error("hermes-tenuo: claude_code is configured but unusable (%s); the tool is off", exc)
        return False
    if config is None or not hasattr(ctx, "register_tool"):
        return False

    def available() -> bool:
        return bool(config["tenuo_claude"] or shutil.which("tenuo-claude"))

    def handler(args: Dict[str, Any], **_kw: Any) -> str:
        try:
            result = run_task(config, hermes_home(), task=args.get("task", ""),
                              workspace=args.get("workspace", ""),
                              minutes=args.get("minutes") or DEFAULT_MINUTES,
                              commands=args.get("commands"),
                              read_only=bool(args.get("read_only")))
            return json.dumps(result)
        except ClaudeCodeError as exc:
            return json.dumps({"ok": False, "error": str(exc)})
        except subprocess.TimeoutExpired:
            return json.dumps({"ok": False, "error": "Claude Code did not finish in time"})
        except Exception as exc:  # never crash the agent loop
            logger.error("hermes-tenuo: claude_code failed: %s", exc, exc_info=True)
            return json.dumps({"ok": False, "error": f"claude_code failed ({type(exc).__name__})"})

    try:
        ctx.register_tool(TOOL_NAME, "tenuo", SCHEMA, handler, check_fn=available, description=DESCRIPTION)
    except TypeError:
        ctx.register_tool(TOOL_NAME, "tenuo", SCHEMA, handler)
    logger.info("hermes-tenuo: claude_code tool on (workspaces: %s)", ", ".join(config["workspaces"]))
    return True


__all__ = ["ClaudeCodeError", "DEFAULT_COMMANDS", "command_constraint", "command_pattern",
           "load_config", "mint_grant", "register", "resolve_workspace", "run_task"]
