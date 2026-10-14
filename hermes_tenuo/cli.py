"""
hermes-tenuo CLI — warrant minting and management.

Usage:
    hermes-tenuo mint --ttl 1h --allow web_search --allow read_file
    hermes-tenuo status
    hermes-tenuo verify
    hermes-tenuo audit --last 20 --denied
    hermes-tenuo demo

Each --allow takes a tool name with optional argument constraints:

    --allow web_search                      any arguments
    --allow read_file:path=/data            path must stay under /data
    --allow memory:target=user              exact value
    --allow write_file:path=/tmp/out,content=*  several constraints
    --allow web_search:query=acme*          glob pattern
    --allow git:action=status|diff|log      one of several values
    --allow checkout:amount=0..4000         number from 0 to 4000, inclusive

Value rules: ``*`` allows anything; ``a|b`` is a choice; ``MIN..MAX`` is a
numeric range (both ends required, inclusive); a value containing ``*`` or
``?`` is a glob; a value starting with ``/`` or ``~`` is a path prefix
(Subpath, traversal-safe); anything else must match exactly.

A range only matches numbers. A tool that sends the amount as a string
(``"40.00"``) is denied, so declare that argument as a number.

Tenuo checks arguments closed-world: once a tool has a constraint, an
argument the warrant does not list is denied, and a listed argument must
be present. For Hermes's own tools mint fills in the rest: arguments
Hermes always sends are added as ``*``, and when a tool's other optional
arguments only page or trim output (``read_file`` offset/limit) they are
allowed. ``--open-args TOOL`` allows every argument the warrant does not
name for that tool.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_mint(args: argparse.Namespace) -> int:
    """Mint a warrant and print config to stdout."""
    return _mint_local(args)


_NUMBER = r"-?\d+(?:\.\d+)?"
_RANGE = re.compile(rf"^({_NUMBER})\.\.({_NUMBER})$")
_MAX_SAFE_INTEGER = (1 << 53) - 1


def _parse_number(text: str) -> float | int:
    value = float(text) if "." in text else int(text)
    # Tenuo Range uses f64 bounds. Reject CLI literals that would become
    # non-finite or cross the range where adjacent integers remain distinct.
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"range bound '{text}' is not finite")
    if abs(value) > _MAX_SAFE_INTEGER:
        raise ValueError(
            f"range bound '{text}' exceeds the safe numeric limit "
            f"{_MAX_SAFE_INTEGER}"
        )
    return value


def _parse_constraint_value(value: str) -> Any:
    """Map one ``arg=value`` string to a tenuo constraint (see module docstring)."""
    from tenuo import Exact, OneOf, Pattern, Range, Subpath, Wildcard
    v = value.strip()
    if v == "*":
        return Wildcard()
    m = _RANGE.fullmatch(v)
    if m:
        lo, hi = _parse_number(m.group(1)), _parse_number(m.group(2))
        if lo > hi:
            raise ValueError(f"range minimum {m.group(1)} is above maximum {m.group(2)}")
        return Range(lo, hi)
    if "|" in v:
        choices = [c.strip() for c in v.split("|") if c.strip()]
        if not choices:
            raise ValueError("empty choice list")
        return OneOf(choices)
    if "*" in v or "?" in v:
        return Pattern(v)
    if v.startswith(("/", "~")):
        return Subpath(os.path.expanduser(v))
    return Exact(v)


def parse_allow(spec: str) -> tuple[str, dict, dict]:
    """Parse ``tool[:arg=value[,arg=value...]]``.

    Returns ``(tool, constraints, display)`` where ``constraints`` maps
    argument names to tenuo constraint objects and ``display`` keeps the raw
    value strings for printing.
    """
    tool, _, rest = spec.strip().partition(":")
    tool = tool.strip()
    if not tool:
        raise ValueError(f"--allow '{spec}': missing tool name")
    constraints: dict = {}
    display: dict = {}
    for item in rest.split(","):
        item = item.strip()
        if not item:
            continue
        arg, eq, value = item.partition("=")
        arg, value = arg.strip(), value.strip()
        if not eq or not arg or not value:
            raise ValueError(f"--allow '{spec}': expected arg=value, got '{item}'")
        try:
            constraints[arg] = _parse_constraint_value(value)
        except ValueError as exc:
            raise ValueError(f"--allow '{spec}': {arg}: {exc}") from exc
        display[arg] = value
    return tool, constraints, display


# Arguments of Hermes Agent's own tools (0.19 schemas):
#   (always sent, optional and output-only, optional and widening).
# mint adds unnamed always-sent arguments as ``*``. When every optional
# argument the user did not name is output-only, the tool allows arguments
# it does not name; otherwise it stays closed and those calls are denied.
_HERMES_TOOL_ARGS: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "read_file": (("path",), ("offset", "limit"), ()),
    "write_file": (("path", "content"), (), ("cross_profile",)),
    "patch": (("mode",), (), ("path", "old_string", "new_string", "replace_all", "patch", "cross_profile")),
    "search_files": (("pattern",), ("limit", "offset", "output_mode", "context"), ("target", "path", "file_glob")),
    "terminal": (("command",), ("timeout",), ("background", "workdir", "pty", "notify_on_complete", "watch_patterns")),
    "web_search": (("query",), ("limit",), ()),
    "web_extract": (("urls",), ("char_limit",), ()),
    "browser_navigate": (("url",), (), ()),
    "vision_analyze": (("image_url", "question"), (), ()),
}


def complete_hermes_args(tool: str, constraints: dict, open_args: bool = False) -> tuple[dict, dict, str, list[str]]:
    """Make one ``--allow`` usable under closed-world argument checks.

    Returns ``(constraints, added, others, notes)``: the constraints to mint,
    the always-sent arguments added as ``*``, whether arguments the warrant
    does not name are ``"allowed"``, ``"denied"`` or ``"any"`` (the tool has
    no constraints), and notes for the operator.
    """
    from tenuo import Wildcard

    if not constraints:
        return constraints, {}, "any", []
    out = dict(constraints)
    added: dict = {}
    notes: list[str] = []
    spec = _HERMES_TOOL_ARGS.get(tool.removeprefix("tool:"))
    auto_open = False
    closed_by: list[str] = []
    if spec is not None:
        required, output_only, widening = spec
        for arg in required:
            if arg not in out:
                out[arg] = Wildcard()
                added[arg] = "*"
        for arg in constraints:
            if arg in output_only or arg in widening:
                notes.append(
                    f"{tool}: '{arg}' is optional in Hermes; naming it makes every "
                    f"{tool} call that omits it fail"
                )
        closed_by = [a for a in widening if a not in constraints]
        auto_open = not closed_by and any(a not in constraints for a in output_only)
    if open_args or auto_open:
        out["_allow_unknown"] = True
        return out, added, "allowed", notes
    if closed_by:
        notes.append(
            f"{tool}: calls that send {', '.join(closed_by)} are denied; "
            f"pass --open-args {tool} to allow arguments the warrant does not name"
        )
    elif spec is None:
        notes.append(
            f"{tool}: arguments other than {', '.join(sorted(constraints))} are denied; "
            f"add the ones it always sends as arg=*, or pass --open-args {tool}"
        )
    return out, added, "denied", notes


def _mint_local(args: argparse.Namespace) -> int:
    """Mint a warrant locally. No network, no account.

    Each ``--allow`` names a tool and, optionally, argument constraints
    (``tool:arg=value,...``). A tool with no constraints is allowed with any
    arguments. See :func:`parse_allow` for the value syntax.
    """
    try:
        from tenuo import SigningKey, Warrant  # noqa: F401
    except ImportError:
        print("error: tenuo is required. Install with: pip install tenuo", file=sys.stderr)
        return 1
    from tenuo import SigningKey, Warrant

    if not args.allow:
        print(
            "error: at least one --allow TOOL is required, e.g. "
            "--allow web_search --allow read_file:path=/data",
            file=sys.stderr,
        )
        return 1

    parsed = []
    for spec in args.allow:
        try:
            parsed.append(parse_allow(spec))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    # Generate keys. Reuse TENUO_SIGNING_KEY as the holder when set so a
    # kanban worker inherits a key that matches the file mint --task writes.
    control_key = SigningKey.generate()
    from hermes_tenuo._config import _env_secret

    existing_key = _env_secret("TENUO_SIGNING_KEY")
    if existing_key:
        try:
            agent_key = SigningKey.from_bytes(base64.b64decode(existing_key))
        except Exception as exc:
            print(f"error: TENUO_SIGNING_KEY is set but could not be loaded: {exc}", file=sys.stderr)
            return 1
    else:
        agent_key = SigningKey.generate()

    open_tools = set(getattr(args, "open_args", None) or [])
    unknown_open = sorted(open_tools - {tool for tool, _, _ in parsed})
    if unknown_open:
        print(f"error: --open-args {unknown_open[0]}: no --allow for that tool", file=sys.stderr)
        return 1
    builder = Warrant.mint_builder().holder(agent_key.public_key)
    completed = []
    for tool, constraints, display in parsed:
        minted, added, others, notes = complete_hermes_args(tool, constraints, tool in open_tools)
        for note in notes:
            print(f"note: {note}", file=sys.stderr)
        builder = builder.capability(tool, **minted)
        completed.append((tool, {**display, **added}, added, others))

    try:
        ttl_seconds = _parse_ttl(args.ttl)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    builder = builder.ttl(ttl_seconds)
    warrant = builder.mint(control_key)

    # Encode
    warrant_b64 = base64.b64encode(warrant.to_bytes()).decode()
    signing_key_b64 = base64.b64encode(agent_key.secret_key_bytes()).decode()
    trusted_root_b64 = base64.b64encode(control_key.public_key.to_bytes()).decode()

    if args.output == "env":
        print(f"export TENUO_WARRANT={warrant_b64}")
        print(f"export TENUO_SIGNING_KEY={signing_key_b64}")
        print(f"export TENUO_TRUSTED_ROOT={trusted_root_b64}")
    elif args.output == "yaml":
        print("# Add to ~/.hermes/config.yaml under plugins.entries.hermes-tenuo:")
        print(f"warrant: {warrant_b64}")
        print(f"trusted_root: {trusted_root_b64}")
        print("# Export before running hermes:")
        print(f"# export TENUO_SIGNING_KEY={signing_key_b64}")
    else:  # "full" default
        print("# ── Hermes config (add to ~/.hermes/config.yaml) ────────────────")
        print("plugins:")
        print("  enabled:")
        print("    - hermes-tenuo")
        print("  entries:")
        print("    hermes-tenuo:")
        print(f"      warrant: {warrant_b64}")
        print(f"      trusted_root: {trusted_root_b64}")
        print("      signing_key_env: TENUO_SIGNING_KEY")
        print()
        print("# ── Signing key (export before running hermes) ───────────────────")
        print(f"export TENUO_SIGNING_KEY={signing_key_b64}")
        print()
        print("# ── Warrant details ─────────────────────────────────────────────")
        print(f"# TTL:   {ttl_seconds}s ({args.ttl})")
        print("# Tools:")
        for tool, display, added, others in completed:
            if others == "any":
                print(f"#   {tool}  (any arguments)")
                continue
            shown = ", ".join(
                f"{k}={v}" + (" (always sent)" if k in added else "") for k, v in display.items()
            )
            print(f"#   {tool}  {shown}; other arguments {others}")
        print()
        print("# Keep the signing key out of config files. The control key that")
        print("# minted this warrant was not saved; mint again to change scope.")

    task_id = getattr(args, "task", None)
    if task_id:
        from hermes_tenuo.kanban import task_warrant_path

        path = task_warrant_path(task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(warrant_b64)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        print(f"# Wrote task warrant: {path}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show what the plugin will load, and where each value comes from."""
    from hermes_tenuo._config import _env_secret, _get_plugin_entry, _looks_like_path
    from hermes_tenuo._home import config_path, hermes_cli_available

    cfg_path = config_path()
    entry = _get_plugin_entry(None)
    via = "hermes_cli" if hermes_cli_available() else "plain read"
    print(f"  Hermes home:  {cfg_path.parent}")
    print(f"  Config file:  {cfg_path} ({'found, ' + via if cfg_path.is_file() else 'not found'})")
    print()

    signing_env = entry.get("signing_key_env", "TENUO_SIGNING_KEY")
    rows = [
        ("Warrant", entry.get("warrant"), _env_secret("TENUO_WARRANT"), "warrant", "TENUO_WARRANT"),
        ("Signing key", None, _env_secret(signing_env), None, signing_env),
        ("Trusted root", entry.get("trusted_root"), _env_secret("TENUO_TRUSTED_ROOT"), "trusted_root", "TENUO_TRUSTED_ROOT"),
    ]
    all_required = True
    for label, cfg_val, env_val, cfg_key, env_name in rows:
        if cfg_val:
            # Never echo the value: a warrant or root is credential material. Say only
            # whether the config points at a file or carries the value inline.
            kind = "file" if isinstance(cfg_val, str) and _looks_like_path(cfg_val) else "inline"
            print(f"  ✓  {label:14} set  (config: {cfg_key}, {kind})")
        elif env_val:
            print(f"  ✓  {label:14} set  (env: {env_name})")
        else:
            hint = f"{cfg_key} or ${env_name}" if cfg_key else f"${env_name}"
            print(f"  ✗  {label:14} not set  ({hint})")
            all_required = False

    if all_required:
        print("\n  Ready for enforcement.")
    else:
        print("\n  Missing required config — enforcement will pass through.")
    return 0


def _warrant_holder(warrant: Any):
    """The holder public key of a warrant across tenuo builds (``holder_key`` since 0.3)."""
    for attr in ("holder_key", "authorized_holder", "holder"):
        value = getattr(warrant, attr, None)
        if value is not None and hasattr(value, "to_bytes"):
            return value
    return None


def cmd_doctor(args: argparse.Namespace) -> int:
    """End-to-end install check.

    Verifies: tenuo importable, plugin entry point registered, Hermes config
    valid, warrant loadable and unexpired, signing key + trusted root present,
    enforcement path (registry hook vs. pre_tool_call fallback).
    """
    ok = True

    def check(passed: bool, msg: str, hint: str = "") -> None:
        nonlocal ok
        if passed:
            print(f"  ✓  {msg}")
        else:
            ok = False
            print(f"  ✗  {msg}")
            if hint:
                print(f"        {hint}")

    def note(msg: str) -> None:
        print(f"  —  {msg}")

    # 1. tenuo importable
    try:
        from tenuo_core import Warrant, PublicKey  # noqa: F401
        check(True, "tenuo_core importable")
    except ImportError as exc:
        check(False, "tenuo_core not importable", f"pip install tenuo ({exc})")
        return 1

    # 2. Plugin entry point registered
    try:
        from importlib.metadata import entry_points
        eps = entry_points(group="hermes_agent.plugins")
        registered = [ep for ep in eps if ep.name == "hermes-tenuo"]
        check(
            bool(registered),
            "plugin entry point hermes_agent.plugins:hermes-tenuo registered",
            'reinstall: pip install --force-reinstall hermes-tenuo',
        )
    except Exception as exc:
        note(f"could not check entry points ({exc})")

    # 3. Hermes config — is the plugin enabled?
    config_entry: dict = {}
    from hermes_tenuo._home import config_path, hermes_cli_available, load_hermes_config
    if not hermes_cli_available():
        note(f"hermes_cli not importable here — reading {config_path()} directly")
    try:
        config = load_hermes_config()
        plugins_cfg = config.get("plugins") or {}
        enabled = plugins_cfg.get("enabled") or []
        check(
            "hermes-tenuo" in enabled,
            "hermes-tenuo listed in plugins.enabled",
            "add `- hermes-tenuo` under plugins.enabled in ~/.hermes/config.yaml",
        )
        config_entry = (plugins_cfg.get("entries") or {}).get("hermes-tenuo") or {}
        if config_entry:
            note(f"plugins.entries.hermes-tenuo has {len(config_entry)} keys")
        else:
            note("plugins.entries.hermes-tenuo empty (falling back to env vars)")
    except Exception as exc:
        note(f"could not read Hermes config ({exc})")

    # 4. Configured? Same resolution the plugin uses (kanban task first).
    from hermes_tenuo._config import (
        _env_secret,
        get_child_warrant_raw,
        load_warrant,
        resolve_warrant_text,
    )

    blocks = "the plugin blocks every tool call until this is fixed"
    # Mirrors build_plugin_guard: a configured warrant that cannot be used
    # installs block-all, it never degrades to passthrough.
    problem = None
    try:
        raw, warrant_source = resolve_warrant_text(None)
    except FileNotFoundError as exc:
        raw, warrant_source = None, "missing"
        problem = f"warrant path does not exist: {exc}"
    except OSError as exc:
        raw, warrant_source = None, "unreadable"
        problem = f"warrant path cannot be read: {exc}"
    if warrant_source.startswith("kanban:"):
        note(warrant_source)
    elif warrant_source not in ("none", "missing", "unreadable"):
        note(f"warrant source: {warrant_source}")

    warrant = load_warrant(raw) if raw else None
    if problem is None and not raw and warrant_source.startswith("kanban:"):
        problem = "kanban worker has no staged task warrant"
    elif problem is None and not raw and warrant_source != "none":
        problem = f"warrant is empty ({warrant_source})"
    elif problem is None and raw and warrant is None:
        problem = "warrant is set but could not be loaded"
    if problem is None and warrant is not None:
        try:
            child_raw = get_child_warrant_raw(None)
        except FileNotFoundError as exc:
            problem = f"child warrant path does not exist: {exc}"
        except OSError as exc:
            problem = f"child warrant path cannot be read: {exc}"
        else:
            if child_raw is not None and load_warrant(child_raw) is None:
                problem = "child warrant is set but could not be loaded"

    configured = warrant is not None and problem is None
    if problem is not None:
        check(False, f"plugin configured (warrant): {problem}", blocks)
    else:
        check(
            configured,
            "plugin configured (warrant)",
            "set TENUO_WARRANT / warrant: — until then the plugin loads and does "
            "not enforce (startup WARNING). Run doctor after install.",
        )

    if warrant is not None:
        # 5. Warrant unexpired / not expiring soon
        try:
            expired = warrant.is_expired()
            check(not expired, "warrant not expired", "mint a fresh warrant: hermes-tenuo mint --ttl 1h ...")
            if not expired:
                try:
                    import datetime
                    exp = getattr(warrant, "expires_at", None)
                    if exp is not None:
                        now = datetime.datetime.now(datetime.timezone.utc)
                        # exp may be a datetime or a Unix timestamp float
                        if isinstance(exp, (int, float)):
                            exp = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
                        days_left = (exp - now).total_seconds() / 86400
                        if days_left < 7:
                            note(f"warrant expires in {days_left:.1f} days — consider renewing soon")
                except Exception:
                    pass
        except Exception:
            note("could not determine warrant expiry")

        # 6. Signing key + holder match
        key_env = config_entry.get("signing_key_env", "TENUO_SIGNING_KEY")
        signing_raw = _env_secret(key_env) or _env_secret("TENUO_SIGNING_KEY")
        if signing_raw:
            try:
                from tenuo_core import SigningKey
                key = SigningKey.from_bytes(base64.b64decode(signing_raw))
                holder = _warrant_holder(warrant)
                if holder is None:
                    note("could not read the warrant holder from this tenuo build — holder match not checked")
                elif key.public_key.to_bytes() == holder.to_bytes():
                    check(True, "signing key matches warrant holder")
                else:
                    check(
                        False,
                        "signing key does not match warrant holder",
                        "export the signing key that was registered with the warrant",
                    )
            except Exception as exc:
                check(False, f"signing key could not be loaded: {exc}")
        else:
            check(False, "signing key not set", "export TENUO_SIGNING_KEY=...")

        # 7. Trusted root (required for enforcement)
        trusted = config_entry.get("trusted_root") or _env_secret("TENUO_TRUSTED_ROOT")
        check(
            bool(trusted),
            "trusted_root set",
            "set TENUO_TRUSTED_ROOT or plugins.entries.hermes-tenuo.trusted_root",
        )
    # 8. Enforcement path
    print()
    try:
        from tools.registry import registry as _tr
        has_enforcement_fn = hasattr(_tr, "set_enforcement_fn")
        if has_enforcement_fn:
            print("  Enforcement paths:")
            print("    ToolRegistry.set_enforcement_fn — registry-dispatched tools")
            print("      Covered: execute_code sandbox, direct registry.dispatch() callers,")
            print("               skip_pre_tool_call_hook=True callers")
            print("    pre_tool_call hook — always registered (covers tools below)")
            print("      Covered: delegate_task, todo, memory, session_search")
            print("      (run_agent.py intercepts these before the registry)")
        else:
            print("  Enforcement path: pre_tool_call hook only")
            print("    Covered: all agent-loop tool calls, including delegate_task,")
            print("    and tools called from inside execute_code scripts (Hermes 0.19+).")
            print("    Gap:")
            print("      - direct registry.dispatch(...) callers bypass enforcement")
            print("        (including plugin ctx.dispatch_tool())")
            print("    Fix pending: https://github.com/NousResearch/hermes-agent/pull/32719")
        print("  execute_code calls arrive without a session id. They are checked")
        print("  against the session that ran the script, found by its task id; when")
        print("  that is not possible and sub-agent or gateway session warrants are")
        print("  in use, the call is blocked.")
        print()
        print("  Lifecycle hooks registered:")
        print("    on_session_start, on_session_end, subagent_start")
        print("    (subagent_start: attaches each delegated child's grant before its first tool call)")
    except ImportError:
        note("skipped the enforcement-path report — this command is not running inside Hermes")
        note("the checks above still cover config, warrant, expiry, and the signing key")
        note("confirm Hermes loaded the plugin: hermes plugins doctor hermes-tenuo")

    print()
    if ok:
        print("  All checks passed.")
        return 0
    else:
        print("  Issues found above. Enforcement may be inactive or partial.")
        return 1


def cmd_audit(args: argparse.Namespace) -> int:
    """Print the local audit log (one line per tool call)."""
    from hermes_tenuo.audit import default_audit_path, format_record, read_audit_log
    path = getattr(args, "path", None) or default_audit_path()
    records = read_audit_log(
        path,
        last=getattr(args, "last", None),
        denied_only=bool(getattr(args, "denied", False)),
    )
    if getattr(args, "json", False):
        for rec in records:
            print(json.dumps(rec, ensure_ascii=False, default=str))
        return 0
    if not records:
        print(f"No audit records at {path}")
        return 0
    for rec in records:
        print(format_record(rec))
    denied = sum(1 for r in records if r.get("decision") == "DENY")
    print(f"\n{len(records)} calls, {denied} denied  ({path})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify the current warrant against trusted_root and show its capabilities."""
    from hermes_tenuo._config import get_trusted_roots, resolve_warrant_text
    from hermes_tenuo._home import hermes_home

    try:
        warrant_raw, source = resolve_warrant_text(None)
    except FileNotFoundError as exc:
        print(f"error: warrant path does not exist: {exc}", file=sys.stderr)
        return 1
    if not warrant_raw:
        if source.startswith("kanban:"):
            print(f"error: no staged task warrant ({source})", file=sys.stderr)
            return 1
        default_path = hermes_home() / "tenuo" / "warrant"
        if default_path.exists():
            warrant_raw = default_path.read_text().strip()
            source = f"file: {default_path}"
        else:
            print(
                f"error: no warrant found (TENUO_WARRANT, plugins.entries.hermes-tenuo.warrant, or {default_path})",
                file=sys.stderr,
            )
            return 1
    print(f"Source:      {source}")

    try:
        from tenuo_core import Warrant
        warrant = Warrant.from_bytes(base64.b64decode(warrant_raw))
    except Exception as e:
        print(f"error: could not load warrant: {e}", file=sys.stderr)
        return 1

    expired = False
    try:
        expired = warrant.is_expired()
    except Exception:
        pass

    print(f"Warrant ID:  {getattr(warrant, 'id', 'unknown')}")
    print(f"Expired:     {'YES ✗' if expired else 'no ✓'}")

    roots = get_trusted_roots(None)
    if not roots:
        print("Signature:   not checked (no trusted_root)")
    else:
        valid = False
        for root in roots:
            try:
                if warrant.verify(root.to_bytes()):
                    valid = True
                    break
            except Exception:
                continue
        if valid:
            print("Signature:   valid ✓")
        else:
            print("Signature:   INVALID ✗  (does not match trusted_root)")
            return 1

    try:
        tools = warrant.tools
        if tools is None:
            print("Tools:       (all — no restrictions)")
        else:
            print(f"Tools:       {', '.join(tools) if tools else '(none)'}")
    except Exception:
        pass

    return 0 if not expired else 1


# ---------------------------------------------------------------------------
# TTL parser
# ---------------------------------------------------------------------------

def _parse_ttl(ttl: str) -> int:
    raw = ttl.strip().lower()
    try:
        if raw.endswith("s"):
            seconds = int(float(raw[:-1]))
        elif raw.endswith("m"):
            seconds = int(float(raw[:-1]) * 60)
        elif raw.endswith("h"):
            seconds = int(float(raw[:-1]) * 3600)
        elif raw.endswith("d"):
            seconds = int(float(raw[:-1]) * 86400)
        else:
            seconds = int(float(raw))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"--ttl '{ttl}': expected a duration like 30m, 1h, 7d, or a positive number of seconds"
        ) from exc
    if seconds <= 0:
        raise ValueError(f"--ttl '{ttl}': must be greater than 0")
    return seconds


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hermes-tenuo",
        description="Tenuo authorization plugin for Hermes Agent",
    )
    subparsers = parser.add_subparsers(dest="command")

    # mint
    mint_p = subparsers.add_parser("mint", help="Mint a warrant and print config")
    mint_p.add_argument("--ttl", default="24h", metavar="DURATION",
                        help="Warrant TTL, e.g. 30m, 1h, 7d (default: 24h)")
    mint_p.add_argument("--allow", action="append", metavar="TOOL[:ARG=VALUE,...]",
                        help="Allow a tool, optionally constraining its arguments (repeatable). "
                             "Examples: --allow web_search  --allow read_file:path=/data  "
                             "--allow git:action=status|diff. Values: '*' any, 'a|b' choice, "
                             "glob with '*'/'?', '/path' prefix, otherwise exact match.")
    mint_p.add_argument("--open-args", action="append", metavar="TOOL",
                        help="Allow arguments the warrant does not name for TOOL (repeatable). "
                             "By default a constrained tool denies them, except the ones mint "
                             "adds for Hermes's own tools.")
    mint_p.add_argument("--task", metavar="ID",
                        help="Write the warrant to $HERMES_HOME/tenuo/warrants/<ID>.warrant "
                             "(kanban worker path). Reuses TENUO_SIGNING_KEY as the holder when set.")
    mint_p.add_argument("--output", choices=["full", "yaml", "env"], default="full",
                        help="Output format: full config (default), yaml keys only, or env exports")

    # status
    subparsers.add_parser("status", help="Show current configuration status")

    # verify
    subparsers.add_parser("verify", help="Verify signature, expiry, and inspect the current warrant")

    # doctor
    subparsers.add_parser("doctor", help="End-to-end install check: plugin discovery, warrant, enforcement path")

    # audit
    audit_p = subparsers.add_parser("audit", help="Show the local audit log (what the agent called, what was denied)")
    audit_p.add_argument("--last", type=int, metavar="N", help="Only the most recent N calls")
    audit_p.add_argument("--denied", action="store_true", help="Only denied calls")
    audit_p.add_argument("--json", action="store_true", help="Raw JSON lines instead of the table")
    audit_p.add_argument("--path", metavar="FILE", help="Audit log file (default: $HERMES_HOME/tenuo/audit.jsonl)")

    subparsers.add_parser("demo", help="Print a local allow/deny transcript (no Hermes process)")

    args = parser.parse_args()

    if args.command == "mint":
        sys.exit(cmd_mint(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "doctor":
        sys.exit(cmd_doctor(args))
    elif args.command == "audit":
        sys.exit(cmd_audit(args))
    elif args.command == "demo":
        from hermes_tenuo.demo import main as cmd_demo
        sys.exit(cmd_demo())
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
