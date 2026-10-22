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
    --allow write_file:path=/tmp/out,mode=w exact mode, path under /tmp/out
    --allow web_search:query=acme*          glob pattern
    --allow git:action=status|diff|log      one of several values
    --allow checkout:amount=0..4000         number from 0 to 4000, inclusive

Value rules: ``*`` allows anything; ``a|b`` is a choice; ``MIN..MAX`` is a
numeric range (both ends required, inclusive); a value containing ``*`` or
``?`` is a glob; a value starting with ``/`` or ``~`` is a path prefix
(Subpath, traversal-safe); anything else must match exactly.

A range only matches numbers. A tool that sends the amount as a string
(``"40.00"``) is denied, so declare that argument as a number.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import sys
from pathlib import Path
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
    from hermes_tenuo._config import _b64_to_bytes, _env_secret

    existing_key = _env_secret("TENUO_SIGNING_KEY")
    if existing_key:
        try:
            agent_key = SigningKey.from_bytes(_b64_to_bytes(existing_key))
        except Exception as exc:
            print(f"error: TENUO_SIGNING_KEY is set but could not be loaded: {exc}", file=sys.stderr)
            return 1
    else:
        agent_key = SigningKey.generate()

    builder = Warrant.mint_builder().holder(agent_key.public_key)
    for tool, constraints, _ in parsed:
        builder = builder.capability(tool, **constraints)

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
        for tool, _, display in parsed:
            if display:
                shown = ", ".join(f"{k}={v}" for k, v in display.items())
                print(f"#   {tool}  {shown}")
            else:
                print(f"#   {tool}  (any arguments)")
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

    if "local_home" in config_entry:
        from hermes_tenuo.local_guard import report_shared_local_config
        check(report_shared_local_config(), "shared local session setup ready",
              "run tenuo-cli doctor and attach a warrant, or tenuo-cli mode observe")
        note("Configuration checks do not prove the running Hermes process loaded the plugin.")
        return 0 if ok else 1

    # 4. Configured? Same resolution the plugin uses (kanban task first).
    from hermes_tenuo._config import (
        _b64_to_bytes,
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
                key = SigningKey.from_bytes(_b64_to_bytes(signing_raw))
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
            print("    Covered: all agent-loop tool calls, including delegate_task")
            print("    Current Hermes main also covers tools called from inside")
            print("    execute_code scripts; older releases may not route them here.")
            print("    Gap:")
            print("      - direct registry.dispatch(...) callers bypass enforcement")
            print("        (including plugin ctx.dispatch_tool())")
            print("    Fix pending: https://github.com/NousResearch/hermes-agent/pull/32719")
        print("  On current Hermes main, execute_code calls inside a script use")
        print("  the warrant in your config; set_session_warrant does not apply.")
        print()
        print("  Lifecycle hooks registered:")
        print("    on_session_start, on_session_end, subagent_start")
        print("    (subagent_start: pre-injects child warrants before first tool call)")
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
    from hermes_tenuo._config import _b64_to_bytes, get_trusted_roots, resolve_warrant_text
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
        warrant = Warrant.from_bytes(_b64_to_bytes(warrant_raw))
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

_LEGACY_KEYS = ("warrant", "child_warrant", "signing_key_file", "signing_key_env", "trusted_root",
                "trusted_root_file", "session_warrants_dir", "operation_requests_dir",
                "operation_approvals_dir", "revocations_dir")


def cmd_setup(args: argparse.Namespace) -> int:
    """Connect this Hermes profile to a tenuo-cli workspace and start in observe mode."""
    import shutil

    import yaml
    from tenuo.local_cli.workspace import Workspace

    from hermes_tenuo._home import config_path

    home = Path(args.home or os.environ.get("TENUO_HOME", "~/.tenuo")).expanduser().absolute()

    path = config_path()
    config = yaml.safe_load(path.read_text()) if path.exists() else {}
    if not isinstance(config, dict):
        print(f"✗  {path} is not a YAML mapping; fix it before running setup", file=sys.stderr)
        return 2
    plugins = config.setdefault("plugins", {}) or {}
    config["plugins"] = plugins
    entries = plugins.setdefault("entries", {}) or {}
    plugins["entries"] = entries
    entry = entries.get("hermes-tenuo") or {}
    legacy = sorted(key for key in _LEGACY_KEYS if key in entry)
    if legacy or entry.get("on_denial", "block") != "block":
        print(f"✗  {path} configures hermes-tenuo with {', '.join(legacy) or 'on_denial: log'}; "
              "remove those settings to use a tenuo-cli workspace", file=sys.stderr)
        return 2
    workspace = Workspace(home)
    created = not (home / "config.yaml").exists()
    if created:
        workspace.initialize(dev=True)
    mode = "enforce" if args.enforce else "observe"
    workspace.set_mode(mode)

    enabled = plugins.get("enabled") or []
    if "hermes-tenuo" not in enabled:
        plugins["enabled"] = [*enabled, "hermes-tenuo"]
    entry["local_home"] = str(home)
    entries["hermes-tenuo"] = entry
    if path.exists():
        backup = path.with_name(path.name + ".before-hermes-tenuo")
        if not backup.exists():
            shutil.copy2(path, backup)
            print(f"  saved the previous config to {backup}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(config, sort_keys=False))

    import shlex

    default = Path(os.environ.get("TENUO_HOME", "~/.tenuo")).expanduser().absolute()
    tenuo_cli = "tenuo-cli" if home == default else f"tenuo-cli --home {shlex.quote(str(home))}"
    hermes_session = ("tenuo-cli hermes session" if home == default
                      else f"tenuo-cli hermes session --home {shlex.quote(str(home))}")
    print(f"✓  {'created' if created else 'using'} the Tenuo workspace at {home}"
          + (" with development identities" if created else ""))
    print(f"✓  hermes-tenuo enabled in {path}, reading that workspace")
    recipes = _install_recipes(home)
    print(f"✓  recipes in {recipes}: {', '.join(sorted(p.stem for p in recipes.glob('*.yaml')))}")
    print(f"✓  mode: {mode}")
    print()
    example = shlex.quote(str(recipes / "project-task.yaml"))
    if mode == "observe":
        print("Nothing is blocked yet. Run Hermes as usual: chats, cron jobs, subagents.")
        print("Every tool call is recorded with its arguments. Then:")
        print(f"  1. {tenuo_cli} calls summary")
        print("     what each person, job and session called, and the attach command for each")
        print("  2. attach a recipe (or your own template) to who it's for, in one step, e.g.")
        print(f"     {hermes_session} attach --session telegram:YOUR_ID --template {example} --set project=$PWD")
        print("     --session takes cron_JOB_ID for every run of a job, <platform>:<user id> for a person,")
        print("     or a session ID; a recipe's first lines say which values it needs")
        print(f"  3. {tenuo_cli} mode enforce")
        print("     the next call is checked; no gateway restart")
    else:
        print("Calls are enforced. Attach a warrant to who it's for:")
        print(f"  {hermes_session} attach --session telegram:YOUR_ID --template {example} --set project=$PWD")
    return 0


def _install_recipes(home):
    """Copy the bundled recipes into the workspace; never overwrite one already there."""
    from importlib.resources import files

    target = Path(home) / "recipes" / "hermes"
    target.mkdir(parents=True, exist_ok=True)
    for folder in files("hermes_tenuo").joinpath("recipes").iterdir():
        if not folder.is_dir():
            continue
        for item in folder.iterdir():
            if item.name.endswith(".yaml"):
                name = folder.name if item.name == "warrant.yaml" else f"{folder.name}-{item.name[:-5]}"
                destination = target / f"{name}.yaml"
                if not destination.exists():
                    destination.write_text(item.read_text())
    return target


def _issue_template(workspace, path, values, holder):
    """Issue a template (a recipe, say) to the holder key and store it, for attach --template."""
    from tenuo.local_cli.warrants import issue, save
    from tenuo.warrant_template import WarrantTemplate

    try:
        from tenuo.warrant_template import parse_set
    except ImportError:  # an SDK without template vars
        if values:
            raise ValueError("--set needs a Tenuo SDK with template vars (tenuo-ai/tenuo#986)")
        parse_set = None
    template = WarrantTemplate.load(path, parse_set(values)) if parse_set else WarrantTemplate.load(path)
    chain = issue(workspace, template, workspace.public_key(holder))
    save(workspace, chain)
    return chain


def cmd_session(args: argparse.Namespace) -> int:
    """Route warrants to Hermes sessions: the attachments local_home mode reads."""
    import yaml
    from tenuo.local import attach, detach, list_sessions, load_warrant_chain, read_session
    from tenuo.local_cli.workspace import Workspace

    workspace = Workspace(args.home)
    try:
        workspace.config
        if args.action == "list":
            result = {"sessions": list_sessions(workspace)}
        elif args.action == "attach":
            if args.template:
                chain = _issue_template(workspace, args.template, args.set, args.holder)
            elif args.set:
                raise ValueError("--set goes with --template")
            else:
                chain = load_warrant_chain(args.file)
            result = {"session": attach(workspace, args.session, chain, holder=args.holder)}
            if args.template:
                result["issued"] = str(chain[-1].id)
        elif args.action == "detach":
            result = {"session": detach(workspace, args.session, args.id)}
        else:
            result = {"session": read_session(workspace, args.session)}
    except FileNotFoundError:
        print(f"✗  no attachments for session {args.session!r}" if args.action != "list"
              else "✗  workspace not found; run tenuo-cli hermes setup", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"✗  {exc}", file=sys.stderr)
        return 1
    if args.json or os.environ.get("TENUO_JSON") == "1":  # tenuo-cli --json hermes session …
        print(json.dumps(result, default=str))
    else:
        print(yaml.safe_dump(result, sort_keys=False).rstrip())
    return 0


def build_parser(prog: str = "tenuo-cli hermes") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
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

    session_p = subparsers.add_parser(
        "session", help="Attach warrants to Hermes sessions (a chat, or cron_<job_id> for every run of a job)")
    session_p.add_argument("--home", metavar="DIR", help="Tenuo workspace (default: TENUO_HOME or ~/.tenuo)")
    session_p.add_argument("--json", action="store_true", help="Print one JSON object")
    session_actions = session_p.add_subparsers(dest="action", required=True)
    session_actions.add_parser("list")
    for action in ("show", "attach", "detach"):
        sub = session_actions.add_parser(action)
        sub.add_argument("--session", required=True, help="Hermes session ID, or cron_<job_id>")
        if action == "attach":
            source = sub.add_mutually_exclusive_group(required=True)
            source.add_argument("--file", help="the warrant file from tenuo-cli warrant issue")
            source.add_argument("--template", help="a YAML template (a recipe) to issue and attach in one step")
            sub.add_argument("--set", action="append", metavar="NAME=VALUE", help="a value for one of the template's vars")
            sub.add_argument("--holder", default="agent", help="the agent key the warrant is issued to")
        if action == "detach":
            sub.add_argument("--id", required=True, help="the warrant ID to detach")

    setup_p = subparsers.add_parser(
        "setup", help="Connect this Hermes profile to a tenuo-cli workspace and start in observe mode")
    setup_p.add_argument("--home", metavar="DIR", help="Tenuo workspace (default: TENUO_HOME or ~/.tenuo)")
    setup_p.add_argument("--enforce", action="store_true", help="Start in enforce mode instead of observe")

    return parser


def run(argv: list[str] | None = None, prog: str = "tenuo-cli hermes") -> int:
    parser = build_parser(prog)
    args = parser.parse_args(argv)
    commands = {"mint": cmd_mint, "status": cmd_status, "verify": cmd_verify, "doctor": cmd_doctor,
                "audit": cmd_audit, "session": cmd_session, "setup": cmd_setup}
    if args.command in commands:
        return commands[args.command](args)
    if args.command == "demo":
        from hermes_tenuo.demo import main as cmd_demo
        return cmd_demo() or 0
    parser.print_help()
    return 0


def tenuo_cli(argv: list[str]) -> int:
    """`tenuo-cli hermes …`, registered as a tenuo.cli entry point."""
    return run(argv)


def main() -> None:
    """The standalone `hermes-tenuo` command, same subcommands."""
    sys.exit(run(prog="hermes-tenuo"))


if __name__ == "__main__":
    main()
