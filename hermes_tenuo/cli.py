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

Value rules: ``*`` allows anything; ``a|b`` is a choice; a value containing
``*`` or ``?`` is a glob; a value starting with ``/`` or ``~`` is a path
prefix (Subpath, traversal-safe); anything else must match exactly.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_mint(args: argparse.Namespace) -> int:
    """Mint a warrant and print config to stdout."""
    return _mint_local(args)


def _parse_constraint_value(value: str) -> Any:
    """Map one ``arg=value`` string to a tenuo constraint (see module docstring)."""
    from tenuo import Exact, OneOf, Pattern, Subpath, Wildcard
    v = value.strip()
    if v == "*":
        return Wildcard()
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

    # Generate keys
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    builder = Warrant.mint_builder().holder(agent_key.public_key)
    for tool, constraints, _ in parsed:
        builder = builder.capability(tool, **constraints)

    # Parse TTL
    ttl_seconds = _parse_ttl(args.ttl)
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
        print(f"# Export before running hermes:")
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
        print(f"      signing_key_env: TENUO_SIGNING_KEY")
        print()
        print("# ── Signing key (export before running hermes) ───────────────────")
        print(f"export TENUO_SIGNING_KEY={signing_key_b64}")
        print()
        print(f"# ── Warrant details ─────────────────────────────────────────────")
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
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show what the plugin will load, and where each value comes from."""
    from hermes_tenuo._config import _env_secret, _get_plugin_entry
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
            kind = "file" if isinstance(cfg_val, str) and cfg_val.startswith(("/", "~", ".")) else "inline"
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
            'reinstall: pip install --force-reinstall "git+https://github.com/tenuo-ai/hermes-tenuo.git"',
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

    # 4. Configured? Enabled-but-empty is a silent no-op at runtime.
    from hermes_tenuo._config import _env_secret, load_warrant

    raw = (
        config_entry.get("warrant")
        or _env_secret("TENUO_WARRANT")
    )
    if raw and (raw.startswith("/") or raw.startswith("~") or raw.startswith(".")):
        path = os.path.expanduser(raw)
        if os.path.exists(path):
            with open(path) as fh:
                raw = fh.read().strip()
        else:
            check(False, f"warrant path does not exist: {path}")
            raw = None

    warrant = load_warrant(raw) if raw else None
    configured = warrant is not None
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
            print("    Covered: all agent-loop tool calls including delegate_task")
            print("    Gaps:")
            print("      - skip_pre_tool_call_hook=True callers bypass enforcement")
            print("      - direct registry.dispatch(...) callers bypass enforcement")
            print("      - execute_code sandbox dispatch path not intercepted")
            print("    Fix pending: https://github.com/NousResearch/hermes-agent/pull/32719")
        print()
        print("  Lifecycle hooks registered:")
        print("    on_session_start, on_session_end, subagent_start")
        print("    (subagent_start: pre-injects child warrants before first tool call)")
    except ImportError:
        note("tools.registry not importable here — run `hermes-tenuo doctor` from a Hermes-enabled venv")

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
    """Verify the current warrant is valid and show its capabilities."""
    from hermes_tenuo._config import _env_secret, _get_plugin_entry
    from hermes_tenuo._home import hermes_home

    warrant_raw = _env_secret("TENUO_WARRANT")
    source = "env: TENUO_WARRANT"
    if not warrant_raw:
        cfg_val = _get_plugin_entry(None).get("warrant")
        if cfg_val:
            warrant_raw, source = str(cfg_val), "config: warrant"
            if warrant_raw.startswith(("/", "~", ".")):
                path = os.path.expanduser(warrant_raw)
                source = f"config: warrant -> {path}"
                if not os.path.exists(path):
                    print(f"error: warrant path from config does not exist: {path}", file=sys.stderr)
                    return 1
                with open(path) as f:
                    warrant_raw = f.read().strip()
    if not warrant_raw:
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

    try:
        tools = warrant.tools
        if tools is None:
            print("Tools:       (all — no restrictions)")
        else:
            print(f"Tools:       {', '.join(tools) if tools else '(none)'}")
    except Exception:
        pass

    return 0


# ---------------------------------------------------------------------------
# TTL parser
# ---------------------------------------------------------------------------

def _parse_ttl(ttl: str) -> int:
    ttl = ttl.strip().lower()
    if ttl.endswith("s"):
        return int(float(ttl[:-1]))
    elif ttl.endswith("m"):
        return int(float(ttl[:-1]) * 60)
    elif ttl.endswith("h"):
        return int(float(ttl[:-1]) * 3600)
    elif ttl.endswith("d"):
        return int(float(ttl[:-1]) * 86400)
    else:
        return int(float(ttl))


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
    mint_p.add_argument("--output", choices=["full", "yaml", "env"], default="full",
                        help="Output format: full config (default), yaml keys only, or env exports")

    # status
    subparsers.add_parser("status", help="Show current configuration status")

    # verify
    subparsers.add_parser("verify", help="Verify and inspect the current warrant")

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
