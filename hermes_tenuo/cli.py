"""
hermes-tenuo CLI — warrant minting and management.

Usage:
    hermes-tenuo mint --ttl 1h --allow web_search --allow read_file
    hermes-tenuo mint --trigger trg-xyz --connect-token tc_...
    hermes-tenuo status
    hermes-tenuo verify

Local mint allows tools with open argument scope (Wildcard).
For argument-level constraints (path restrictions, query allowlists, etc.),
use the Cloud warrant builder — that is the authoritative source for
constraint semantics and keeps constraint logic out of this CLI.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from typing import Any, Optional

# Hermes #93824 (Aug 2026) bounds pre_tool_call at plugins.hook_callback_timeout
# (default 30s) and fails closed. Cloud approval polls for up to 5 minutes.
_DEFAULT_HOOK_CALLBACK_TIMEOUT = 30.0
_CLOUD_APPROVAL_POLL_SECS = 300.0


def _cloud_hook_timeout_note(
    connect_token: Optional[str],
    hook_callback_timeout: Any,
) -> Optional[str]:
    """Return a doctor note if Cloud approval can be cut off by the hook timeout.

    ``hook_callback_timeout`` is the raw ``plugins.hook_callback_timeout`` value
    (None = unset / Hermes default of 30s; 0 = timeout disabled).
    """
    if not connect_token:
        return None
    if hook_callback_timeout is None:
        timeout = _DEFAULT_HOOK_CALLBACK_TIMEOUT
    else:
        try:
            timeout = float(hook_callback_timeout)
        except (TypeError, ValueError):
            timeout = _DEFAULT_HOOK_CALLBACK_TIMEOUT
    if timeout == 0 or timeout >= _CLOUD_APPROVAL_POLL_SECS:
        return None
    return (
        f"plugins.hook_callback_timeout is {timeout:g}s but Cloud approval polls "
        f"for up to {_CLOUD_APPROVAL_POLL_SECS:g}s — a slow approval will fail "
        f"closed (Hermes #93824). Set plugins.hook_callback_timeout to "
        f"{_CLOUD_APPROVAL_POLL_SECS:g} or 0 (disable)."
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_mint(args: argparse.Namespace) -> int:
    """Mint a warrant and print config to stdout."""
    # Cloud-backed minting via trigger
    if getattr(args, "trigger", None):
        return _mint_from_trigger(args)
    return _mint_local(args)


def _mint_from_trigger(args: argparse.Namespace) -> int:
    """Mint via Tenuo Cloud trigger: POST /v1/triggers/{id}/fire."""
    token = getattr(args, "connect_token", None) or os.environ.get("TENUO_CONNECT_TOKEN")
    if not token:
        print(
            "error: --trigger requires a connect token. "
            "Set TENUO_CONNECT_TOKEN or pass --connect-token.",
            file=sys.stderr,
        )
        return 1

    from hermes_tenuo._cloud import parse_connect_token, fire_trigger, CloudAPIError
    creds = parse_connect_token(token)
    if not creds or not creds.api_key:
        print("error: could not parse connect token", file=sys.stderr)
        return 1

    print(f"Firing trigger {args.trigger}...", file=sys.stderr)
    try:
        result = fire_trigger(
            args.trigger,
            api_key=creds.api_key,
            endpoint=creds.endpoint,
        )
    except CloudAPIError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    _print_cloud_mint_output(result, args.output)
    return 0


def _print_cloud_mint_output(result: Any, output_format: str) -> None:
    """Print the Cloud-minted warrant config."""
    from hermes_tenuo._cloud import FireTriggerResult
    if output_format == "env":
        print(f"export TENUO_WARRANT={result.warrant_b64}")
        if result.trusted_root_b64:
            print(f"export TENUO_TRUSTED_ROOT={result.trusted_root_b64}")
    elif output_format == "yaml":
        print(f"warrant: {result.warrant_b64}")
        if result.trusted_root_b64:
            print(f"trusted_root: {result.trusted_root_b64}")
    else:
        print("# ── Hermes config (add to ~/.hermes/config.yaml) ────────────────")
        print("plugins:")
        print("  enabled:")
        print("    - hermes-tenuo")
        print("  entries:")
        print("    hermes-tenuo:")
        print(f"      warrant: {result.warrant_b64}")
        if result.trusted_root_b64:
            print(f"      trusted_root: {result.trusted_root_b64}")
        print(f"      signing_key_env: TENUO_SIGNING_KEY")
        print()
        if result.warrant_id:
            print(f"# ── Warrant ID: {result.warrant_id}")
        if result.expires_at:
            print(f"# ── Expires:    {result.expires_at}")
        print()
        print("# ── Note: set TENUO_SIGNING_KEY to your agent's Ed25519 signing key")
        print("# ── (the key registered with Cloud, matching the warrant holder)")


def _mint_local(args: argparse.Namespace) -> int:
    """Mint a warrant locally (no Cloud required).

    Each --allow tool is permitted with Wildcard() on all arguments.
    For argument-level constraints (path restrictions, query allowlists, etc.)
    use the Cloud warrant builder — that is the authoritative source for
    constraint semantics. Local mint is for dev/bootstrap use only.
    """
    try:
        from tenuo import SigningKey, Warrant, Wildcard  # noqa: F401
    except ImportError:
        print("error: tenuo is required. Install with: pip install tenuo", file=sys.stderr)
        return 1

    from tenuo import SigningKey, Warrant, Wildcard

    # Generate keys
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Build warrant — each tool is allowed with Wildcard on all arguments
    builder = Warrant.mint_builder().holder(agent_key.public_key)

    if not args.allow:
        print(
            "error: at least one --allow TOOL is required. "
            "For argument-level constraints use Cloud's warrant builder.",
            file=sys.stderr,
        )
        return 1

    for tool in (args.allow or []):
        builder = builder.capability(tool.strip(), **{})

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
        caps = args.allow or []
        if caps:
            print(f"# Tools: {', '.join(t.strip() for t in caps)}")
        print()
        print("# Note: argument-level constraints require Cloud's warrant builder.")
        print("# Local mint permits each tool with open argument scope (Wildcard).")

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show current plugin configuration status."""
    checks = [
        ("TENUO_WARRANT",      "Warrant"),
        ("TENUO_SIGNING_KEY",  "Signing key"),
        ("TENUO_TRUSTED_ROOT", "Trusted root"),
        ("TENUO_CONNECT_TOKEN","Cloud token (optional)"),
    ]
    all_required = True
    for env, label in checks:
        val = os.environ.get(env)
        required = "optional" not in label.lower()
        if val:
            print(f"  ✓  {label:30} set")
        else:
            marker = "✗" if required else "—"
            print(f"  {marker}  {label:30} not set")
            if required:
                all_required = False

    if all_required:
        print("\n  Ready for enforcement.")
    else:
        print("\n  Missing required config — enforcement will pass through.")
    return 0


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
            "reinstall: pip install --force-reinstall hermes-tenuo",
        )
    except Exception as exc:
        note(f"could not check entry points ({exc})")

    # 3. Hermes config — is the plugin enabled?
    config_entry: dict = {}
    hook_callback_timeout: Any = None
    try:
        from hermes_cli.config import load_config
        config = load_config() or {}
        plugins_cfg = config.get("plugins") or {}
        enabled = plugins_cfg.get("enabled") or []
        hook_callback_timeout = plugins_cfg.get("hook_callback_timeout")
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
    except ImportError:
        note("hermes_cli not importable here — skipping config.yaml checks")

    # 4. Warrant loadable
    from hermes_tenuo._config import load_warrant

    raw = (
        config_entry.get("warrant")
        or os.environ.get("TENUO_WARRANT")
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
    check(
        warrant is not None,
        "warrant loaded",
        "set TENUO_WARRANT or plugins.entries.hermes-tenuo.warrant",
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
        signing_raw = os.environ.get(
            config_entry.get("signing_key_env", "TENUO_SIGNING_KEY"),
            os.environ.get("TENUO_SIGNING_KEY"),
        )
        if signing_raw:
            try:
                from tenuo_core import SigningKey
                key = SigningKey.from_bytes(base64.b64decode(signing_raw))
                holder = getattr(warrant, "holder", None)
                if holder is not None and key.public_key.to_bytes() == holder.to_bytes():
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

    # 7. Trusted root
    trusted = config_entry.get("trusted_root") or os.environ.get("TENUO_TRUSTED_ROOT")
    check(
        bool(trusted),
        "trusted_root set",
        "set TENUO_TRUSTED_ROOT or plugins.entries.hermes-tenuo.trusted_root",
    )

    # 7b. Cloud approval vs Hermes hook timeout (Hermes #93824, Aug 2026)
    connect_token = config_entry.get("connect_token") or os.environ.get("TENUO_CONNECT_TOKEN")
    timeout_note = _cloud_hook_timeout_note(connect_token, hook_callback_timeout)
    if timeout_note:
        note(timeout_note)

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


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify the current warrant is valid and show its capabilities."""
    warrant_raw = os.environ.get("TENUO_WARRANT")
    if not warrant_raw:
        # Try reading from file
        default_path = os.path.expanduser("~/.hermes/tenuo/warrant")
        if os.path.exists(default_path):
            with open(default_path) as f:
                warrant_raw = f.read().strip()
        else:
            print("error: TENUO_WARRANT not set and ~/.hermes/tenuo/warrant not found", file=sys.stderr)
            return 1

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
    mint_p.add_argument("--allow", action="append", metavar="TOOL",
                        help="Allow a tool by name (repeat for multiple). "
                             "Examples: --allow web_search --allow read_file. "
                             "For argument-level constraints use Cloud's warrant builder.")
    mint_p.add_argument("--output", choices=["full", "yaml", "env"], default="full",
                        help="Output format: full config (default), yaml keys only, or env exports")
    mint_p.add_argument("--trigger", metavar="TRIGGER_ID",
                        help="Fire a Tenuo Cloud trigger to get a Cloud-issued warrant "
                             "(requires TENUO_CONNECT_TOKEN or --connect-token)")
    mint_p.add_argument("--connect-token", metavar="TOKEN",
                        help="Tenuo Cloud connect token (overrides TENUO_CONNECT_TOKEN)")

    # status
    subparsers.add_parser("status", help="Show current configuration status")

    # verify
    subparsers.add_parser("verify", help="Verify and inspect the current warrant")

    # doctor
    subparsers.add_parser("doctor", help="End-to-end install check: plugin discovery, warrant, enforcement path")

    args = parser.parse_args()

    if args.command == "mint":
        sys.exit(cmd_mint(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "doctor":
        sys.exit(cmd_doctor(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
