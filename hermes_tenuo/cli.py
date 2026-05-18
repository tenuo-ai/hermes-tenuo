"""
hermes-tenuo CLI — warrant minting and management.

Usage:
    hermes-tenuo mint --ttl 1h --allow web_search --allow "read_file:path=/data"
    hermes-tenuo status
    hermes-tenuo verify
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# Capability parser
# ---------------------------------------------------------------------------

def _parse_capability(cap: str) -> tuple[str, dict]:
    """Parse 'tool_name' or 'tool_name:arg=value,arg2=value2' into (name, constraints)."""
    if ":" not in cap:
        return cap.strip(), {}
    tool, rest = cap.split(":", 1)
    constraints = {}
    for pair in rest.split(","):
        pair = pair.strip()
        if "=" not in pair:
            print(f"Warning: ignoring malformed constraint '{pair}' (expected arg=value)", file=sys.stderr)
            continue
        k, v = pair.split("=", 1)
        constraints[k.strip()] = v.strip()
    return tool.strip(), constraints


def _build_constraint(tool: str, arg: str, pattern: str):
    """Convert a config string pattern into a Tenuo constraint object."""
    from tenuo import Subpath, UrlSafe, Wildcard, Pattern, Exact

    if pattern == "*" or pattern == "":
        return Wildcard()
    if pattern.startswith("/"):
        return Subpath(pattern)
    if pattern.startswith("http://") or pattern.startswith("https://"):
        return UrlSafe(allow_schemes=["https", "http"])
    return Pattern(f"*{pattern}*") if "*" not in pattern else Pattern(pattern)


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
    """Mint a warrant locally (no Cloud required)."""
    try:
        from tenuo import SigningKey, Warrant, Wildcard  # noqa: F401
    except ImportError:
        print("error: tenuo is required. Install with: pip install tenuo", file=sys.stderr)
        return 1

    from tenuo import SigningKey, Warrant

    # Generate keys
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Build warrant
    builder = Warrant.mint_builder().holder(agent_key.public_key)

    if not args.allow:
        print("Warning: no --allow flags given; warrant allows all tools with Wildcard constraints.", file=sys.stderr)

    for cap in (args.allow or []):
        tool, constraints = _parse_capability(cap)
        if constraints:
            built = {k: _build_constraint(tool, k, v) for k, v in constraints.items()}
            builder = builder.capability(tool, **built)
        else:
            # No constraints declared — don't add any (bare tool allowlist)
            builder = builder.capability(tool)

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
            print(f"# Tools: {', '.join(c.split(':')[0] for c in caps)}")
        else:
            print("# Tools: (all — no restrictions)")

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
    mint_p.add_argument("--allow", action="append", metavar="TOOL[:ARG=VALUE]",
                        help="Allow a tool (repeat for multiple). "
                             "Examples: --allow web_search  "
                             "--allow 'read_file:path=/data'")
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

    args = parser.parse_args()

    if args.command == "mint":
        sys.exit(cmd_mint(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
