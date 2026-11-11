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
    --allow 'write_file:path=/tmp/out,content=*'  path under /tmp/out, any content
    --allow 'web_search:query=acme*'        glob pattern
    --allow 'git:action=status|diff|log'    one of several values
    --allow checkout:amount=0..4000         number from 0 to 4000, inclusive

Value rules: ``*`` allows anything; ``a|b`` is a choice; ``MIN..MAX`` is a
numeric range (both ends required, inclusive); a value containing ``*`` or
``?`` is a glob; a value starting with ``/`` or ``~`` is a path prefix
(Subpath, traversal-safe); anything else must match exactly.

Once a tool has any constraint, a call may only send the arguments named
here: an unnamed argument is denied, and ``arg=*`` requires the argument.
Quote a spec that contains ``*``, ``?`` or ``|`` so the shell passes it through.

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
from typing import Any

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_mint(args: argparse.Namespace) -> int:
    """Mint a warrant and print config to stdout."""
    if any(getattr(args, field, None) for field in ("issuer_key", "holder_public_key", "out", "session_id")):
        return _mint_separate(args)
    return _mint_local(args)


def cmd_keygen(args: argparse.Namespace) -> int:
    """Create an identity without printing private signing material."""
    from pathlib import Path
    from tenuo import SigningKey
    from hermes_tenuo.issuance import write_private_file
    private_path, public_path = Path(args.private_key).expanduser(), Path(args.public_key).expanduser()
    try:
        if private_path.resolve() == public_path.resolve():
            raise ValueError("private and public paths must differ")
        if private_path.exists() or public_path.exists():
            raise ValueError("identity output already exists; choose new paths")
        key = SigningKey.generate()
        write_private_file(private_path, base64.b64encode(key.secret_key_bytes()).decode())
        try:
            write_private_file(public_path, base64.b64encode(key.public_key.to_bytes()).decode())
        except (OSError, ValueError):
            # Do not strand a private identity without its corresponding public
            # key. Both paths were verified absent above and writes never
            # overwrite, so this removes only the private file created here.
            try:
                private_path.unlink()
            except OSError:
                pass
            raise
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Private key saved: {private_path}")
    print(f"Public key saved: {public_path}")
    return 0


def _check_task_id(task_id: str) -> str:
    """A task id names one file in the warrants folder; refuse anything that is a path."""
    if (
        not task_id.strip()
        or task_id in (".", "..")
        or any(c in task_id for c in ("/", "\\", "\0"))
        or os.sep in task_id
    ):
        raise ValueError(f"--task '{task_id}': expected a task id, not a path")
    return task_id


def _mint_separate(args: argparse.Namespace) -> int:
    from hermes_tenuo.issuance import mint_for_holder, read_public_key, read_signing_key, write_private_file
    task_id = getattr(args, "task", None)
    out = getattr(args, "out", None)
    if not all(getattr(args, field, None) for field in ("issuer_key", "holder_public_key")) or not (out or task_id):
        print(
            "error: separate issuance requires --issuer-key, --holder-public-key and --out (or --task)",
            file=sys.stderr,
        )
        return 1
    if task_id and out:
        print("error: --task writes the task warrant path; do not pass --out as well", file=sys.stderr)
        return 1
    try:
        capabilities = {}
        for spec in args.allow or []:
            tool, constraints, _ = parse_allow(spec)
            if tool in capabilities:
                raise ValueError(f"duplicate tool: {tool}")
            capabilities[tool] = constraints
        issuer = read_signing_key(args.issuer_key)
        holder = read_public_key(args.holder_public_key)
        if task_id:
            from hermes_tenuo.kanban import task_warrant_path
            out = task_warrant_path(_check_task_id(task_id))
        warrant = mint_for_holder(issuer, holder, capabilities, _parse_ttl(args.ttl),
                                  getattr(args, "session_id", None))
        if task_id:
            # A task warrant is replaced when the task is re-issued.
            out.parent.mkdir(parents=True, exist_ok=True)
            write_private_file(out, warrant.to_base64(), overwrite=True)
        else:
            write_private_file(out, warrant.to_base64())
    except Exception as exc:
        print(f"error: issuance failed: {exc}", file=sys.stderr)
        return 1
    print(f"Warrant saved: {out}")
    print(f"Issuer public key: {base64.b64encode(issuer.public_key.to_bytes()).decode()}")
    return 0


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
    if getattr(args, "task", None):
        try:
            _check_task_id(args.task)
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
        from hermes_tenuo._config import get_trusted_roots
        from hermes_tenuo.issuance import write_private_file
        from hermes_tenuo.kanban import task_warrant_path

        path = task_warrant_path(task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_private_file(path, warrant_b64, overwrite=True)
        print(f"# Wrote task warrant: {path}")
        print("# It is signed by the new issuer above, so the worker accepts it only when")
        print("# its trusted_root is that value. To sign every task with one issuer, use")
        print("#   hermes-tenuo mint --task ID --issuer-key ISSUER.key --holder-public-key HOLDER.pub ...")
        if get_trusted_roots(None):
            from hermes_tenuo._config import get_on_denial
            print(
                "warning: the trusted_root configured here did not sign this task warrant; "
                f"for the worker, {_trust_failure_effect(get_on_denial(None))}",
                file=sys.stderr,
            )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show what the plugin will load, and where each value comes from."""
    from hermes_tenuo._config import _env_secret, _get_plugin_entry, _looks_like_path, get_require_warrant
    from hermes_tenuo._home import config_path, hermes_cli_available
    from hermes_tenuo.kanban import current_task_id, load_task_warrant_raw, task_warrant_path

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
    # A kanban worker loads its task warrant and never the install-wide one.
    task_id = current_task_id()
    task_staged = bool(task_id and load_task_warrant_raw(task_id))
    warrant_set = task_staged if task_id else bool(rows[0][1] or rows[0][2])
    missing = []
    for label, cfg_val, env_val, cfg_key, env_name in rows:
        if label == "Warrant" and task_id:
            if task_staged:
                print(f"  ✓  {label:14} set  (kanban task {task_id}, file)")
            else:
                print(f"  ✗  {label:14} not staged  (kanban task {task_id}: {task_warrant_path(task_id)})")
                missing.append(label)
        elif cfg_val:
            # Never echo the value: a warrant or root is credential material. Say only
            # whether the config points at a file or carries the value inline.
            kind = "file" if isinstance(cfg_val, str) and _looks_like_path(cfg_val) else "inline"
            print(f"  ✓  {label:14} set  (config: {cfg_key}, {kind})")
        elif env_val:
            print(f"  ✓  {label:14} set  (env: {env_name})")
        else:
            hint = f"{cfg_key} or ${env_name}" if cfg_key else f"${env_name}"
            print(f"  ✗  {label:14} not set  ({hint})")
            missing.append(label)

    if not missing:
        print("\n  Ready for enforcement. Run `hermes-tenuo doctor` to check the values.")
    elif task_id and not task_staged:
        print(f"\n  No warrant is staged for kanban task {task_id} — every tool call is blocked.")
    elif warrant_set and "Signing key" in missing:
        print("\n  A warrant is set but the signing key is not — every tool call is blocked until it is.")
    elif warrant_set:
        print(f"\n  A warrant is set but trusted_root is not — {_trust_failure_effect(entry.get('on_denial'))}.")
    elif get_require_warrant(None):
        print("\n  No warrant, and require_warrant is on — every tool call is blocked.")
    else:
        print("\n  No warrant — the plugin loads and enforces nothing.")
    return 0


def _warrant_holder(warrant: Any):
    """The holder public key of a warrant across tenuo builds (``holder_key`` since 0.3)."""
    for attr in ("holder_key", "authorized_holder", "holder"):
        value = getattr(warrant, attr, None)
        if value is not None and hasattr(value, "to_bytes"):
            return value
    return None


def _trust_failure_effect(on_denial: Any) -> str:
    """What a trusted_root problem does at runtime, which depends on on_denial."""
    if on_denial == "log":
        return (
            "every tool call fails the warrant check; with on_denial: log it is recorded "
            "and still runs (delegate_task spawns are blocked)"
        )
    return "every tool call is blocked until this is fixed"


def _signed_by(warrant: Any, roots: list) -> bool:
    """Whether one of *roots* issued *warrant* (the check the plugin makes on every call)."""
    for root in roots:
        try:
            if warrant.verify(root.to_bytes()):
                return True
        except Exception:
            continue
    return False


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
        _b64_to_bytes,
        _env_secret,
        get_child_warrant_raw,
        get_delegation_plan_path,
        get_trusted_roots,
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

        # 7. Trusted root: set, a public key, and the issuer of this warrant.
        # Unlike an unusable warrant, a trust failure is a denial on each
        # call, so on_denial decides whether those calls still run.
        trust_effect = _trust_failure_effect(config_entry.get("on_denial", "block"))
        trusted = config_entry.get("trusted_root") or _env_secret("TENUO_TRUSTED_ROOT")
        if not trusted:
            check(
                False,
                "trusted_root set",
                f"set TENUO_TRUSTED_ROOT or plugins.entries.hermes-tenuo.trusted_root — {trust_effect}",
            )
        else:
            roots = get_trusted_roots(None)
            if not roots:
                check(False, "trusted_root is not a base64 public key", trust_effect)
            else:
                check(True, "trusted_root set")
                signed = _signed_by(warrant, roots)
                check(
                    signed,
                    "warrant is signed by trusted_root" if signed else "warrant is not signed by trusted_root",
                    f"set trusted_root to the public key of the issuer that minted this warrant — {trust_effect}",
                )

        # 8. Delegation plan, when configured
        plan_path = get_delegation_plan_path(None)
        if plan_path:
            from hermes_tenuo.delegation import DelegationPlanError, load_plan
            try:
                load_plan(plan_path)
            except DelegationPlanError as exc:
                check(False, f"delegation plan: {exc}", blocks)
            else:
                try:
                    has_child = get_child_warrant_raw(None) is not None
                except OSError:
                    has_child = True
                if has_child:
                    check(False, "child_warrant and delegation_plan are both set", f"remove one — {blocks}")
                else:
                    check(True, "delegation plan loads")

    # 9. on_denial
    on_denial = config_entry.get("on_denial", "block")
    if on_denial == "log":
        note("on_denial: log — denied calls are recorded, not blocked (delegate_task spawns still are)")
    elif on_denial != "block":
        check(False, f"on_denial is {on_denial!r}; expected block or log", "it is treated as block")
    # 10. Enforcement path
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
        if _signed_by(warrant, roots):
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

def cmd_hands(args: argparse.Namespace) -> int:
    import signal

    from hermes_tenuo.hands import device
    from hermes_tenuo.hands.sandbox import SandboxUnavailable
    if args.hands_command == "demo":
        from hermes_tenuo.hands.onboarding import create_demo
        print(create_demo())
        return 0
    if args.hands_command == "log":
        path = device.home() / "log.jsonl"
        lines = path.read_text().splitlines()[-args.last:] if path.is_file() else []
        for line in lines:
            entry = json.loads(line)
            what = entry["note"] or f"exit {entry['exit']}"
            print(f"{entry['at']}  {device.printable(str(what)):<12}  {device.printable(str(entry['command']))}")
        if not lines:
            print("Nothing has run on this machine yet.")
        return 0
    if args.hands_command == "check":
        ok = True
        for passed, text in device.check(args.invite, args.dir, read_only=args.read_only,
                                         plain_http=args.plain_http, network=args.network):
            ok = ok and passed is not False
            print(f"  {'—' if passed is None else '✓' if passed else '✗'}  {text}")
        print("\n  Ready: run `hermes-tenuo hands up` with the same arguments." if ok else
              "\n  Fix the lines marked ✗, then run this again.")
        return 0 if ok else 1
    if args.hands_command != "up":
        print("usage: hermes-tenuo hands up [INVITE] --dir FOLDER --for 4h | hermes-tenuo hands check [INVITE] "
              "--dir FOLDER | hermes-tenuo hands log")
        return 2
    try:
        duration = _parse_ttl(args.ttl)
        if duration <= 0:
            raise ValueError("the time window must be positive")
        print("Checking this machine before pairing…")
        checks = device.check(args.invite, args.dir, read_only=args.read_only,
                              plain_http=args.plain_http, network=args.network,
                              allow_unsandboxed=args.no_sandbox)
        for passed, text in checks:
            print(f"  {'—' if passed is None else '✓' if passed else '✗'}  {device.printable(text)}")
        if any(passed is False for passed, _ in checks):
            print("Nothing was paired. Fix the lines marked ✗, then run the same command again.")
            return 1
        dev = device.Device(args.invite, args.dir, duration, name=args.name,
                            allow_unsandboxed=args.no_sandbox, read_only=args.read_only,
                            plain_http=args.plain_http, read_home=args.read_home, read=args.read or (),
                            network=args.network)
        signal.signal(signal.SIGINT, dev.stop)
        signal.signal(signal.SIGTERM, dev.stop)
        return dev.serve()
    except (device.HandsError, SandboxUnavailable, ConnectionError, ValueError) as exc:
        print(f"hermes-tenuo hands: {exc}", file=sys.stderr)
        return 1


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
    except (TypeError, ValueError, OverflowError) as exc:
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

    keygen_p = subparsers.add_parser("keygen", help="Create private/public identity files")
    keygen_p.add_argument("--private-key", required=True, metavar="PATH")
    keygen_p.add_argument("--public-key", required=True, metavar="PATH")

    # mint
    mint_p = subparsers.add_parser("mint", help="Mint a warrant and print config")
    mint_p.add_argument("--ttl", default="24h", metavar="DURATION",
                        help="Warrant TTL, e.g. 30m, 1h, 7d (default: 24h)")
    mint_p.add_argument("--allow", action="append", metavar="TOOL[:ARG=VALUE,...]",
                        help="Allow a tool, optionally constraining its arguments (repeatable). "
                             "Examples: --allow web_search  --allow read_file:path=/data  "
                             "--allow 'git:action=status|diff'. Values: '*' any, 'a|b' choice, "
                             "glob with '*'/'?', '/path' prefix, otherwise exact match. "
                             "Once a tool has any constraint, a call may send only the arguments "
                             "named here: an unnamed argument is denied, and ARG=* requires the "
                             "argument to be present. Quote a spec containing '*', '?' or '|'.")
    mint_p.add_argument("--task", metavar="ID",
                        help="Write the warrant to $HERMES_HOME/tenuo/warrants/<ID>.warrant "
                             "(kanban worker path). With --issuer-key and --holder-public-key it is "
                             "signed by that issuer; otherwise by a new one, with TENUO_SIGNING_KEY "
                             "as the holder when set.")
    mint_p.add_argument("--output", choices=["full", "yaml", "env"], default="full",
                        help="Output format: full config (default), yaml keys only, or env exports")

    mint_p.add_argument("--issuer-key", metavar="PATH", help="Operator issuer private key file (base64)")
    mint_p.add_argument("--holder-public-key", metavar="PATH", help="Recipient public key file (base64)")
    mint_p.add_argument("--out", metavar="PATH", help="Write warrant to a new 0600 file")
    mint_p.add_argument("--session-id", metavar="ID", help="Bind separate issuance to a session")

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

    hands_p = subparsers.add_parser("hands", help="Let your Hermes server use a folder on this machine")
    hands_sub = hands_p.add_subparsers(dest="hands_command")
    hands_sub.add_parser("demo", help="Create a disposable practice project; pairs nothing")
    up_p = hands_sub.add_parser("up", help="Share one folder with the server for a set time")
    up_p.add_argument("invite", nargs="?", metavar="INVITE",
                      help="The hands://... line from `/hands invite` (only needed the first time)")
    up_p.add_argument("--dir", default=".", metavar="FOLDER", help="Folder the server may work in (default: here)")
    up_p.add_argument("--for", dest="ttl", default="4h", metavar="DURATION", help="How long, e.g. 30m, 4h (default: 4h)")
    up_p.add_argument("--name", metavar="NAME", help="What to call this machine (default: its hostname)")
    up_p.add_argument("--no-sandbox", action="store_true",
                      help="Run commands with your full access when this machine has no sandbox")
    up_p.add_argument("--read-only", action="store_true",
                      help="Let commands read the folder but not change it")
    up_p.add_argument("--plain-http", action="store_true",
                      help="Connect to a server on the internet without encryption (not recommended)")
    up_p.add_argument("--network", action="store_true",
                      help="Let commands use the internet, to install dependencies, clone or download (off by default)")
    up_p.add_argument("--read", action="append", metavar="FOLDER",
                      help="Also let commands read this folder in your home folder (repeatable)")
    up_p.add_argument("--read-home", action="store_true",
                      help="Let commands read your whole home folder, except keys, credentials and browser data")
    check_p = hands_sub.add_parser("check", help="See whether this machine is ready for `hands up`, without pairing")
    check_p.add_argument("invite", nargs="?", metavar="INVITE", help="The hands://... line, to test that its server is reachable")
    check_p.add_argument("--dir", default=".", metavar="FOLDER", help="Folder you plan to share (default: here)")
    check_p.add_argument("--read-only", action="store_true", help="Check for --read-only use")
    check_p.add_argument("--network", action="store_true", help="Check for --network use")
    check_p.add_argument("--plain-http", action="store_true", help="Check for --plain-http use")
    hands_sub.add_parser("log", help="Show what the server ran on this machine").add_argument(
        "--last", type=int, default=20, metavar="N")

    args = parser.parse_args()

    if args.command == "keygen":
        sys.exit(cmd_keygen(args))
    elif args.command == "mint":
        sys.exit(cmd_mint(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "doctor":
        sys.exit(cmd_doctor(args))
    elif args.command == "audit":
        sys.exit(cmd_audit(args))
    elif args.command == "hands":
        sys.exit(cmd_hands(args))
    elif args.command == "demo":
        from hermes_tenuo.demo import main as cmd_demo
        sys.exit(cmd_demo())
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
