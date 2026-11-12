"""Developer workflow for wrapping existing MCP servers and checking authority."""
from __future__ import annotations

import asyncio
import json
import shlex
import sys
import time
from pathlib import Path

from hermes_tenuo.audit import read_audit_log


def add_parser(subparsers):
    parser = subparsers.add_parser("mcp", help="Wrap existing MCP servers and verify delegated calls")
    commands = parser.add_subparsers(dest="mcp_command", required=True)
    wrap = commands.add_parser("wrap", help="Create a wrapper workspace from an existing JSON or YAML config")
    wrap.add_argument("source", type=Path, help="Config with mcpServers or mcp_servers")
    wrap.add_argument("workspace", type=Path, help="New directory for wrapper settings and audit")
    wrap.add_argument("--server", action="append", default=[], help="Server to wrap (repeatable; default: all enabled)")
    wrap.add_argument("--trust-root", type=Path, help="Existing issuer public key; omit to create a local check issuer")

    for command, help_text in (
        ("config", "Print the wrapper launch config for an MCP client"),
        ("tools", "Discover wrapped tool names and their argument schemas"),
        ("serve", "Run the protected MCP server over stdio"),
    ):
        sub = commands.add_parser(command, help=help_text)
        sub.add_argument("workspace", type=Path)

    check = commands.add_parser("check", help="Preview or test scoped calls using a real delegated warrant")
    check.add_argument("workspace", type=Path)
    check.add_argument("cases", type=Path, help="JSON array of tool, allow and deny arguments")
    check.add_argument("--run", action="store_true", help="Execute the displayed calls against the wrapped services")

    call = commands.add_parser("call", help="Send an MCP call with a warrant chain and holder proof")
    call.add_argument("workspace", type=Path)
    call.add_argument("tool", help="Qualified name from mcp tools")
    call.add_argument("--args", default="{}", help="JSON object with tool arguments")
    call.add_argument("--warrant", type=Path, action="append", required=True, help="Warrant file, repeat root to leaf")
    call.add_argument("--holder-key", type=Path, required=True, help="Leaf holder's private key file")

    audit = commands.add_parser("audit", help="View correlated decisions and outcomes across tools")
    audit.add_argument("workspaces", type=Path, nargs="+", help="Wrapper workspaces to read together")
    audit.add_argument("--warrant", help="Show this warrant and its descendants")
    audit.add_argument("--denied", action="store_true", help="Show only denied calls")
    audit.add_argument("--json", action="store_true", help="Emit JSON lines for other tools")


def _cases(path):
    cases = json.loads(path.expanduser().read_text())
    if not isinstance(cases, list) or not cases:
        raise ValueError("Cases must be a non-empty JSON array")
    tools = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"tool", "allow", "deny"}:
            raise ValueError("Each case needs tool, allow and deny fields")
        tool, allowed, denied = case["tool"], case["allow"], case["deny"]
        if not isinstance(tool, str) or not tool or tool in tools:
            raise ValueError("Each case needs a distinct, qualified tool name")
        if (not isinstance(allowed, dict) or not isinstance(denied, dict)
                or not allowed or allowed.keys() != denied.keys() or "_tenuo" in allowed
                or json.dumps(allowed, sort_keys=True) == json.dumps(denied, sort_keys=True)):
            raise ValueError(f"{tool}: use different allow and deny values for the same argument names")
        if any(value is None or isinstance(value, dict) for value in (*allowed.values(), *denied.values())):
            raise ValueError(f"{tool}: check supports scalars and arrays. Use mcp call for a custom object constraint.")
        json.dumps(case, allow_nan=False)
        tools.add(tool)
    return cases


def _audit(args):
    records = []
    for workspace in dict.fromkeys(path.expanduser().resolve() for path in args.workspaces):
        if not (workspace / "workspace.json").is_file():
            raise ValueError(f"No wrapper workspace at {workspace}")
        for record in read_audit_log(workspace / "audit.jsonl", denied_only=args.denied):
            if args.warrant and args.warrant not in [
                record.get("warrant_id"), *record.get("parent_warrant_ids", []),
            ]:
                continue
            records.append({**record, "workspace": str(workspace)})
    records.sort(key=lambda record: record["timestamp"])
    if args.json:
        for record in records:
            print(json.dumps(record))
    elif not records:
        print("No matching calls. Run mcp check or mcp call to see decisions here.")
    else:
        multiple = len(set(record["workspace"] for record in records)) > 1
        for record in records:
            reason = f" ({record['reason'].replace('_', ' ')})" if record.get("reason") else ""
            warrant = f" | warrant {record['warrant_id']}" if record.get("warrant_id") else ""
            source = f" | {record['workspace']}" if multiple else ""
            print(f"{record['timestamp']}  {record['decision']:5} {record['tool'] or 'unknown tool'}"
                  f" | {record['outcome']}{reason}{warrant}{source}")
    return 0


def _authorization(chain, holder, tool, arguments):
    from tenuo_core import sign_meta

    if "_tenuo" in arguments:
        raise ValueError("_tenuo is reserved for authority metadata")
    envelope = sign_meta(chain, holder, tool, json.dumps(arguments, allow_nan=False), int(time.time()))
    return {"tenuo": envelope}


async def _run_check(workspace, cases):
    from jsonschema.validators import validator_for
    from referencing import Registry
    from tenuo import CEL, Exact, SigningKey

    from hermes_tenuo.issuance import mint_for_holder, read_signing_key
    from hermes_tenuo.mcp_gateway import AUDIT_META
    from hermes_tenuo.mcp_workspace import connect_wrapper, list_tools

    issuer_path = workspace / "issuer.key"
    if not issuer_path.is_file():
        raise ValueError("This workspace uses an external issuer. Use mcp call with its warrant and holder key.")
    issuer = read_signing_key(issuer_path)
    delegator, holder = SigningKey.generate(), SigningKey.generate()
    async with connect_wrapper(workspace) as client:
        definitions = {tool.name: tool async for tool in list_tools(client)}
        capabilities = {}
        for case in cases:
            tool = case["tool"]
            if tool not in definitions:
                raise ValueError(f"{tool} is unavailable. Use mcp tools to list qualified names.")
            schema = definitions[tool].input_schema
            validator = validator_for(schema)(schema, registry=Registry())
            for field in ("allow", "deny"):
                if not validator.is_valid(case[field]):
                    raise ValueError(f"{tool}: the {field} arguments do not match the tool schema. Use mcp tools to inspect it.")
            constraints = {}
            for key, value in case["allow"].items():
                if isinstance(value, str):
                    constraints[key] = Exact(value)
                    continue
                # CEL maps expose fields as variables, so a CEL equality against
                # `value` requires a schema that excludes object arguments.
                property_schema = schema.get("properties", {}).get(key, {})
                if not isinstance(property_schema, dict) or property_schema.get("type") not in (
                    "boolean", "integer", "number", "array",
                ):
                    raise ValueError(f"{tool}: {key} needs a single scalar or array type for the guided check.")
                constraints[key] = CEL("value == " + json.dumps(value, ensure_ascii=False))
            capabilities[tool] = constraints

        parent = mint_for_holder(issuer, delegator.public_key, {tool: {} for tool in capabilities}, 300)
        builder = parent.attenuate_builder()
        builder.inherit_all()
        builder.with_holder(holder.public_key)
        builder.with_ttl_capped_to_parent(120)
        for tool, constraints in capabilities.items():
            builder.with_capability(tool, constraints)
        builder.terminal()
        leaf = builder.delegate(delegator)
        print(f"Delegated warrant {leaf.id} (two-minute lifetime)", flush=True)
        for case in cases:
            tool = case["tool"]
            for field, expected in (("deny", "DENY"), ("allow", "ALLOW")):
                arguments = case[field]
                result = await client.call_tool(tool, arguments, meta=_authorization([parent, leaf], holder, tool, arguments))
                event = (result.meta or {}).get(AUDIT_META, {})
                if (event.get("decision") != expected or result.is_error != (expected == "DENY")
                        or expected == "DENY" and event.get("reason") != "constraint_violation"):
                    expectation = "DENY for an out-of-scope argument" if expected == "DENY" else "ALLOW and tool success"
                    raise ValueError(f"{tool}: expected {expectation}. Check the audit log before retrying.")
                outcome = "not forwarded" if expected == "DENY" else "tool reported success"
                print(f"{expected:5} {tool} | {outcome}", flush=True)
    print(f"Inspect this run: hermes-tenuo mcp audit {shlex.quote(str(workspace))} --warrant {leaf.id}")
    return 0


async def _client_command(args, workspace):
    from tenuo import Warrant

    from hermes_tenuo.issuance import read_signing_key
    from hermes_tenuo.mcp_workspace import connect_wrapper, list_tools

    async with connect_wrapper(workspace) as client:
        if args.mcp_command == "tools":
            tools = [tool.model_dump(by_alias=True, include={"name", "description", "input_schema"})
                     async for tool in list_tools(client)]
            print(json.dumps(tools, indent=2))
            return 0
        arguments = json.loads(args.args)
        if not isinstance(arguments, dict):
            raise ValueError("--args must be a JSON object")
        chain = [Warrant.from_base64(path.expanduser().read_text().strip()) for path in args.warrant]
        holder = read_signing_key(args.holder_key)
        result = await client.call_tool(args.tool, arguments, meta=_authorization(chain, holder, args.tool, arguments))
        print(result.model_dump_json(by_alias=True, exclude_none=True, indent=2))
        return int(result.is_error)


def run(args):
    try:
        if args.mcp_command == "audit":
            return _audit(args)
        from hermes_tenuo.mcp_workspace import create_workspace, launch_args, load_servers

        workspace = args.workspace.expanduser().resolve()
        if args.mcp_command == "wrap":
            selected = create_workspace(args.source, workspace, args.server, args.trust_root)
            print(f"Wrapped {', '.join(selected)} in {workspace}.")
            print(f"Discover tool names and arguments: hermes-tenuo mcp tools {shlex.quote(str(workspace))}")
            return 0
        if args.mcp_command == "config":
            load_servers(workspace)
            print(json.dumps({"mcpServers": {"tenuo": {"command": sys.executable, "args": launch_args(workspace)}}},
                             indent=2))
            return 0
        if args.mcp_command == "serve":
            from hermes_tenuo.mcp_gateway import serve

            asyncio.run(serve(workspace))
            return 0
        if args.mcp_command == "check":
            cases = _cases(args.cases)
            for case in cases:
                print(f"{case['tool']}\n  Allow {json.dumps(case['allow'])}\n  Deny  {json.dumps(case['deny'])}", flush=True)
            if not args.run:
                print("Preview only. Rerun with --run to exercise these calls against the wrapped services.")
                return 0
            return asyncio.run(_run_check(workspace, cases))
        return asyncio.run(_client_command(args, workspace))
    except ModuleNotFoundError as exc:
        if exc.name not in {"mcp", "httpx2", "yaml"}:
            raise
        print("Install the MCP extra first: pip install 'hermes-tenuo[mcp]'", file=sys.stderr)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"MCP setup or call failed: {exc}", file=sys.stderr)
    except Exception as exc:
        print(f"MCP connection failed ({type(exc).__name__}). Check the wrapper's stderr and original MCP settings.",
              file=sys.stderr)
    return 1
