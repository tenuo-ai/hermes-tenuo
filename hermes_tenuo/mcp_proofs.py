"""Sign wrapped MCP calls using the original name from Hermes discovery."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger("hermes_tenuo.mcp")
CARRIER = "_tenuo"


class MCPMappingError(ValueError):
    """A configured wrapper tool does not have an unambiguous discovered name."""


def _discovered_names(server_name):
    from tools import mcp_tool
    from tools.mcp_schema_cache import config_fingerprint, get_cached_entry, tools_from_cache_entry
    from tools.mcp_tool_registration import _make_tool_filter
    from tools.mcp_tool_scope import _resolve_server_key

    with mcp_tool._lock:
        key = _resolve_server_key(server_name)
        live = mcp_tool._servers.get(key)
        if live is not None:
            names = [tool.name for tool in live._tools]
            config = live._config
        else:
            config = mcp_tool._lazy_server_configs.get(key)
            names = None
    if names is None:
        if config is None:
            return []
        entry = get_cached_entry(server_name, config_fingerprint(config))
        names = [tool["name"] for tool in tools_from_cache_entry(entry)] if entry else []
    include = _make_tool_filter(server_name, config)
    return [name for name in names if include(name)]


def tool_resolver(servers):
    # The registry toolset retains the exact server key and respects the current
    # profile scope. Model-facing names alone lose that provenance on rewrite.
    owners = {f"mcp-{server}": server for server in servers}

    def resolve(tool_name):
        if not tool_name.startswith("mcp__"):
            return None
        try:
            from tools.mcp_tool_schema import mcp_prefixed_tool_name
            from tools.registry import registry

            server = owners.get(registry.get_toolset_for_tool(tool_name))
            if server is None:
                return None
            matches = {
                name for name in _discovered_names(server)
                if mcp_prefixed_tool_name(server, name) == tool_name
            }
        except Exception as exc:
            raise MCPMappingError("Could not read Hermes's MCP tool registration. Reload MCP discovery.") from exc
        if len(matches) != 1:
            raise MCPMappingError(
                f"Cannot resolve {tool_name!r} to one tool on {server!r}. Reload MCP discovery "
                "or exclude tools with colliding names."
            )
        return matches.pop()

    return resolve


def load_servers(ctx):
    from hermes_tenuo._config import _get_plugin_entry

    block = _get_plugin_entry(ctx).get("mcp_proofs")
    if not block:
        return []
    if not isinstance(block, dict) or not isinstance(block.get("servers"), list):
        raise ValueError("mcp_proofs needs a servers list of Hermes MCP server names")
    servers = block["servers"]
    if any(not isinstance(server, str) or not server.strip() for server in servers):
        raise ValueError("mcp_proofs.servers entries must be non-empty server names")
    return servers


def make_middleware(resolve, get_guard):
    """Attach the session's proof to calls to a discovered wrapper tool."""
    def attach_mcp_proof(tool_name="", args=None, next_call=None, session_id="", **_kw):
        args = dict(args or {})
        try:
            target = resolve(tool_name)
        except MCPMappingError as exc:
            return json.dumps({"error": str(exc)})
        if target is None:
            return next_call(args)
        args.pop(CARRIER, None)
        guard = get_guard()
        try:
            attributed = guard.delegation_session(session_id or _session_id(), str(_kw.get("task_id") or "")) if guard else ""
            meta = guard.call_meta(attributed, target, args) if guard is not None else None
        except Exception as exc:
            # Hermes can bypass middleware that raises. A proof-attribution failure must refuse here.
            logger.warning("hermes-tenuo: could not select MCP proof authority (%s)", type(exc).__name__)
            return json.dumps({"error": "Cannot attribute this MCP call to its authority; call refused."})
        if meta is None:
            logger.info("hermes-tenuo: no authority to prove for %s; the wrapper will refuse it", tool_name)
            return next_call(args)
        return next_call({**args, CARRIER: meta["tenuo"]})

    return attach_mcp_proof


def _session_id():
    try:
        from gateway.session_context import get_session_env
        return str(get_session_env("HERMES_SESSION_ID", "") or "")
    except Exception:
        return ""


def register(ctx, get_guard):
    try:
        servers = load_servers(ctx)
    except ValueError as exc:
        logger.error("hermes-tenuo: mcp_proofs is configured but unusable (%s); wrapped MCP calls carry no proof", exc)
        return None
    if not servers or not hasattr(ctx, "register_middleware"):
        return None
    resolve = tool_resolver(servers)
    ctx.register_middleware("tool_execution", make_middleware(resolve, get_guard))
    logger.info("hermes-tenuo: signing calls to wrapped MCP servers %s", ", ".join(servers))
    return resolve
