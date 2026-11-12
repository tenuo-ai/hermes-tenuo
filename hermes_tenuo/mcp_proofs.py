"""Sign Hermes's calls to Tenuo-wrapped MCP servers with the session's own authority.

``hermes-tenuo mcp serve`` (``mcp_gateway``) verifies a warrant chain and the caller's proof on every
call, but Hermes's MCP client sends none. For the MCP servers named in ``mcp_proofs.servers``, this
``tool_execution`` middleware adds the proof in the SDK's ``_tenuo`` argument carrier, signed over the
wrapper's tool name with the session's own chain and key (``HermesGuard.call_meta``). On a delegated
A2A turn that is the chain ending in the grant this agent holds, so the wrapper checks the delegated
authority itself::

    plugins:
      entries:
        hermes-tenuo:
          mcp_proofs:
            servers: [tenuo]     # names under Hermes mcp_servers that run `hermes-tenuo mcp serve`

Hermes registers a server's tools as ``mcp__<server>__<tool>``; the wrapper's tools are named
``<wrapped server>__<tool>``. Grants name the wrapper's names (``files__write_file``), and the local
guard authorizes these calls under the same names. Wrapper names must use only letters, digits and
underscores, and stay short enough that Hermes does not shorten them: otherwise the signed name does
not match and the wrapper refuses the call.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional

logger = logging.getLogger("hermes_tenuo.mcp")

CARRIER = "_tenuo"
HERMES_MCP_PREFIX = "mcp__"
HERMES_NAME_LIMIT = 64


def prefixes(servers: Iterable[str]) -> List[str]:
    """Hermes tool-name prefixes for the configured wrapper servers."""
    import re

    return [f"{HERMES_MCP_PREFIX}{re.sub(r'[^A-Za-z0-9_]', '_', str(s))}__" for s in servers if str(s)]


def wrapper_tool_name(tool_name: str, server_prefixes: Iterable[str]) -> Optional[str]:
    """The wrapper's name for a Hermes MCP tool name, or None when it is not a wrapped tool."""
    for prefix in server_prefixes:
        if tool_name.startswith(prefix) and len(tool_name) > len(prefix):
            return tool_name[len(prefix):]
    return None


def load_servers(ctx: Any) -> List[str]:
    from hermes_tenuo._config import _get_plugin_entry

    block = _get_plugin_entry(ctx).get("mcp_proofs")
    if not block:
        return []
    if not isinstance(block, dict) or not isinstance(block.get("servers"), list):
        raise ValueError("mcp_proofs needs a servers list of Hermes MCP server names")
    return [str(s) for s in block["servers"] if str(s).strip()]


def make_middleware(server_prefixes: List[str], get_guard: Callable[[], Any]) -> Callable[..., Any]:
    """``tool_execution`` middleware that attaches the session's proof to wrapped MCP calls."""

    def attach_mcp_proof(tool_name: str = "", args: Optional[Dict[str, Any]] = None,
                         next_call: Optional[Callable[[Dict[str, Any]], Any]] = None,
                         session_id: str = "", **_kw: Any) -> Any:
        args = dict(args or {})
        target = wrapper_tool_name(tool_name, server_prefixes)
        if target is None:
            return next_call(args)
        # Only this middleware writes the carrier: a value the model supplied is never forwarded.
        args.pop(CARRIER, None)
        guard = get_guard()
        meta = None
        if guard is not None:
            meta = guard.call_meta(session_id or _session_id(), target, args)
        if meta is None:
            logger.info("hermes-tenuo: no authority to prove for %s; the wrapper will refuse it", tool_name)
            return next_call(args)
        if len(tool_name) >= HERMES_NAME_LIMIT:
            logger.warning("hermes-tenuo: %s may be a shortened name; the wrapper may refuse its proof", tool_name)
        return next_call({**args, CARRIER: meta["tenuo"]})

    return attach_mcp_proof


def _session_id() -> str:
    try:
        from gateway.session_context import get_session_env
        return str(get_session_env("HERMES_SESSION_ID", "") or "")
    except Exception:
        return ""


def register(ctx: Any, get_guard: Callable[[], Any]) -> List[str]:
    """Register the middleware when ``mcp_proofs`` names wrapper servers. Returns their prefixes."""
    try:
        servers = load_servers(ctx)
    except Exception as exc:
        logger.error("hermes-tenuo: mcp_proofs is configured but unusable (%s); wrapped MCP calls carry no proof", exc)
        return []
    if not servers or not hasattr(ctx, "register_middleware"):
        return []
    server_prefixes = prefixes(servers)
    ctx.register_middleware("tool_execution", make_middleware(server_prefixes, get_guard))
    logger.info("hermes-tenuo: signing calls to wrapped MCP servers %s", ", ".join(servers))
    return server_prefixes


__all__ = ["CARRIER", "make_middleware", "prefixes", "register", "wrapper_tool_name"]
