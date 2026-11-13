"""Verify MCP calls at the receiving boundary before forwarding them."""
from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from jsonschema.validators import validator_for
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from referencing import Registry
from tenuo import Authorizer
from tenuo.mcp import MCPVerifier
from tenuo.nonce import NonceStore

from hermes_tenuo.audit import LocalAuditLog
from hermes_tenuo.issuance import read_public_key
from hermes_tenuo.mcp_replay import WorkspaceNonces
from hermes_tenuo.mcp_revocations import WorkspaceRevocations
from hermes_tenuo.mcp_workspace import connect_tools, load_servers

AUDIT_FILE = "audit.jsonl"
AUDIT_META = "tenuo.ai/wrapper"


def _reply(record, message):
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        is_error=True,
        meta={AUDIT_META: {
            "call_id": record["tool_call_id"], "decision": record["decision"], "reason": record.get("reason"),
        }},
    )


class WrappedTools:
    def __init__(self, workspace: Path, tools):
        root = read_public_key(workspace / "trusted-root.pub")
        self.authorizer = Authorizer(trusted_roots=[root])
        self.verifier = MCPVerifier(
            authorizer=self.authorizer,
            require_warrant=True,
            nonce_store=NonceStore(backend=WorkspaceNonces(workspace / "nonces.sqlite3")),
            control_plane=False,
        )
        self.tools = tools
        self.validators = {
            name: validator_for(tool.definition.input_schema)(tool.definition.input_schema, registry=Registry())
            for name, tool in tools.items()
        }
        self.audit = LocalAuditLog(workspace / AUDIT_FILE)
        self.revocations = WorkspaceRevocations(workspace, self.authorizer)

    async def list_tools(self, _context, _params):
        return types.ListToolsResult(tools=[tool.definition for tool in self.tools.values()])

    async def call_tool(self, _context, params):
        started = time.monotonic()
        tool = self.tools.get(params.name)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "tool_call_id": uuid.uuid4().hex,
            "server": tool.server if tool else None,
            "tool": tool.definition.name if tool else None,
            "decision": "DENY",
            "outcome": "not forwarded",
        }
        if tool is None:
            record["reason"] = "unknown_tool"
            self.audit(SimpleNamespace(**record))
            return _reply(record, "Unknown wrapped tool. List the available tools and choose its qualified name.")
        if params.task is not None or params.request_state is not None or params.input_responses is not None:
            record["reason"] = "unsupported_call_mode"
            self.audit(SimpleNamespace(**record))
            return _reply(record, "This wrapper supports direct tool calls without task or interactive continuations.")
        try:
            self.revocations.refresh()
        except Exception:
            record["reason"] = "revocation_list_unavailable"
            self.audit(SimpleNamespace(**record))
            return _reply(record, "Could not use the signed revocation list. Restore the accepted version or a newer signed list.")
        verdict = self.verifier.verify(
            params.name, params.arguments, meta=params.meta, input_schema=tool.definition.input_schema,
        )
        chain = getattr(verdict, "presented_chain", [])
        if chain:
            record["warrant_id"] = str(chain[-1].id)
            record["parent_warrant_ids"] = [str(warrant.id) for warrant in chain[:-1]]
        if not verdict.allowed or not chain:
            reason = verdict.error_type or ("verified_chain_unavailable" if verdict.allowed else "authorization_denied")
            record["reason"] = reason
            self.audit(SimpleNamespace(**record))
            return _reply(record, f"Tenuo denied this call ({reason.replace('_', ' ')}). No request was sent upstream.")

        leaf = chain[-1]
        record.update(
            decision="ALLOW",
            holder_fingerprint=hashlib.sha256(leaf.holder_key.to_bytes()).hexdigest(),
            root_fingerprint=hashlib.sha256(chain[0].issuer.to_bytes()).hexdigest(),
        )
        try:
            valid_arguments = self.validators[params.name].is_valid(verdict.clean_arguments)
        except Exception:
            valid_arguments = False
        if not valid_arguments:
            record["reason"] = "invalid_tool_arguments"
            self.audit(SimpleNamespace(**record))
            return _reply(record, "Tenuo allowed the call, but the arguments did not match the tool schema.")

        record["outcome"] = "forwarding"
        self.audit(SimpleNamespace(**record))
        try:
            result = await tool.session.call_tool(
                tool.name, verdict.clean_arguments, read_timeout_seconds=tool.timeout,
            )
        except Exception:
            record.update(outcome="unknown", reason="upstream_call_failed")
            self.audit(SimpleNamespace(**record, duration_ms=round((time.monotonic() - started) * 1000)))
            return _reply(record, "Tenuo allowed the call, but the upstream outcome is unknown. Check the service before retrying.")

        record["outcome"] = "tool reported error" if result.is_error else "tool reported success"
        self.audit(SimpleNamespace(**record, duration_ms=round((time.monotonic() - started) * 1000)))
        return result.model_copy(update={"meta": {
            **(result.meta or {}),
            AUDIT_META: {"call_id": record["tool_call_id"], "decision": record["decision"]},
        }})


async def serve(workspace: Path):
    async with connect_tools(load_servers(workspace)) as tools:
        gateway = WrappedTools(workspace, tools)
        server = Server(
            "tenuo-mcp",
            on_list_tools=gateway.list_tools,
            on_call_tool=gateway.call_tool,
        )
        async with stdio_server() as (reader, writer):
            await server.run(reader, writer, server.create_initialization_options())
