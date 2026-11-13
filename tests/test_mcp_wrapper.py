"""Exercise the real MCP transports and SDK verifier across separate processes."""
from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

import uvicorn  # noqa: E402
from mcp import types  # noqa: E402
from mcp.server.lowlevel import Server  # noqa: E402
from mcp.server.stdio import stdio_server  # noqa: E402
from tenuo import Exact, SignedRevocationList, SigningKey  # noqa: E402

from hermes_tenuo.issuance import mint_for_holder  # noqa: E402
from hermes_tenuo.mcp_cli import _authorization  # noqa: E402
from hermes_tenuo.mcp_gateway import AUDIT_META  # noqa: E402
from hermes_tenuo.mcp_workspace import connect_wrapper, create_workspace, load_servers  # noqa: E402


def _backend(effects):
    async def list_tools(_context, _params):
        return types.ListToolsResult(tools=[types.Tool(
            name="write",
            input_schema={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
        )])

    async def call_tool(_context, params):
        assert "tenuo" not in (params.meta or {})
        value = params.arguments["value"]
        effects.write_text(effects.read_text() + value + "\n" if effects.exists() else value + "\n")
        return types.CallToolResult(content=[types.TextContent(type="text", text=value)])

    return Server("test-backend", on_list_tools=list_tools, on_call_tool=call_tool)


async def _stdio_backend(effects):
    server = _backend(effects)
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def _local_backend(effects):
    return {"command": sys.executable, "args": [str(Path(__file__).resolve()), str(effects)]}


async def _cli(*args, check=True):
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "hermes_tenuo.cli", "mcp", *map(str, args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
    if check:
        assert proc.returncode == 0, (stdout.decode(), stderr.decode())
    return stdout.decode()


@pytest.mark.asyncio
async def test_wrap_check_and_audit_over_stdio_and_http(tmp_path):
    local_effects, http_effects = tmp_path / "local.txt", tmp_path / "http.txt"
    app = _backend(http_effects).streamable_http_app(json_response=True)
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.listen()
        runner = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            for _ in range(100):
                if server.started:
                    break
                await asyncio.sleep(0.05)
            assert server.started
            source, workspace = tmp_path / "servers.json", tmp_path / "wrapped"
            source.write_text(json.dumps({"mcpServers": {
                "local": _local_backend(local_effects),
                "remote": {"url": f"http://127.0.0.1:{port}/mcp"},
            }}))
            await _cli("wrap", source, workspace)
            discovered = json.loads(await _cli("tools", workspace))
            assert [tool["name"] for tool in discovered] == ["local__write", "remote__write"]
            cases = tmp_path / "cases.json"
            cases.write_text(json.dumps([
                {"tool": tool["name"], "allow": {"value": "ok"}, "deny": {"value": "forbidden"}}
                for tool in discovered
            ]))
            assert "Preview only" in await _cli("check", workspace, cases)
            assert not local_effects.exists() and not http_effects.exists()
            assert "Inspect this run" in await _cli("check", workspace, cases, "--run")
            assert local_effects.read_text() == http_effects.read_text() == "ok\n"
            events = [json.loads(line) for line in (await _cli("audit", workspace, "--json")).splitlines()]
            assert [(event["server"], event["decision"], event["outcome"]) for event in events] == [
                ("local", "DENY", "not forwarded"), ("local", "ALLOW", "tool reported success"),
                ("remote", "DENY", "not forwarded"), ("remote", "ALLOW", "tool reported success"),
            ]
            assert len({event["warrant_id"] for event in events}) == 1
            assert all(len(event["parent_warrant_ids"]) == 1 for event in events)
            assert "forbidden" not in (workspace / "audit.jsonl").read_text()
        finally:
            server.should_exit = True
            await runner


@pytest.mark.asyncio
async def test_external_warrant_replay_revocation_and_audit_across_wrappers(tmp_path):
    from base64 import b64encode

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    trust = tmp_path / "issuer.pub"
    trust.write_text(b64encode(issuer.public_key.to_bytes()).decode())
    workspaces = []
    for name in ("first", "second"):
        source = tmp_path / f"{name}.json"
        source.write_text(json.dumps({"mcpServers": {name: _local_backend(tmp_path / f"{name}.txt")}}))
        workspace = tmp_path / name
        create_workspace(source, workspace, [], trust)
        assert not (workspace / "issuer.key").exists()
        workspaces.append(workspace)

    arguments = {"value": "verified"}
    warrant = mint_for_holder(issuer, holder.public_key, {
        "first__write": {"value": Exact("verified")},
        "second__write": {"value": Exact("verified")},
    }, 120)
    first_auth = _authorization([warrant], holder, "first__write", arguments)
    async with connect_wrapper(workspaces[0]) as client:
        no_warrant = await client.call_tool("first__write", arguments)
        assert no_warrant.meta[AUDIT_META]["decision"] == "DENY"
        bad_proof = await client.call_tool("first__write", {"value": "changed"}, meta=first_auth)
        assert bad_proof.meta[AUDIT_META]["decision"] == "DENY"
        allowed = await client.call_tool("first__write", arguments, meta=first_auth)
        assert not allowed.is_error
    async with connect_wrapper(workspaces[0]) as client:
        replay = await client.call_tool("first__write", arguments, meta=first_auth)
        assert replay.meta[AUDIT_META]["decision"] == "DENY"
    assert (tmp_path / "first.txt").read_text() == "verified\n"

    async with connect_wrapper(workspaces[1]) as client:
        crossed = await client.call_tool("second__write", arguments, meta=first_auth)
        assert crossed.meta[AUDIT_META]["decision"] == "DENY"
        revocations = SignedRevocationList.builder().version(1).revoke(warrant.id).build(issuer)
        (workspaces[1] / "revocations.srl").write_bytes(revocations.to_bytes())
        second_auth = _authorization([warrant], holder, "second__write", arguments)
        revoked = await client.call_tool("second__write", arguments, meta=second_auth)
        assert revoked.meta[AUDIT_META]["reason"] == "revoked"
    assert not (tmp_path / "second.txt").exists()

    # A new wrapper cannot resurrect the revoked grant with an older signed
    # list, a different list at the same version, or a deleted list.
    revocation_path = workspaces[1] / "revocations.srl"
    rollback = SignedRevocationList.builder().version(0).build(issuer)
    conflict = SignedRevocationList.builder().version(1).build(issuer)
    for replacement in (rollback, conflict, None):
        if replacement is None:
            revocation_path.unlink()
        else:
            revocation_path.write_bytes(replacement.to_bytes())
        async with connect_wrapper(workspaces[1]) as client:
            blocked = await client.call_tool("second__write", arguments, meta=second_auth)
            assert blocked.meta[AUDIT_META]["reason"] == "revocation_list_unavailable"
    newer = SignedRevocationList.builder().version(2).revoke(warrant.id).build(issuer)
    revocation_path.write_bytes(newer.to_bytes())
    async with connect_wrapper(workspaces[1]) as client:
        revoked = await client.call_tool("second__write", arguments, meta=second_auth)
        assert revoked.meta[AUDIT_META]["reason"] == "revoked"
    assert not (tmp_path / "second.txt").exists()

    lines = (await _cli("audit", *workspaces, "--warrant", warrant.id, "--json")).splitlines()
    assert {json.loads(line)["server"] for line in lines} == {"first", "second"}


def test_config_import_avoids_copying_credentials_and_detects_retargeting(tmp_path):
    source = tmp_path / "config.yaml"
    contents = """
mcp_servers:
  local:
    command: echo
    env:
      TOKEN: do-not-copy
  disabled:
    enabled: false
    command: echo
"""
    source.write_text(contents)
    workspace = tmp_path / "wrapper"
    assert list(create_workspace(source, workspace, [], None)) == ["local"]
    assert source.read_text() == contents
    assert "do-not-copy" not in (workspace / "workspace.json").read_text()
    source.write_text(contents.replace("command: echo", "command: false", 1))
    with pytest.raises(ValueError, match="changed in the source"):
        load_servers(workspace)


@pytest.mark.parametrize("spec, variable", [
    ({"url": "${MCP_URL}"}, "MCP_URL"),
    ({"command": "${MCP_COMMAND}"}, "MCP_COMMAND"),
    ({"command": "echo", "args": ["${MCP_ARGS}"]}, "MCP_ARGS"),
    ({"command": "echo", "cwd": "${MCP_CWD}"}, "MCP_CWD"),
    ({"command": "echo", "env": {"TARGET": "${MCP_TARGET}"}}, "MCP_TARGET"),
    ({"url": "https://example.com/mcp", "headers": {"Authorization": "${MCP_TOKEN}"}}, "MCP_TOKEN"),
])
def test_expanded_connection_settings_are_pinned_without_copying_secrets(tmp_path, monkeypatch, spec, variable):
    monkeypatch.setenv(variable, "original-sensitive-value")
    source, workspace = tmp_path / "servers.json", tmp_path / "workspace"
    source.write_text(json.dumps({"mcpServers": {"service": spec}}))
    create_workspace(source, workspace, [], None)
    assert load_servers(workspace)
    assert "original-sensitive-value" not in (workspace / "workspace.json").read_text()
    monkeypatch.setenv(variable, "different-sensitive-value")
    with pytest.raises(ValueError, match="Resolved settings"):
        load_servers(workspace)


def test_existing_unpinned_workspace_is_rejected(tmp_path):
    source, workspace = tmp_path / "servers.json", tmp_path / "workspace"
    source.write_text(json.dumps({"mcpServers": {"service": {"command": "echo"}}}))
    create_workspace(source, workspace, [], None)
    config = json.loads((workspace / "workspace.json").read_text())
    del config["resolved_servers"]
    (workspace / "workspace.json").write_text(json.dumps(config))
    with pytest.raises(ValueError, match="not pinned"):
        load_servers(workspace)


if __name__ == "__main__":
    asyncio.run(_stdio_backend(Path(sys.argv[1])))
