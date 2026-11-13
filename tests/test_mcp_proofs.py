"""The two tracks together: a delegated A2A task calls a Tenuo-wrapped MCP server, which verifies the
operator → A → B chain itself before forwarding."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from types import SimpleNamespace
from base64 import b64encode

import pytest

pytest.importorskip("mcp")

from tenuo import SigningKey, Warrant, Wildcard  # noqa: E402

from hermes_tenuo.a2a_delegate import delegate  # noqa: E402
from hermes_tenuo.a2a_ingress import public_key_b64  # noqa: E402
from hermes_tenuo.mcp_gateway import AUDIT_META  # noqa: E402
from hermes_tenuo.audit import LocalAuditLog  # noqa: E402
from hermes_tenuo.hermes_guard import HermesGuard  # noqa: E402
from hermes_tenuo.mcp_proofs import CARRIER, MCPMappingError, make_middleware, tool_resolver  # noqa: E402
from hermes_tenuo.mcp_workspace import connect_wrapper, create_workspace  # noqa: E402
from tests.test_a2a_delegate import Peer2, _config  # noqa: E402
from tests.test_mcp_wrapper import _cli, _local_backend  # noqa: E402

HERMES_NAME = "mcp__tenuo__first__write"  # how Hermes names the wrapper's first__write


def _resolve_test_tool(name):
    return "first__write" if name == HERMES_NAME else None


def test_resolve_names_with_punctuation_truncation_and_overlapping_servers(monkeypatch):
    from hermes_tenuo import mcp_proofs

    def hermes_name(server, tool):
        name = re.sub(r"[^A-Za-z0-9_]", "_", f"mcp__{server}__{tool}")
        if len(name) > 64:
            return name[:55] + "_" + hashlib.sha256(name.encode()).hexdigest()[:8]
        return name

    originals = ["my-files__a.b", "first__" + "long" * 30]
    registered = {hermes_name("a__b", name): "mcp-a__b" for name in originals}
    # An unrelated registry entry can share a model-facing prefix.
    registered["mcp__a__b__other"] = "mcp-unrelated"
    registry = SimpleNamespace(get_toolset_for_tool=registered.get)
    monkeypatch.setitem(sys.modules, "tools.registry", SimpleNamespace(registry=registry))
    monkeypatch.setitem(sys.modules, "tools.mcp_tool_schema", SimpleNamespace(mcp_prefixed_tool_name=hermes_name))
    monkeypatch.setattr(mcp_proofs, "_discovered_names", lambda server: originals if server == "a__b" else [])
    resolve = tool_resolver(["a", "a__b"])
    for original in originals:
        assert resolve(hermes_name("a__b", original)) == original
    assert resolve("mcp__a__b__other") is None
    originals.append("my_files__a_b")
    with pytest.raises(MCPMappingError, match="colliding names"):
        resolve(hermes_name("a__b", originals[0]))
    called = []
    reply = make_middleware(resolve, lambda: None)(
        tool_name=hermes_name("a__b", originals[0]), next_call=called.append,
    )
    assert "colliding names" in json.loads(reply)["error"] and not called


def _forward(middleware, guard_session, args):
    sent = {}

    def next_call(payload):
        sent.update(payload)
        return "forwarded"

    assert middleware(tool_name=HERMES_NAME, args=args, next_call=next_call, session_id=guard_session) == "forwarded"
    return sent


@pytest.mark.asyncio
async def test_a_delegated_task_reaches_a_wrapped_mcp_tool_only_within_its_grant(tmp_path, monkeypatch):
    monkeypatch.setenv("TOKEN_HOME", "secret-token")
    root, a, b = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    trust = tmp_path / "root.pub"
    trust.write_text(b64encode(root.public_key.to_bytes()).decode())
    effects = tmp_path / "first.txt"
    source = tmp_path / "mcp.json"
    source.write_text(json.dumps({"mcpServers": {"first": _local_backend(effects)}}))
    workspace = tmp_path / "wrapped"
    create_workspace(source, workspace, [], trust)

    # The operator's warrant for A covers the wrapped tool; A delegates "verified" only to B.
    w_a = (Warrant.mint_builder().holder(a.public_key)
           .capability("first__write", {"value": Wildcard()}).ttl(3600).mint(root))
    keys = type("K", (), {"b": b, "root": root})
    home = Peer2(b, {"agent-a": public_key_b64(a)}, root)
    home.guard._mcp_resolver = _resolve_test_tool
    sender_log, receiver_log = tmp_path / "sender.jsonl", tmp_path / "receiver.jsonl"
    home.guard._audit_callback = LocalAuditLog(receiver_log)
    delegation = delegate(config=_config(keys), chain=[w_a], key=a, peer="home", task="Record verified.",
             tools={"first__write": {"value": {"equals": "verified"}}}, post=home.post)
    HermesGuard(audit_callback=LocalAuditLog(sender_log)).record_delegation("sess-a", [w_a], delegation)
    home.ingress.current_turn = lambda: home.turn

    # B's own guard authorizes the Hermes-side call under the wrapper's name.
    assert home.call(HERMES_NAME, {"value": "verified"}) is None
    assert home.call(HERMES_NAME, {"value": "changed"})["action"] == "block"

    middleware = make_middleware(_resolve_test_tool, lambda: home.guard)
    allowed = _forward(middleware, "sess-b", {"value": "verified", CARRIER: {"forged": True}})
    outside = _forward(middleware, "sess-b", {"value": "changed"})
    assert allowed[CARRIER] != {"forged": True}  # the model's own carrier is never forwarded

    async with connect_wrapper(workspace) as client:
        result = await client.call_tool("first__write", allowed)
        assert not result.is_error and result.meta[AUDIT_META]["decision"] == "ALLOW"
        denied = await client.call_tool("first__write", outside)
        assert denied.is_error and denied.meta[AUDIT_META]["reason"] == "constraint_violation"
        bare = await client.call_tool("first__write", {"value": "verified"})
        assert bare.is_error and bare.meta[AUDIT_META]["decision"] == "DENY"
    assert effects.read_text() == "verified\n"

    audit = [json.loads(r) for r in (workspace / "audit.jsonl").read_text().splitlines()]
    allowed_row = next(r for r in audit if r["decision"] == "ALLOW")
    assert allowed_row["parent_warrant_ids"] == [str(w_a.id)]  # the wrapper saw the delegated chain
    combined = await _cli("audit", workspace, "--hermes-log", sender_log, "--hermes-log", receiver_log,
                          "--warrant", delegation["grant"]["id"], "--json")
    rows = [json.loads(line) for line in combined.splitlines()]
    assert {row["source"] for row in rows} == {str(path.resolve()) for path in (workspace, sender_log, receiver_log)}
    assert all(row["warrant_id"] == delegation["grant"]["id"] for row in rows)
    assert all(row["parent_warrant_ids"] == [str(w_a.id)] for row in rows)
    assert {row["decision"] for row in rows if row["source"] == str(workspace.resolve())} == {"ALLOW", "DENY"}
    assert "changed" not in combined and f'"{CARRIER}"' not in combined


def test_calls_to_other_tools_pass_through_untouched():
    middleware = make_middleware(_resolve_test_tool, lambda: None)
    seen = {}
    middleware(tool_name="terminal", args={"command": "ls", CARRIER: "kept"}, next_call=seen.update)
    assert seen == {"command": "ls", CARRIER: "kept"}


def test_a_session_without_authority_sends_no_proof():
    middleware = make_middleware(_resolve_test_tool, lambda: None)
    seen = {}
    middleware(tool_name=HERMES_NAME, args={"value": "x", CARRIER: {"forged": 1}}, next_call=seen.update)
    assert seen == {"value": "x"}


def test_the_guard_authorizes_the_tool_arguments_not_the_proof_carrier(monkeypatch):
    """Hermes runs registry enforcement after execution middleware, so the guard sees _tenuo there."""
    root, holder = SigningKey.generate(), SigningKey.generate()
    w = Warrant.mint_builder().holder(holder.public_key).capability("first__write", {"value": Wildcard()}).ttl(600).mint(root)
    guard = HermesGuard(warrant=w, signing_key=holder, trusted_roots=[root.public_key])
    guard._mcp_resolver = _resolve_test_tool
    name = HERMES_NAME
    assert guard.pre_tool_call(name, {"value": "x", CARRIER: {"warrant": "w", "signature": "s"}}, session_id="s") is None
    # Elsewhere _tenuo stays an ordinary, unnamed argument.
    other = HermesGuard(warrant=w, signing_key=holder, trusted_roots=[root.public_key])
    assert other.pre_tool_call(name, {"value": "x", CARRIER: {}}, session_id="s")["action"] == "block"


@pytest.mark.parametrize("adapter", [False, True])
def test_task_only_mcp_call_proves_child_authority_and_refuses_ambiguous_tasks(monkeypatch, adapter):
    from tenuo import Authorizer, Exact
    from tenuo.mcp import MCPVerifier
    from hermes_tenuo._guard import PluginGuard
    from hermes_tenuo.a2a_ingress import grant_to

    root, parent_key, child_key = (SigningKey.generate() for _ in range(3))
    parent = (Warrant.mint_builder().holder(parent_key.public_key)
              .capability("first__write", {"value": Wildcard()}).ttl(600).mint(root))
    child = grant_to(parent_key, [parent], child_key.public_key, {"first__write": {"value": Exact("child")}}, 120)
    guard = HermesGuard(warrant=parent, signing_key=parent_key, trusted_roots=[root.public_key])
    guard.set_session_warrant("child", child, child_key, parent_warrant=[parent])
    guard._remember_task("child-task", "child")
    monkeypatch.setattr("hermes_tenuo.mcp_proofs._session_id", lambda: "")
    middleware = make_middleware(_resolve_test_tool, lambda: PluginGuard(guard) if adapter else guard)
    forwarded = []
    middleware(tool_name=HERMES_NAME, args={"value": "child", CARRIER: "forged"},
               task_id="child-task", next_call=forwarded.append)
    proof = forwarded[-1][CARRIER]
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root.public_key]))
    assert verifier.verify("first__write", {"value": "child"}, meta={"tenuo": proof}).allowed
    assert not verifier.verify("first__write", {"value": "parent-only"}, meta={"tenuo": proof}).allowed
    # Sign an out-of-scope value too: the wrapper must still see the child's restricted warrant.
    middleware(tool_name=HERMES_NAME, args={"value": "parent-only"},
               task_id="child-task", next_call=forwarded.append)
    assert not verifier.verify("first__write", {"value": "parent-only"},
                               meta={"tenuo": forwarded[-1][CARRIER]}).allowed
    for task in ("unknown", "child-task"):
        if task == "child-task":
            guard._remember_task(task, "another-child")
        before = len(forwarded)
        response = middleware(tool_name=HERMES_NAME, args={"value": "child"}, task_id=task,
                              next_call=forwarded.append)
        assert "refused" in json.loads(response)["error"] and len(forwarded) == before
