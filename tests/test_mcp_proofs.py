"""The two tracks together: a delegated A2A task calls a Tenuo-wrapped MCP server, which verifies the
operator → A → B chain itself before forwarding."""

from __future__ import annotations

import json
from base64 import b64encode

import pytest

pytest.importorskip("mcp")

from tenuo import SigningKey, Warrant, Wildcard  # noqa: E402

from hermes_tenuo.a2a_delegate import delegate  # noqa: E402
from hermes_tenuo.a2a_ingress import public_key_b64  # noqa: E402
from hermes_tenuo.mcp_gateway import AUDIT_META  # noqa: E402
from hermes_tenuo.mcp_proofs import CARRIER, make_middleware, prefixes, wrapper_tool_name  # noqa: E402
from hermes_tenuo.mcp_workspace import connect_wrapper, create_workspace  # noqa: E402
from tests.test_a2a_delegate import Peer2, _config  # noqa: E402
from tests.test_mcp_wrapper import _local_backend  # noqa: E402

HERMES_NAME = "mcp__tenuo__first__write"  # how Hermes names the wrapper's first__write


def test_wrapped_tool_names():
    p = prefixes(["tenuo", "my-wrapper"])
    assert wrapper_tool_name(HERMES_NAME, p) == "first__write"
    assert wrapper_tool_name("mcp__my_wrapper__git__status", p) == "git__status"
    assert wrapper_tool_name("mcp__other__first__write", p) is None
    assert wrapper_tool_name("terminal", p) is None


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
    home.guard._mcp_prefixes = prefixes(["tenuo"])
    delegate(config=_config(keys), chain=[w_a], key=a, peer="home", task="Record verified.",
             tools={"first__write": {"value": {"equals": "verified"}}}, post=home.post)
    home.ingress.current_turn = lambda: home.turn

    # B's own guard authorizes the Hermes-side call under the wrapper's name.
    assert home.call(HERMES_NAME, {"value": "verified"}) is None
    assert home.call(HERMES_NAME, {"value": "changed"})["action"] == "block"

    middleware = make_middleware(prefixes(["tenuo"]), lambda: home.guard)
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


def test_calls_to_other_tools_pass_through_untouched():
    middleware = make_middleware(prefixes(["tenuo"]), lambda: None)
    seen = {}
    middleware(tool_name="terminal", args={"command": "ls", CARRIER: "kept"}, next_call=seen.update)
    assert seen == {"command": "ls", CARRIER: "kept"}


def test_a_session_without_authority_sends_no_proof():
    middleware = make_middleware(prefixes(["tenuo"]), lambda: None)
    seen = {}
    middleware(tool_name=HERMES_NAME, args={"value": "x", CARRIER: {"forged": 1}}, next_call=seen.update)
    assert seen == {"value": "x"}


def test_the_guard_authorizes_the_tool_arguments_not_the_proof_carrier(monkeypatch):
    """Hermes runs registry enforcement after execution middleware, so the guard sees _tenuo there."""
    from hermes_tenuo.hermes_guard import HermesGuard

    root, holder = SigningKey.generate(), SigningKey.generate()
    w = Warrant.mint_builder().holder(holder.public_key).capability("first__write", {"value": Wildcard()}).ttl(600).mint(root)
    guard = HermesGuard(warrant=w, signing_key=holder, trusted_roots=[root.public_key])
    guard._mcp_prefixes = prefixes(["wrapped"])
    name = "mcp__wrapped__first__write"
    assert guard.pre_tool_call(name, {"value": "x", CARRIER: {"warrant": "w", "signature": "s"}}, session_id="s") is None
    # Elsewhere _tenuo stays an ordinary, unnamed argument.
    other = HermesGuard(warrant=w, signing_key=holder, trusted_roots=[root.public_key])
    assert other.pre_tool_call(name, {"value": "x", CARRIER: {}}, session_id="s")["action"] == "block"
