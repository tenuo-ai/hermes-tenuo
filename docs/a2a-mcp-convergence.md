# Bringing the A2A and MCP tracks together

Updated 2026-11-12. Working note for the agent-to-agent track (`feat/a2a-delegation`, #82) and the MCP
track (`codex/mcp-authority`, #81).

## One trust model

Both tracks enforce at the receiving boundary, from the same pieces:

| | A2A receiver (`a2a_ingress`) | MCP wrapper (`mcp_gateway`) |
|---|---|---|
| Authority | delegated warrant chain from an operator root | same |
| Holder proof | receiver's own key at every tool call | caller's `_meta.tenuo` proof per call |
| Verification | `Authorizer.verify_chain` + `enforce_tool_call` | `tenuo.mcp.MCPVerifier` |
| Revocation | signed list, raw bytes (`revocations.srl`) | same file format |
| Replay | persisted nonces | persisted nonces (workspace) |
| Audit | `LocalAuditLog`, `tool`/`decision`/`reason` | same log and shape |
| Rules | Hermes Guests vocabulary (`equals`, `one_of`, `range`, `pattern`, `regex`, `any`, `"*"`) | wrapper preview cases |

## The join: a delegated agent calls a wrapped MCP tool

```
operator root → A's warrant ──tenuo_delegate──▶ grant held by B ──B calls an MCP tool──▶ wrapper verifies
                                                                   _meta.tenuo = chain [root…A, B]
                                                                   signed with B's key
```

`HermesGuard.call_meta(session_id, tool, args)` (in #82) returns the `_meta` block for one call from
the session's own authority. On a delegated A2A turn that is the chain ending in B's grant, signed with
B's key. Verified in `tests/test_a2a_delegate.py::test_a_delegated_turn_presents_its_grant_to_an_mcp_verifier`
with `MCPVerifier`, the class the wrapper uses: the operator → A → B chain verifies; a call outside the
grant, or a proof replayed with other arguments, is refused. The SDK's `_tenuo` argument carrier also
verifies and is stripped from the forwarded arguments.

## Done in #82

- **Proofs on Hermes's own MCP calls** (`hermes_tenuo/mcp_proofs.py`): a `tool_execution` middleware
  adds the SDK's `_tenuo` carrier, signed with the session's own chain and key over the wrapper's tool
  name, for servers listed in `mcp_proofs.servers`. Any `_tenuo` the model supplied is dropped first.
  The local guard authorizes those calls under the wrapper's name and ignores the carrier (Hermes runs
  registry enforcement after execution middleware). Hermes names the tools `mcp__<server>__<tool>`, so
  the wrapper name is the remainder.
- **Live, two Hermes gateways and the wrapper** (`spikes/a2a-d0/two_agent.py`, 6/6): A delegates
  "write `verified`"; B's agent calls the wrapped tool; the wrapper process verifies operator → A → B and
  forwards; its audit records A's warrant as the parent; the backend records `verified`. B's attempt to
  write another value is refused by B's guard.
- `mcp config` names the server `tenuo_mcp`: the name `tenuo` collides with hermes-tenuo's own toolset in
  Hermes and hid the wrapped tools in testing.

## Review updates in #84

- Hermes's scoped tool registry identifies the actual wrapper server. The plugin resolves the
  registered name against the wrapper's discovery data, including rewritten or shortened names.
  An ambiguous or unavailable mapping blocks the call.
- The MCP wrapper persists the accepted signed list's version and digest in the workspace. It
  refuses a rollback, a different list at the same version, or a missing list after acceptance.
- The sender records the child grant ID. Receiver and wrapper decisions carry the same lineage.
  `mcp audit --hermes-log` combines the agent and wrapper logs by warrant ID. The integration test
  also presents a valid proof for an out-of-scope call directly to the wrapper and checks the denial
  and backend state.
- Protected A2A ingress requires one named sender per receiver until [upstream #146669](https://github.com/NousResearch/hermes-agent/issues/146669)
  isolates task reads by peer. `a2a check` reports the same configuration requirements.

## Follow-ups

1. **Rule vocabulary.** `mcp check` builds `Exact`/`CEL` constraints from example arguments. Accepting the
   `tenuo_delegate` rule JSON would let one grant description serve both.
2. **One revoke command.** Fold `hermes-tenuo a2a revoke` and the wrapper's revocation file into a
   single `hermes-tenuo revoke`.
