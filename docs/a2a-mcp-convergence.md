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

## Findings for the MCP track

1. **Names Hermes rewrites.** Wrapper aliases may contain `-` or `.` (from server names), and Hermes
   shortens tool names over 64 characters. A proof is then signed over a name the wrapper does not
   expose, and the call is refused. Either restrict aliases to `[A-Za-z0-9_]` and warn on long names at
   `wrap`, or expose the Hermes name too.
2. **Revocation rollback across processes.** Tenuo's `Authorizer` refuses an older list within one
   process, but a new `mcp serve` process (one per client connection) accepts any validly signed
   `revocations.srl` on disk, including an older one that un-revokes grants. Persist the highest version
   accepted in the workspace and refuse lower ones, as the A2A receiver now does. Requires write access
   to the workspace, so this is integrity hardening, not a remote bypass.
3. **Rule vocabulary.** `mcp check` builds `Exact`/`CEL` constraints from example arguments; accepting the
   `tenuo_delegate` rule JSON would let one grant description serve both.
4. **One revoke command.** Fold `hermes-tenuo a2a revoke` and the wrapper's revocation file into a
   single `hermes-tenuo revoke`.
