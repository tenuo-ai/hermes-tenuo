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

## What is left, and who

1. **Attach the proof to Hermes's MCP calls** (MCP track). Hermes's public `tool_execution` middleware
   can pass modified arguments to `next_call`, so a middleware can add `_tenuo` from `call_meta` to
   calls for wrapped MCP tools. Open question: the proof is signed over the tool name the wrapper sees,
   but Hermes registers MCP tools under collision-resolved local names and keeps the mapping in private
   modules. Either the wrapper accepts the Hermes-side name, or Hermes exposes "server and original
   tool name for a registered MCP tool" publicly. Prefer the public API.
2. **Rule vocabulary in the wrapper's preview** (MCP track): accept the same rule JSON as
   `tenuo_delegate`, so one grant description works for both.
3. **One revoke command** (either): `hermes-tenuo a2a revoke` writes the wrapper's format; fold it and
   the wrapper's revocation into a single `hermes-tenuo revoke`.
4. **End-to-end lab** (A2A track, after 1): A delegates to B; B's delegated task calls a wrapped
   Filesystem MCP; the wrapper allows only the delegated path. Reuses `spikes/a2a-d0`.
