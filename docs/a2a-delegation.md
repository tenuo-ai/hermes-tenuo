# Delegate tasks between Hermes agents (preview)

One Hermes can hand a bounded task to another over native A2A. The receiving agent runs it only within
a Tenuo grant that the sender gave it: named tools, limited argument values, a short lifetime. The
receiver checks the grant before the task reaches its model and again at every tool call, with its own
key. Its other tools and permissions do not apply to the task.

Preview: the design, evidence and limits are in [the design report](a2a-delegation-design.md).

## How it works

```
operator root ──▶ A's warrant ──(tenuo_delegate)──▶ grant held by B's key ──▶ B runs only that
```

- The grant is a child of the warrant A's session already holds, so A can only delegate what it has.
- Only B's key can use it. A signs the request; B checks that the authenticated peer's pinned key
  signed it, for B, for this conversation, for this exact task text, once.
- B verifies the whole chain to a root it trusts, and refuses anything revoked.
- A delegated turn can delegate onward, but only within its own grant; the next agent verifies the
  whole chain back to the root.

## Set up the receiving agent (B)

1. Show its key: `hermes-tenuo a2a key`.
2. Enable Hermes's A2A platform for the profile and give its one sending agent a named token:

   ```yaml
   platforms:
     a2a: {enabled: true, extra: {port: 9900}}
   platform_toolsets:
     a2a: [homeassistant]          # what delegated tasks may be offered at all
   ```

   In the profile's `.env`: `A2A_PEER_TOKENS=agent-a:<token>`, `A2A_TRUSTED_PEERS=agent-a`, and
   `A2A_HOST=0.0.0.0` only if other machines must reach it. Leave `A2A_BEARER_TOKEN` unset.
3. Pin that sender and trust the operator root that issues its warrants:

   ```yaml
   plugins:
     entries:
       hermes-tenuo:
         a2a_ingress:
           enabled: true
           peers: {agent-a: "<A's public key>"}      # the name from A2A_PEER_TOKENS
           trusted_roots: ["<operator root public key>"]
           revocation_list: ~/.hermes/tenuo/revocations.srl   # optional
   ```

4. Run `hermes-tenuo a2a check`, then restart the gateway.

Use one receiver per sending agent until [upstream #146669](https://github.com/NousResearch/hermes-agent/issues/146669)
is fixed. Hermes serves `ListTasks` and `GetTask` before the plugin's dispatch hook and shares
those reads among authenticated peers. Protected ingress requires one named token identity
matching the sole pinned peer. A configuration mismatch blocks inbound message dispatch.
Use a dedicated receiver and keep that token private.

Every inbound A2A message without a valid delegation is dropped before it reaches the agent. Keep
`hermes-tenuo` the only plugin using `pre_gateway_dispatch` on this agent.

## Set up the delegating agent (A)

A needs an enforcing warrant (`warrant`, `TENUO_SIGNING_KEY`, `trusted_root`) that allows
`tenuo_delegate` and covers what it will delegate. Then pair the peer:

```yaml
plugins:
  entries:
    hermes-tenuo:
      a2a_delegation:
        peers:
          home:
            url: http://home-hermes:9900/
            public_key: "<B's key from hermes-tenuo a2a key>"
            token_env: A2A_TOKEN_HOME      # holds the token B issued to agent-a
        max_ttl_seconds: 900
```

Enable the `tenuo` toolset for the platforms where the agent should delegate
(`hermes tools enable tenuo --platform <platform>`).

## The tool

`tenuo_delegate(peer, task, tools, ttl_seconds)`. `tools` lists, per tool, a rule for every argument:

| Rule | Meaning |
|---|---|
| `{"equals": v}` | exactly this string or number |
| `{"one_of": [a, b]}` | one of these strings or numbers |
| `{"range": [lo, hi]}` | a number in this range |
| `{"pattern": "light.*"}` | a glob |
| `{"regex": "^…$"}` | a regular expression |
| `{"any": true}` | any value, but the argument must be given |
| `"*": {"any": true}` | other arguments allowed (only if A's own warrant allows that) |

```json
{"peer": "home", "task": "Turn on the guest room light.", "ttl_seconds": 300,
 "tools": {"ha_call_service": {"domain": {"equals": "light"}, "service": {"one_of": ["turn_on", "turn_off"]},
                               "entity_id": {"equals": "light.guest_room"}, "*": {"any": true}}}}
```

Every argument a rule names must be present on each call; list optional arguments only when you need
to limit them, and use `"*"` to let the peer pass the rest. The result says what the peer replied and
the grant it used. A failed send is not retried, because the task may have run.

## Delegated tasks that use MCP servers

When the receiving agent reaches a service through a Tenuo-wrapped MCP server
([MCP wrapper](mcp-wrapper.md)), its calls carry the delegated chain and the wrapper verifies it again,
independently of the agent. Grant the wrapper's tool names (`files__write_file`) in `tenuo_delegate`
and set `mcp_proofs.servers` on the receiving agent.

## Revoke

Revoke a grant or a sender's whole warrant (everything delegated from it) with the operator root key:

```sh
hermes-tenuo a2a revoke <warrant-or-grant-id> --root-key root.key --list revocations.srl
```

Copy the file to each receiver's `revocation_list` path; it is re-read on change. The format is the
one the MCP wrapper reads as `revocations.srl`, so one list can serve agents and wrapped MCP servers
that trust the same root. A configured list
that is missing, not signed by a trusted root, or older than the last one refuses every delegation.

## Limits

- One delegated task per A2A conversation; each `tenuo_delegate` call opens a new one.
- A sender sees a dropped task as an empty reply (`refused_or_empty`), not a reasoned refusal.
- The receiving agent's model still runs for an admitted task on its own credentials.
- Tested with Hermes v0.22.6.


The receiver persists the accepted revocation-list version and content digest. A different list at
that same version is refused, including after restart; publish a strictly newer signed list to update
revocations. If upgrading a preview workspace whose saved version has no digest, publish a newer list
before resuming delegated work. Do not delete the saved state to recover.
