# hermes-tenuo

Cryptographic warrant enforcement for [Hermes Agent](https://github.com/NousResearch/hermes-agent). Scope your autonomous agents — cron jobs, sub-agents, gateway users — to exactly the tools and paths they need. No tool call runs outside what you explicitly authorized.

Works standalone. [Tenuo Cloud](https://cloud.tenuo.ai) is optional — it adds a warrant builder that learns from your agent's real call patterns, plus a dashboard and audit log.

## Install

```bash
pip install hermes-tenuo
```

## Enable

```yaml
# ~/.hermes/config.yaml
plugins:
  enabled:
    - hermes-tenuo
  entries:
    hermes-tenuo:
      warrant: ~/.hermes/tenuo/warrant   # path to your warrant file
      # signing_key_env: TENUO_SIGNING_KEY  # env var holding your Ed25519 key
```

That's it. On the next `hermes` start, every tool call is verified against the warrant before execution.

## Create a warrant

```python
from tenuo import SigningKey, Warrant, Subpath, Wildcard

control_key = SigningKey.generate()   # your control plane key
agent_key = SigningKey.generate()     # your agent's key (export as TENUO_SIGNING_KEY)

warrant = (
    Warrant.mint_builder()
    .holder(agent_key.public_key)
    .capability("read_file", path=Subpath("/data"))
    .capability("web_search", query=Wildcard())
    .capability("memory", action=Wildcard(), key=Wildcard())
    .ttl(3600)
    .mint(control_key)
)

# Save to file:
import base64
with open("~/.hermes/tenuo/warrant", "w") as f:
    f.write(base64.b64encode(warrant.to_bytes()).decode())
```

Or use `hermes-tenuo mint` (requires Tenuo Cloud):

```bash
export TENUO_WARRANT=$(hermes-tenuo mint --ttl 1h \
  --allow read_file:path=/data \
  --allow web_search \
  --allow memory)
```

## Use cases

- **Cron agents** — warrant with TTL; expires when the job should be done, blocking anything further
- **Subagents** — set `child_warrant`; children spawned by `delegate_task` get the narrower warrant automatically
- **Multi-user gateways** — call `guard.set_session_warrant(session_id, warrant)` per user; sessions are isolated

See [full documentation](https://tenuo.ai/docs/hermes) and [examples](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/hermes).

## With Tenuo Cloud (optional)

Connect to Tenuo Cloud to let the warrant builder learn your agent's real call patterns and generate tight warrants automatically:

```yaml
plugins:
  entries:
    hermes-tenuo:
      connect_token: tc_live_...   # from Tenuo Cloud dashboard → Quick Connect
      warrant: ~/.hermes/tenuo/warrant
```

With only `connect_token` and no `warrant`, the plugin runs in **audit-only mode** — every tool call is logged to Cloud for pattern learning, nothing is blocked. Add `warrant` to activate enforcement.

## License

MIT
