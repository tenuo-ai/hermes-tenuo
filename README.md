# hermes-tenuo

Tenuo authorization plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

Streams every tool call to [Tenuo Cloud](https://cloud.tenuo.ai) for audit and policy learning. Activates cryptographic warrant enforcement once a warrant is configured.

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
      connect_token: tc_live_...   # paste from Tenuo Cloud dashboard
```

That's it. Tool calls start flowing to Cloud immediately. Tenuo Cloud's warrant builder learns your agent's real call patterns and generates a tight warrant for you to review and activate.

## Activate enforcement

Once Cloud has generated a warrant:

```yaml
plugins:
  entries:
    hermes-tenuo:
      connect_token: tc_live_...
      warrant: ~/.hermes/tenuo/warrant   # path or base64
```

Now `pre_tool_call` blocks anything outside the warrant scope.

## Use cases

- **Cron agents** — warrant with TTL; expires when the job should be done
- **Subagents** — attenuated child warrant; children can't exceed parent scope
- **Multi-user gateways** — per-session warrants; different users get different capabilities

See [docs/hermes.md](https://tenuo.ai/docs/hermes) for full documentation.

## License

MIT
