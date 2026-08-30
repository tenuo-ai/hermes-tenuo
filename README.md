# hermes-tenuo

Cryptographic warrant enforcement for [Hermes Agent](https://github.com/NousResearch/hermes-agent). Scope your autonomous agents — cron jobs, sub-agents, gateway users — to exactly the tools and paths they need. No tool call runs outside what you explicitly authorized.

## Install

```bash
pip install "git+https://github.com/tenuo-ai/hermes-tenuo.git"
# or, from a Hermes-enabled venv:
hermes plugins install tenuo-ai/hermes-tenuo
```

Requires `tenuo>=0.2.3` (pulled in automatically) and **Hermes Agent 0.20.x**. Tested against upstream `NousResearch/hermes-agent` 0.20.x (August 2026) and the `tenuo-ai/hermes-agent` fork that includes `ToolRegistry.set_enforcement_fn`.

To list this plugin in the Hermes community catalog, submit `docs/plugin-index-entry.json` with `ref` set to the install commit SHA.

## Enable

```yaml
# ~/.hermes/config.yaml
plugins:
  enabled:
    - hermes-tenuo
  entries:
    hermes-tenuo:
      warrant: ~/.hermes/tenuo/warrant      # path to your warrant file
      trusted_root: <base64-issuer-pubkey>  # control plane public key
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

Or use `hermes-tenuo mint` to generate keys and a warrant locally:

```bash
hermes-tenuo mint --allow read_file --allow web_search --allow memory --ttl 1h --output full
# → prints keys + warrant + the config YAML block to paste
```

## Use cases

- **Cron agents** — warrant with TTL; expires when the job should be done, blocking anything further
- **Subagents** — set `child_warrant`; children spawned by `delegate_task` get the narrower warrant automatically
- **Multi-user gateways** — call `guard.set_session_warrant(session_id, warrant)` per user; sessions are isolated

See [examples](https://github.com/tenuo-ai/hermes-tenuo/tree/main/examples). This README is the documentation until a dedicated docs page is published.

## Verify it's working

After install, run `hermes-tenuo doctor` from the same venv Hermes uses. It checks plugin discovery, config wiring, warrant validity, signing-key/holder match, and reports which enforcement path is active.

```bash
hermes-tenuo doctor
#   ✓  tenuo_core importable
#   ✓  plugin entry point hermes_agent.plugins:hermes-tenuo registered
#   ✓  hermes-tenuo listed in plugins.enabled
#   —  plugins.entries.hermes-tenuo has 3 keys
#   ✓  warrant loaded
#   ✓  warrant not expired
#   ✓  signing key matches warrant holder
#   ✓  trusted_root set
#
#   Enforcement path: ToolRegistry.set_enforcement_fn (universal coverage)
```

If `doctor` reports the `pre_tool_call` fallback path instead, see **Limitations** below.

## Limitations & observability

**Coverage depends on the Hermes build you're running.**

| Hermes build | Enforcement path | Coverage |
|---|---|---|
| `tenuo-ai/hermes-agent` fork | `ToolRegistry.set_enforcement_fn` | Every `registry.dispatch()` call, including the `execute_code` sandbox path |
| Upstream `NousResearch/hermes-agent` | `pre_tool_call` plugin hook | Tool calls through the main agent loop. **Gaps:** callers that set `skip_pre_tool_call_hook=True`, plugins that invoke `registry.dispatch()` directly, and the `execute_code` sandbox dispatch path |

`pre_tool_call` is always registered, including on the fork, so tools that `run_agent.py` intercepts before the registry (`todo`, `memory`, `session_search`, `delegate_task`) stay gated.

Neither path inspects what happens *inside* an `execute_code` script — a script can still call `subprocess.run(...)` or `os.system(...)` directly. Use container/sandbox backends (Docker, Modal, Daytona) for that threat model.

Tracking issues / PRs: [hermes-agent#21849](https://github.com/NousResearch/hermes-agent/issues/21849), [hermes-agent#18148](https://github.com/NousResearch/hermes-agent/issues/18148), [hermes-agent#496](https://github.com/NousResearch/hermes-agent/issues/496).

**Quiet failure modes to know about.**

- *Plugin listed but not configured.* If `hermes-tenuo` is enabled but has no `warrant` or `connect_token`, the plugin loads and does not enforce. Startup now logs a WARNING, and `hermes-tenuo doctor` fails that check. Confirm with `doctor` after every install.
- *Audit-only mode.* With `connect_token` set and no `warrant`, every tool call is logged to Tenuo Cloud but nothing is blocked. This is intentional for the warrant-builder on-ramp — **do not use in production without a warrant.**
- *Denials are reported to the model, not the operator.* When a warrant blocks a tool, the message is delivered to the model as the tool result. Raise the `hermes_tenuo` log level to see operator-visible denial lines.
- *Cloud approval vs hook timeout.* Hermes fails closed if `pre_tool_call` exceeds `plugins.hook_callback_timeout` (default 30s). Cloud approval polls for up to 5 minutes, so a slow human approval looks like a warrant denial unless you raise or disable that timeout. See **With Tenuo Cloud** below.

## With Tenuo Cloud (optional)

Connect to [Tenuo Cloud](https://cloud.tenuo.ai) to let the warrant builder learn your agent's real call patterns and generate tight warrants automatically:

```yaml
plugins:
  entries:
    hermes-tenuo:
      connect_token: tc_live_...   # from Tenuo Cloud dashboard → Quick Connect
      warrant: ~/.hermes/tenuo/warrant
```

With only `connect_token` and no `warrant`, the plugin runs in **audit-only mode** — every tool call is logged to Cloud for pattern learning, nothing is blocked. Add `warrant` to activate enforcement.

Cloud approval waits inside `pre_tool_call` for up to 5 minutes. Hermes 0.20+ bounds that hook at `plugins.hook_callback_timeout` (default 30s) and **fails closed** on timeout ([#93824](https://github.com/NousResearch/hermes-agent/pull/93824)). If you use Cloud approval gates, raise the timeout to cover the poll window, or disable it:

```yaml
plugins:
  hook_callback_timeout: 300   # seconds; 0 disables the bound
```

`hermes-tenuo doctor` warns when `connect_token` is set and the timeout is still the 30s default.

## Managed scope (enterprise / multi-user)

Hermes ships a managed-scope layer (`/etc/hermes/config.yaml`, root-owned) that overlays administrator-pinned values on top of every user's `~/.hermes/config.yaml`. hermes-tenuo config keys read through the same loader, so managed scope is a reliable way to lock warrant and trust settings fleet-wide.

```yaml
# /etc/hermes/config.yaml  (root-owned, not user-writable)
plugins:
  entries:
    hermes-tenuo:
      warrant: /etc/hermes/tenuo/fleet.warrant
      trusted_root: <base64-issuer-pubkey>
      on_denial: block
```

Users cannot override these keys from their own `~/.hermes/config.yaml`. The managed file wins per-leaf while leaving unmanaged keys user-controlled.

**What to pin via managed scope**

| Key | Managed? | Notes |
|---|---|---|
| `warrant` | Yes | Fleet warrant path; individual users can't point at a wider warrant |
| `trusted_root` | Yes | Locks the issuer anchor; prevents swapping in a self-signed root |
| `on_denial` | Yes | Ensures `block` mode can't be softened to `log` by users |
| `connect_token` | Optional | Pin if all agents should log to the same Cloud workspace |
| `signing_key_env` | No | Private key material belongs in env vars or a secrets manager, not a config file |

**Activation**

The managed dir defaults to `/etc/hermes`. Override with `HERMES_MANAGED_DIR` for non-standard paths or containerised deployments:

```bash
HERMES_MANAGED_DIR=/opt/hermes/managed hermes chat
```

Run `hermes-tenuo doctor` to confirm which warrant is loaded — managed-scope overrides show up in the config path reported there.

## License

MIT
