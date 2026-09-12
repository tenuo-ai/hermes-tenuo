# hermes-tenuo

**Give each Hermes agent a signed, expiring permission slip. Nothing outside it runs.**

Hermes agents run unattended: cron jobs, `delegate_task` subagents, gateway
users on Telegram or Discord, kanban workers. Each one gets the full tool set,
so one poisoned web page or one over-eager subagent has the same blast radius
as you do at the keyboard.

hermes-tenuo puts a [Tenuo](https://github.com/tenuo-ai/tenuo) **warrant** in
front of every tool call. A warrant is a signed grant that says which tools
this agent may call, with which arguments, until when. The plugin checks each
call against it before the handler runs. The agent cannot widen its own
warrant, a subagent can only receive a narrower one, and when the TTL ends the
job ends with it.

```text
read_file  path=/data/q3.md      ✓ allowed
read_file  path=/etc/passwd      ✗ Constraint 'path' not satisfied
terminal   command=ls            ✗ Tool 'terminal' is not authorized
```

Everything runs locally: keys, warrants, and every decision. No account, no
network, no proxy, no changes to your tools. It is a normal Hermes plugin.

## Quickstart (two minutes)

**1. Install.**

```bash
hermes plugins install tenuo-ai/hermes-tenuo
# or, into the venv Hermes uses:
pip install "git+https://github.com/tenuo-ai/hermes-tenuo.git"
```

Requires Hermes Agent 0.20.x (tested against upstream, September 2026) and
`tenuo>=0.3.0`, which is pulled in automatically.

**2. Mint a warrant.** This generates a key pair and a warrant, and prints
the exact config block to paste.

```bash
hermes-tenuo mint --ttl 1h \
  --allow read_file:path=/data \
  --allow web_search
```

```yaml
# ~/.hermes/config.yaml   (printed by the command above)
plugins:
  enabled:
    - hermes-tenuo
  entries:
    hermes-tenuo:
      warrant: <base64>            # or a path to a .warrant file
      trusted_root: <base64>       # the public key that signed it
      signing_key_env: TENUO_SIGNING_KEY
```

```bash
export TENUO_SIGNING_KEY=<printed by mint>
```

**3. Check the wiring, then run Hermes.**

```bash
hermes-tenuo doctor
hermes
```

Ask the agent to read `/etc/passwd` or run a shell command. It gets a denial
as the tool result and the handler never executes:

```text
Constraint 'path' not satisfied: value does not match constraint
Tool 'terminal' is not authorized
```

## Scoping arguments

Each `--allow` names a tool and, optionally, constraints on its arguments.
A tool with no constraints is allowed with any arguments.

| Syntax | Meaning | Example |
|---|---|---|
| `tool` | any arguments | `--allow web_search` |
| `tool:arg=/path` | argument must be that path or under it (traversal-safe) | `--allow read_file:path=/data` |
| `tool:arg=glob*` | argument must match the glob | `--allow web_search:query=acme*` |
| `tool:arg=a\|b\|c` | argument must be one of the choices | `--allow git:action=status\|diff\|log` |
| `tool:arg=value` | argument must match exactly | `--allow write_file:mode=w` |
| `tool:arg=*` | that argument may be anything | `--allow memory:action=*` |
| `tool:a=..,b=..` | several constraints on one tool | `--allow write_file:path=/tmp/out,mode=w` |

Any argument the warrant does not name is unconstrained for that tool. The
`--ttl` flag takes `30m`, `1h`, `7d`, and so on (default `24h`).

For anything the flag syntax cannot express, mint in Python with the full
constraint set (numeric ranges, case-insensitive paths, and more):

```python
import base64, os
from tenuo import SigningKey, Warrant, Subpath, Pattern, Range

control_key = SigningKey.generate()   # keep private; its public key is trusted_root
agent_key = SigningKey.generate()     # export its secret as TENUO_SIGNING_KEY

warrant = (
    Warrant.mint_builder()
    .holder(agent_key.public_key)
    .capability("read_file", path=Subpath("/data"))
    .capability("web_search", query=Pattern("acme*"))
    .capability("scale_cluster", replicas=Range.max_value(10))
    .ttl(3600)
    .mint(control_key)
)

path = os.path.expanduser("~/.hermes/tenuo/warrant")
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    f.write(base64.b64encode(warrant.to_bytes()).decode())
```

Point `warrant:` at that file. Set `trusted_root` to the base64 of
`control_key.public_key.to_bytes()` and `TENUO_SIGNING_KEY` to the base64 of
`agent_key.secret_key_bytes()`.

## What it unlocks

| Scenario | What you do | What you get |
|---|---|---|
| **Cron and scheduled agents** | Mint with `--ttl` matching the job window | The job cannot keep acting after it should be done, even if it is still running |
| **Subagents via `delegate_task`** | Set `child_warrant` to a narrower warrant | Every child session gets the narrow warrant automatically; a researcher cannot suddenly `write_file` |
| **Multi-user gateways** | Call `guard.set_session_warrant(session_id, warrant)` when a session starts | Per-user permissions, isolated per session, cleared on session end |
| **Kanban workers** | Drop `~/.hermes/tenuo/warrants/<task_id>.warrant` | The worker loads its own warrant; a denial auto-blocks the task on the board |
| **Fleet rollout** | Pin `warrant`, `trusted_root`, `on_denial` in managed scope | Users cannot loosen them from `~/.hermes/config.yaml` |

Runnable versions of the first three live in
[`examples/`](https://github.com/tenuo-ai/hermes-tenuo/tree/main/examples).

## See what your agent actually calls

Every decision is appended to a local JSONL audit log, on by default at
`~/.hermes/tenuo/audit.jsonl` (profile-aware under `HERMES_HOME`). No account
needed.

```bash
hermes-tenuo audit --last 20          # one line per tool call
hermes-tenuo audit --denied           # only what the warrant blocked
hermes-tenuo audit --json | jq ...    # raw records
```

```text
2026-09-12 10:00:00  ALLOW  read_file  path=/data/q3.md
2026-09-12 10:00:01  DENY   terminal  command=ls  — Tool 'terminal' is not authorized
```

Not sure what to allow yet? Set `on_denial: log`. Every call is still
checked and recorded, but nothing is blocked. Run the agent, read the denied
lines, tighten the warrant, then remove the line (the default is `block`).

```yaml
plugins:
  entries:
    hermes-tenuo:
      warrant: ~/.hermes/tenuo/warrant
      trusted_root: <base64>
      on_denial: log
```

## How it works

| Hermes hook | What hermes-tenuo does there |
|---|---|
| `pre_tool_call` | Verifies the tool name and arguments against the session's warrant. On denial, returns `{"action": "block", "message": ...}`; the handler never runs. |
| `post_tool_call` | Adds timing to the recorded decision and writes the audit record. |
| `subagent_start` | Hands the `child_warrant` to the new child session. |
| `on_session_end` | Clears any per-session warrant set with `guard.set_session_warrant()`, so gateway users never share one. |

The decision itself runs in Tenuo's Rust core: signature, expiry, holder
proof-of-possession, and every argument constraint. The plugin holds only the
issuer's **public** key. It never sees the key that minted the warrant.

Denials are returned to the model as the tool result, so the agent can
explain what it was not allowed to do. Raise the `hermes_tenuo` logger level
to see the same lines as an operator.

## Coverage

On upstream Hermes, enforcement runs at `pre_tool_call`. That covers every
tool call made through the agent loop, including the tools `run_agent.py`
handles before the registry (`todo`, `memory`, `session_search`,
`delegate_task`). It does not cover:

- callers that pass `skip_pre_tool_call_hook=True`;
- plugins that call `registry.dispatch()` directly;
- the `execute_code` sandbox's internal tool dispatch.

A registry-level hook that closes all three is proposed upstream in
[hermes-agent#32719](https://github.com/NousResearch/hermes-agent/pull/32719).
The plugin detects it at load time and uses it automatically, and
`hermes-tenuo doctor` reports which path is active.

Neither path inspects what an `execute_code` script does on its own, such as
`subprocess.run(...)`. Use a container backend (Docker, Modal, Daytona) for
that threat model.

## CLI

```bash
hermes-tenuo mint --allow TOOL[:ARG=VALUE,...] [--allow ...] [--ttl 1h] [--output full|yaml|env]
hermes-tenuo status      # what the plugin will load from config and env
hermes-tenuo verify      # decode and check the current warrant
hermes-tenuo doctor      # end-to-end install check
hermes-tenuo audit [--last N] [--denied] [--json] [--path FILE]
```

Run `doctor` from the same venv Hermes uses. It checks plugin discovery,
config wiring, warrant validity, that the signing key matches the warrant
holder, and which enforcement path is active. Run it after every install.

## Configuration reference

All keys live under `plugins.entries.hermes-tenuo`. Each has an environment
variable equivalent.

| Key | Env | Meaning |
|---|---|---|
| `warrant` | `TENUO_WARRANT` | Base64 warrant, or a path to a file containing one. Required for enforcement. |
| `trusted_root` | `TENUO_TRUSTED_ROOT` | Base64 public key of the issuer. Warrants signed by anything else are rejected. |
| `signing_key_env` | | Name of the env var holding the agent's Ed25519 secret key. Default `TENUO_SIGNING_KEY`. |
| `child_warrant` | `TENUO_CHILD_WARRANT` | Warrant handed to sessions spawned by `delegate_task`. |
| `on_denial` | | `block` (default) or `log`. |
| `audit_log` | `TENUO_AUDIT_LOG` | Path of the JSONL audit log, or `false` to disable. Default `$HERMES_HOME/tenuo/audit.jsonl`. |
| `connect_token` | `TENUO_CONNECT_TOKEN` | Optional. Connects the plugin to Tenuo Cloud (see below). |

Keep secret key material in env vars or a secrets manager, never in
`config.yaml`.

## Things to know

- **Enabled but unconfigured is a no-op.** Without a `warrant`, the plugin
  loads, logs a warning, and enforces nothing. `doctor` fails that check.
- **Multiplexed profiles.** Under `gateway.multiplex_profiles`, `TENUO_*`
  values are read through Hermes `get_secret`, so put each profile's keys in
  that profile's `.env`. A secondary profile does not inherit the launch
  profile's credentials.
- **Rotate by re-minting.** The control key is not saved by `mint`. To change
  scope, mint a new warrant and replace the config values; the old warrant
  stops being accepted when you change `trusted_root`, or when its TTL ends.

## Managed scope (fleet and multi-user)

Hermes overlays a root-owned `/etc/hermes/config.yaml` on every user's
config. hermes-tenuo reads its keys through the same loader, so an
administrator can pin the warrant and trust anchor for the whole fleet:

```yaml
# /etc/hermes/config.yaml  (root-owned)
plugins:
  entries:
    hermes-tenuo:
      warrant: /etc/hermes/tenuo/fleet.warrant
      trusted_root: <base64>
      on_denial: block
```

Pin `warrant`, `trusted_root`, and `on_denial`. Leave `signing_key_env` to
the environment. Override the managed directory with `HERMES_MANAGED_DIR` for
containers or non-standard layouts.

## Tenuo Cloud (optional)

Everything above works without an account. If you want a hosted control
plane, set `connect_token` and the plugin can stream the same audit events, fetch
Cloud-issued warrants (`hermes-tenuo mint --trigger <id>`), and wait on human
approval gates. Details at [tenuo.ai](https://tenuo.ai).

## Listing in the Hermes plugin catalog

Submit `docs/plugin-index-entry.json` with `ref` set to the commit you want
reviewed. Catalog installs pin that commit.

## License

Apache-2.0
