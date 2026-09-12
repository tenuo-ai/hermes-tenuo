# hermes-tenuo

[![CI](https://github.com/tenuo-ai/hermes-tenuo/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/hermes-tenuo/actions/workflows/ci.yml)
[![Upstream Hermes](https://github.com/tenuo-ai/hermes-tenuo/actions/workflows/upstream-hermes.yml/badge.svg)](https://github.com/tenuo-ai/hermes-tenuo/actions/workflows/upstream-hermes.yml)

**Give each Hermes agent a signed, expiring permission slip. Nothing outside it runs.**

See it without installing Hermes or talking to a model:

```bash
pip install hermes-tenuo
hermes-tenuo demo
```

```text
A nightly job gets a permission slip: read /data/reports,
write /tmp/nightly, then stop. Nothing else runs.
No Hermes process, no API key.

== Cron ==
The job does the work. Then it tries to leave the slip.
  ALLOW  read_file  path=/data/reports/q3.csv
  ALLOW  write_file  path=/tmp/nightly/report.md
  DENY   read_file  path=/etc/passwd
         Constraint 'path' not satisfied: value does not match constraint  ← /etc/passwd is not under /data/reports
  DENY   terminal  command=ls
         Tool 'terminal' is not authorized  ← terminal is not on the slip

That slip is a Tenuo warrant: signed, expiring, checked before
the handler runs. Same check, two more shapes:

== delegate_task ==
Same rule, after a handoff. The researcher was only granted web_search.
  [orchestrator] ALLOW  read_file  path=/data/input.csv
  [orchestrator] ALLOW  delegate_task  task=research q3  context=web_search only
  [researcher] ALLOW  web_search  query=AI papers 2026
  [researcher] DENY   write_file  path=/data/output/x.md
         Tool 'write_file' is not authorized  ← the researcher was not granted write_file

== Gateway ==
Same server, two slips.
  [analyst] ALLOW  read_file  path=/data/reports/q1.csv
  [analyst] DENY   write_file  path=/data/output/x.txt
         Tool 'write_file' is not authorized  ← write_file is not on the analyst's slip
  [viewer] ALLOW  read_file  path=/data/public/faq.md
  [viewer] DENY   read_file  path=/data/reports/q1.csv
         Constraint 'path' not satisfied: value does not match constraint  ← /data/reports is not on the viewer's slip
```

A [Tenuo](https://github.com/tenuo-ai/tenuo) warrant is that slip. Each Hermes
tool call is checked against it — tool name and arguments — before the
handler runs. A `delegate_task` child only gets what the parent granted. A
gateway user carries their own slip. Keys and decisions stay local.

The plugin returns the denial as the tool result, so the model sees why
the handler never ran:

```text
read_file  path=/etc/passwd
Constraint 'path' not satisfied: value does not match constraint
```

For a recorded session with a real model and a planted prompt injection,
see [docs/walkthrough.md](docs/walkthrough.md).

## Install into Hermes

**1. Install.**

```bash
# into the venv Hermes uses (pulls in tenuo):
pip install hermes-tenuo

# or as a directory plugin under ~/.hermes/plugins:
hermes plugins install tenuo-ai/hermes-tenuo
pip install "tenuo>=0.3.0"   # Hermes does not install plugin dependencies
```

To run the latest unreleased code instead: `pip install "git+https://github.com/tenuo-ai/hermes-tenuo.git"`.

Requires Hermes Agent 0.20 or newer. A nightly job loads the plugin through the plugin loader of upstream Hermes `main`, both install routes; the badge above is its latest result.
The pip route installs `tenuo>=0.3.0` for you; the directory route needs the
extra `pip install` line above.

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

Ask the agent to read `/etc/passwd`. It gets the same denial as the tool
result. Load `skill_view("hermes-tenuo:tenuo-scope")` to mint a warrant
for a cron job, a `delegate_task` child, or a gateway session.

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
| **Subagents via `delegate_task`** | Grant from the parent (`grant_builder`) | The child hop is verified as a chain; a researcher cannot suddenly `write_file` |
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
hermes-tenuo demo        # local allow/deny transcript (no Hermes process)
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

## Connecting a control plane (optional)

Everything above runs from files and environment variables on one machine.
That is the right shape for one developer and a handful of agents. Once you
run a fleet of Hermes agents, cron jobs, and gateway users, the hard part
stops being the check itself and becomes operating the authority around it:
who may mint production warrants, how keys rotate, how a bad warrant is
pulled back before its TTL ends, and where you look when something was
denied at 3 a.m. A Tenuo control plane takes that over.

When `TENUO_CONNECT_TOKEN` is set, the Tenuo SDK inside this plugin connects
on its own and every allow and deny decision from every Hermes agent streams
there, with nothing else to configure. On top of that stream the control
plane gives you:

- **Revocation before expiry.** Pull a warrant, a key, or an agent the moment
  something looks wrong instead of waiting for the TTL. Revocation lists are
  published to every verifier.
- **Central issuance and rotation.** Mint per-job warrants from policy rather
  than by hand, and rotate root and holder keys on a schedule without
  touching each agent's environment.
- **Human approval gates.** Route calls to sensitive tools to a person, so
  the agent can proceed only with a signed approval.
- **One searchable audit trail.** Signed receipts from every agent, session,
  and profile in one place, instead of one `audit.jsonl` per machine.

Tenuo Cloud is the managed version of that control plane. See
[tenuo.ai](https://tenuo.ai) for access, or the Tenuo repo for running your
own.

## License

Apache-2.0
