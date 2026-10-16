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
  DENY   read_file  path=/opt/private/payroll.csv
         Constraint 'path' not satisfied: value does not match constraint  ← /opt/private/payroll.csv is not under /data/reports
  DENY   terminal  command=ls
         Tool 'terminal' is not authorized  ← terminal is not on the slip
  (one second later)
  DENY   read_file  path=/data/reports/q3.csv
         Warrant has expired  ← the job window ended

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
read_file  path=/opt/private/payroll.csv
Constraint 'path' not satisfied: value does not match constraint
```

For a recorded session with a real model and a planted prompt injection,
see [docs/walkthrough.md](docs/walkthrough.md).

## Install into Hermes

**1. Install.** hermes-tenuo is in the
[Hermes plugin catalog](https://hermes-agent.nousresearch.com/docs/plugins/hermes-tenuo),
so this installs the reviewed, pinned commit:

```bash
hermes plugins install hermes-tenuo
hermes plugins enable hermes-tenuo
```

`install` asks for `TENUO_WARRANT` and `TENUO_SIGNING_KEY`. You mint those
in the next step, so leave both empty for now. `enable` installs the `tenuo`
dependency into the Hermes runtime.

If you manage the Hermes venv yourself, `pip install hermes-tenuo` into it
instead. That also puts the `hermes-tenuo` command on your path, so you can
drop the `uvx` prefix below. To run the latest unreleased code:
`pip install "git+https://github.com/tenuo-ai/hermes-tenuo.git"`.

Requires Hermes Agent 0.20 or newer. A nightly job loads the plugin through
the plugin loader of upstream Hermes `main` using both install routes; the
badge above is its latest result.

**2. Mint a warrant.** This generates a key pair and a warrant, and prints
the exact config block to paste.

```bash
uvx hermes-tenuo mint --ttl 1h \
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

Put the printed `TENUO_SIGNING_KEY` in `~/.hermes/.env`. Hermes reads that
file when it starts. The `uvx` command below does not, so export the same
value in this shell before the check:

```bash
export TENUO_SIGNING_KEY=<printed by mint>
```

**3. Check it, then start Hermes.** Run these in order:

```bash
hermes plugins doctor hermes-tenuo
uvx hermes-tenuo doctor
hermes
```

- `hermes plugins doctor hermes-tenuo` — Hermes loads the plugin and registers
  its hooks. This does not look at your warrant. If it cannot find the plugin,
  go back to step 1.
- `uvx hermes-tenuo doctor` — checks the config you pasted, the warrant, its
  expiry, and that the signing key matches the warrant holder. Fix anything it
  marks with `✗` before you start Hermes. This command runs outside Hermes, so
  it does not report the enforcement path.
- `hermes` — start the agent.

If you installed with `pip install hermes-tenuo` into the same environment
Hermes uses, drop the `uvx` prefix. `hermes-tenuo doctor` then also prints
which enforcement path is active.

Ask the agent to read `/opt/private/payroll.csv`. It gets the same denial as the tool
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
| `tool:arg=MIN..MAX` | argument must be a number in that range, inclusive | `--allow checkout:amount=0..4000` |
| `tool:arg=value` | argument must match exactly | `--allow write_file:mode=w` |
| `tool:arg=*` | that argument may be anything | `--allow memory:action=*` |
| `tool:a=..,b=..` | several constraints on one tool | `--allow write_file:path=/tmp/out,mode=w` |

A range only matches numbers: an amount sent as the string `"40.00"` is
denied, so declare such arguments as numbers in the tool schema. Give both
ends; `0..4000` also rules out negative amounts. Only a complete numeric
`MIN..MAX` value is treated as a range, so values such as
`release..candidate` continue to be exact strings. Tenuo ranges use
IEEE-754 numbers; the CLI rejects non-finite bounds and values outside the
safe integer range (`-9007199254740991` to `9007199254740991`).

Any argument the warrant does not name is unconstrained for that tool. The
`--ttl` flag takes `30m`, `1h`, `7d`, and so on (default `24h`).

A number range is `--allow checkout:amount=0..4000` (both ends, inclusive).
For a case-insensitive path, or anything else the flag cannot express, mint
in Python:

```python
import base64, os
from tenuo import SigningKey, Warrant, Subpath, Pattern

control_key = SigningKey.generate()   # keep private; its public key is trusted_root
agent_key = SigningKey.generate()     # export its secret as TENUO_SIGNING_KEY

warrant = (
    Warrant.mint_builder()
    .holder(agent_key.public_key)
    .capability("read_file", path=Subpath("/data", case_sensitive=False))
    .capability("web_search", query=Pattern("acme*"))
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
| **Multi-user gateways** | Call `guard.set_session_warrant(session_id, warrant)` when a session starts | That user's tools follow that warrant until the session ends. Tool calls from inside `execute_code` still follow the config warrant |
| **Kanban workers** | `hermes-tenuo mint --task <id> --allow ...` | Writes `~/.hermes/tenuo/warrants/<id>.warrant` for the current holder; a denial auto-blocks the task on the board |
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

Hermes asks hermes-tenuo before each agent-loop tool handler runs
(`pre_tool_call`). The coverage below describes current upstream Hermes
`main`, exercised by the **Upstream Hermes** badge. Hermes 0.20 and later can
load the plugin, but older releases may not route tool calls made inside
`execute_code` through this hook. On an older or unverified build, do not
grant `execute_code` to an agent or session whose isolation depends on
hermes-tenuo.

On current Hermes `main`, that includes every tool call in the agent loop,
the tools Hermes handles before its registry (`todo`, `memory`,
`session_search`, `delegate_task`), and tool calls an `execute_code` script
makes through Hermes, such as `read_file` or `web_search`. A caller that passes
`skip_pre_tool_call_hook=True` has already been through this check.

Those `execute_code` calls are checked against the warrant in your config
(`TENUO_WARRANT`, or `plugins.entries.hermes-tenuo.warrant`). Hermes does
not send the gateway session id with them, so a warrant you attached with
`set_session_warrant` is not the one applied. On a gateway, leave
`execute_code` off a session warrant when that session must stay narrower
than the config warrant.

Two things stay outside this check:

- Another plugin calling `ctx.dispatch_tool()`. That goes straight to
  `registry.dispatch()` and skips the hook. Only install plugins you trust
  alongside hermes-tenuo. A registry-level hook that closes this gap is
  proposed upstream in
  [hermes-agent#32719](https://github.com/NousResearch/hermes-agent/pull/32719).
  When Hermes provides it, hermes-tenuo uses it automatically.
- What an `execute_code` script runs on its own, such as
  `subprocess.run(...)`. Use a container backend (Docker, Modal, Daytona)
  for that.

## CLI

```bash
hermes-tenuo demo        # local allow/deny transcript (no Hermes process)
hermes-tenuo mint --allow TOOL[:ARG=VALUE,...] [--allow ...] [--ttl 1h] [--task ID] [--output full|yaml|env]
hermes-tenuo status      # what the plugin will load from config and env
hermes-tenuo verify      # signature (if trusted_root is set), expiry, capabilities
hermes-tenuo doctor      # end-to-end install check
hermes-tenuo audit [--last N] [--denied] [--json] [--path FILE]
```

After a catalog install these commands are not on your path. Prefix each
one with `uvx `.

`uvx hermes-tenuo doctor` checks the config, warrant validity and expiry, and
that the signing key matches the warrant holder. Export
`TENUO_SIGNING_KEY` in that shell first, because `uvx` does not load
`~/.hermes/.env`. It does not report the enforcement path. Confirm Hermes
loaded the plugin with `hermes plugins doctor hermes-tenuo`. Run both after
every install.

## Configuration reference

All keys live under `plugins.entries.hermes-tenuo`. Each has an environment
variable equivalent.

| Key | Env | Meaning |
|---|---|---|
| `warrant` | `TENUO_WARRANT` | Base64 warrant, or a path to a file containing one. Required for enforcement. |
| `trusted_root` | `TENUO_TRUSTED_ROOT` | Base64 public key of the issuer. Required for enforcement: without it every call is blocked (logged instead under `on_denial: log`). Warrants and delegation chains signed by anything else are rejected. |
| `signing_key_file` | | Base64 holder private key file; alternative to environment configuration. Relative paths resolve under the profile home. |
| `trusted_root_file` | | Base64 issuer public key file; alternative to inline/environment trust configuration. |
| `signing_key_env` | | Name of the env var holding the agent's Ed25519 secret key. Default `TENUO_SIGNING_KEY`. |
| `child_warrant` | `TENUO_CHILD_WARRANT` | Warrant handed to sessions spawned by `delegate_task`. |
| `on_denial` | | `block` (default) or `log`. |
| `require_session_warrant` | `TENUO_REQUIRE_SESSION_WARRANT` | After any `set_session_warrant` call, sessions with no warrant are blocked. `true` / `false` override the auto default. |
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

### Separate holder identity and warrant issuance

The operator does not need the holder's private key. Create the holder identity
in the agent environment, keeping its private file there:

```sh
hermes-tenuo keygen --private-key holder.key --public-key holder.pub
```

Give only `holder.pub` to the operator. In the operator environment, create a
separate issuer identity once and issue a scoped warrant:

```sh
hermes-tenuo keygen --private-key issuer.key --public-key issuer.pub
hermes-tenuo mint --issuer-key issuer.key --holder-public-key holder.pub \
  --ttl 20m --allow 'read_file:path=/data/reports' --out reports.warrant
```

Key and warrant files use base64 text. Outputs are created atomically with
permissions `0600`; existing files are never overwritten. Store issuer private
keys outside the agent's accessible environment. No private key is printed by
these commands. Explicit issuance completely ignores `TENUO_SIGNING_KEY`.

Give the agent `reports.warrant` and the trusted `issuer.pub`. Configure
`warrant: /absolute/path/reports.warrant` and
`trusted_root_file: /absolute/path/issuer.pub` in the plugin entry. Set
`signing_key_file: /absolute/path/holder.key` for the agent's holder identity,
removing the old `signing_key_env` entry and `TENUO_SIGNING_KEY` environment value. Do not give the agent `issuer.key`.

Optional `--session-id ID` embeds a session binding in the signed warrant. It
neither discovers a running session nor attaches the warrant to one. Ordinary
static configuration still needs a restart after replacement. The original
`mint --allow ...` quickstart remains available; it combines provisioning and
issuance and prints a holder private key, so use it only in a trusted terminal.

### Declarative scope policies

Use a policy when a scope is worth reusing; ad hoc `mint --allow ...` remains
supported. A policy is a template, not approval or a signed warrant. It contains
no key locations, credentials, automatic renewal, or standing issuance authority.

Save `report-reader.yaml`:

```yaml
version: 1
name: report-reader
ttl: 20m
capabilities:
  read_file:
    path: {subpath: /data/reports}
  web_search:
    query: {pattern: 'example*'}
```

```sh
hermes-tenuo policy validate report-reader.yaml
hermes-tenuo policy show report-reader.yaml
hermes-tenuo mint --policy report-reader.yaml \
  --issuer-key issuer.key --holder-public-key holder.pub --out reports.warrant
# Explicit --ttl overrides the policy duration:
hermes-tenuo mint --policy report-reader.yaml --ttl 10m \
  --issuer-key issuer.key --holder-public-key holder.pub --out shorter.warrant
```

`mint --policy` and `--allow` are mutually exclusive. Without a policy duration
or explicit `--ttl`, mint uses 24 hours. `show` prints the validated typed JSON
snapshot; validation does not issue or install authority.

Every argument constraint has exactly one explicit type:

| Form | Meaning |
|---|---|
| `{exact: 'report.txt'}` | Exact string; quote numeric-looking strings |
| `{one_of: ['status', 'diff']}` | One of a nonempty list of strings |
| `{range: {min: 0, max: 100}}` | Inclusive numeric bounds; numeric strings do not match |
| `{pattern: 'example*'}` | Glob pattern |
| `{subpath: /data/reports}` | Traversal-safe absolute path prefix |
| `{wildcard: true}` | Explicitly unconstrained argument |

An empty tool mapping (`web_search: {}`) allows any arguments for that tool.
**Omitted arguments are unconstrained**, not forbidden. Omitted tools are not
granted. Required constrained arguments must be present at authorization time.
There is no environment expansion, home expansion, or template evaluation.
Unknown fields, duplicate keys, aliases, anchors, unsafe YAML tags, unsupported
versions, empty capabilities, invalid durations, and invalid bounds are rejected.
Range bounds must be finite and within ±9,007,199,254,740,991.

The editor schema for versions 1 and 2 is [policy.schema.json](hermes_tenuo/schemas/policy.schema.json)
and ships in the Python package. `policy validate` is authoritative, including
cross-field checks such as minimum not exceeding maximum.

### Dynamic session warrants (opt in)

Static `warrant` configuration remains the default. To publish multiple grants to
individual conversations without restarting Hermes, configure:

```yaml
plugins:
  entries:
    hermes-tenuo:
      session_warrants_dir: /path/to/operator-published/sessions
      signing_key_env: TENUO_SIGNING_KEY
      trusted_root: <issuer-public-key-base64>
```

The operator writes this directory; the agent should have **read-only** access.
Keep the issuer private key outside the agent's accessible environment. A local
file protocol also works when the operator and Hermes use the same machine.
Directory isolation is still important: possession of a warrant does not itself
prove that an operator intended to attach it to a particular conversation.

```sh
hermes-tenuo attach diagnostic.warrant --session example-session
hermes-tenuo sessions --session example-session
hermes-tenuo status  # dynamic configuration health, not runtime activation
hermes-tenuo doctor
hermes-tenuo detach WARRANT_ID --session example-session
# Replace one grant atomically, retaining other attached warrants:
hermes-tenuo attach renewed.warrant --session example-session --replace OLD_WARRANT_ID
```

These commands use the configured directory, or an explicit `--directory PATH`.
Session identifiers are opaque: the storage layer hashes them rather than using
them as paths. A request/approval integration can supply the originating session
without requiring users to discover its identifier manually.

Attachments survive subsequent turns and gateway restarts. The next protected
call reloads a bounded atomic membership snapshot, then checks issuer trust,
holder proof, signature, expiry, and arguments using Tenuo enforcement. One
attached warrant must authorize the **entire** call; constraints from separate
grants are never combined. A corrupt or expired grant cannot hide another valid
grant. Signed session restrictions, when present, must match the session.

An empty directory, missing session, unreadable/invalid manifest, or absence of
any authorizing grant blocks execution. Session mode always enforces denials;
it does not use `on_denial: log`, inherit the static warrant, or automatically
pass authority to child sessions. Each child needs explicit attachments.
Legacy in-memory session APIs and static deployment behavior are unchanged.

`attach` reports **published**, not confirmed loaded: runtime verification occurs
before the next call. `sessions` shows published IDs and expiration, not verified
activation. The local audit decision identifies the selected warrant on ALLOW.
Detach prevents later calls in that session; it cannot cancel an operation
already authorized or revoke other copies of the signed warrant. The directory
is not a sandbox, and these changes do not add new enforcement coverage to
Hermes execution paths that bypass its existing tool hooks.


Replacement requires a valid, unexpired candidate with the same holder and issuer
as the attached grant. Failed validation leaves session membership unchanged.
Identity/trust rotation is a separate explicit operation; `--replace` does not
silently rotate keys. Runtime verification still checks the configured trust and
tool constraints before each call.


For recovery of an already-issued artifact, `attach --expected-id WARRANT_ID`
rejects a substituted file before publication. This does not mint a new warrant.

Relative `session_warrants_dir` paths resolve under the active Hermes profile home
(`HERMES_HOME` outside Hermes), independent of the working directory. Explicit CLI
`--directory` paths use the shell's working directory.

`sessions` reports malformed individual grants as `invalid` with their SHA-256
fingerprint; unrelated valid grants remain inspectable and removable. Attachment
and replacement retain malformed entries for diagnosis. To remove all authority
from a session, including recovery from an invalid JSON manifest, run:

```sh
hermes-tenuo clear-session --session example-session
```

This publishes an empty manifest without decoding the old contents. Symlinks are
rejected, and other sessions remain unchanged. Detachment/clearing affects future
checks, not already authorized operations or copies attached elsewhere.

New directories and manifests default to permissions `0700` and `0600`. For a
separate agent OS user, provision a shared read group, make the directory `0750`
with the appropriate group, and set each published manifest to `0640` before
agent use. Atomic updates preserve existing ownership and read permissions;
failed ownership preservation leaves the previous manifest intact. Group- or
world-writable manifests are rejected. Keep the directory operator-writable only
and mount it read-only into the agent. These commands require Unix file locking.

## Request authority, approve outside Hermes

A request is an unsigned snapshot, not authority. Create one ad hoc without a
policy file, or replace `--allow` with `--policy report-reader.yaml`:

```sh
hermes-tenuo request create --holder-public-key reader.pub --session research-session \
  --description 'Read the quarterly report' --ttl 20m \
  --allow 'read_file:path=/data/reports' --out report.request.json
hermes-tenuo request show report.request.json
hermes-tenuo approve report.request.json --issuer-key issuer.key
```

Approval displays the exact recipient, session, duration and scope, then asks
for confirmation. Confirm the public holder fingerprint against the intended
agent identity; an untrusted request cannot establish its own identity. Use
`--yes` only when explicitly approving noninteractively. The issuer reads only
the holder public key. It signs the already-reviewed in-memory snapshot; edits
to the request file during review cannot change what is signed. Output defaults
to `report.request.warrant` and refuses overwrite; `--out` selects another file.
Requests never supply output paths or issuer credentials.

For the same-machine workflow, add `--attach` to approval. It publishes the signed
warrant to the request's session in configured `session_warrants_dir`; use
`--directory` for an explicitly selected local store. No execution ID lookup,
network service, or gateway restart is needed. Publication is not a runtime
acknowledgment: the running plugin verifies it before the next protected call.
Approval does not automatically retry a previously denied operation. Ask Hermes
to continue when ready. A new session receives no attachments automatically.

To let Hermes itself propose authority, configure both directories:

```yaml
plugins:
  entries:
    hermes-tenuo:
      session_warrants_dir: /srv/hermes-authority/sessions
      requests_dir: /srv/hermes-authority/requests
      signing_key_env: TENUO_SIGNING_KEY
      trusted_root: <issuer-public-key>
```

Include the plugin's `tenuo` toolset if your configuration restricts available
toolsets. `tenuo_request_authority(allow, ttl, description)` writes an unsigned
request and returns its path and external approval command. The recipient holder
and session come from runtime context, never model arguments. This one bounded
control operation can run without infrastructure authority; protected tools
remain denied until a signed warrant is attached. It neither signs nor attaches
warrants. Request scope strings use the same syntax as `mint --allow`.

Keep the issuer private key outside agent-accessible paths/tools. Give Hermes
write access to the request directory and read-only access to session membership;
use separate mounts or OS permissions. Running the operator and Hermes as the
same unrestricted OS account is not isolation. Operator approval works in a
separate terminal on the same machine; remote transport is optional deployment
work, not part of this protocol. The tool caps request size, scope count and
retained requests per session; archive old requests after review when needed.

Generated approval commands include the originating session store explicitly, so
approval from another terminal/profile does not select a different store by
accident. `approve --attach` displays and checks that destination before loading
the issuer key or signing. Missing configuration, invalid membership, and ordinary
write-permission failures therefore leave no newly issued warrant.

Preflight cannot prevent every later I/O failure. If publication fails after
signing, approval reports the issued warrant ID and a recovery `attach` command
with `--expected-id`. Retry that command rather than approving/signing again;
substituting another artifact is rejected. Publication still does not imply the
runtime has activated the warrant.

### Renew an existing grant

Renewal signs a new validity window; old copies are not revoked. It uses the
operator's issuer private key and the previous signed warrant;
it never needs the holder private key or a saved policy:

```sh
hermes-tenuo renew --from reports.warrant --issuer-key issuer.key \
  --ttl 20m --out reports-renewed.warrant
```

The previous issuer signature is checked even if the grant has expired. Renewal
preserves the holder public key, exact tool constraints, and signed session
binding. `--ttl` is required to approve the new lifetime explicitly. A new warrant ID and
validity window are created; the previous artifact remains valid until its own
expiry. Renewal does not attach authority or restart Hermes. Deliver and activate
the replacement separately.

This first renewal flow accepts simple root execution warrants. Delegated grants,
issuer grants, extensions (including approval gates), and additional restrictions
are rejected rather than silently removed. Use explicit reviewed issuance for
those cases or for changes to scope. Existing output files are never overwritten.

For dynamic sessions, activate the renewed grant without restarting the gateway:

```sh
hermes-tenuo attach reports-renewed.warrant --session example-session --replace OLD_WARRANT_ID
```

This atomically replaces only the previous grant's session membership, preserving
other attached warrants. The running plugin verifies the new grant before the
next protected call. Use `sessions --session example-session` to inspect published
IDs; old copies elsewhere remain subject to their original expiry.


### Load runtime keys from files

The plugin can read the holder private key and trusted issuer public key from
separate base64 text files. Keep the issuer **private** key outside the agent's
accessible environment. Only its public key belongs in this configuration:

```yaml
plugins:
  entries:
    hermes-tenuo:
      warrant: /path/to/agent.warrant
      signing_key_file: tenuo/holder.key
      trusted_root_file: tenuo/issuer.pub
```

These are explicit file settings, not inline key material. Relative paths resolve
under the active Hermes profile home (`HERMES_HOME`); absolute paths and `~` paths
also work. Each file must contain exactly one base64-encoded key, optionally with
a trailing newline. Keep the holder private file at permission `0600`; mount key
files read-only when using a container. Key values are never logged by file loading.
Files are bounded to 64 KiB and read at guard construction; restart Hermes after
rotating these identity files.

Choose one source for each key. `signing_key_file` conflicts with an explicit
`signing_key_env` or a defined `TENUO_SIGNING_KEY` secret. `trusted_root_file`
conflicts with `trusted_root` or a defined `TENUO_TRUSTED_ROOT` secret. Remove the
old source when migrating. Missing, invalid, or conflicting configured files
block enforcement initialization, including when no warrant is configured; they
never fall back to an environment key. Existing environment and inline-public-key
configuration continue working when the file settings are absent.

Run `hermes-tenuo status` to inspect configured sources and `hermes-tenuo doctor`
to validate loading and the holder/warrant match. These paths are operator
configuration, not agent-selected tool arguments.

## Human approval for an operation: send a file, sign it, bring it back

Issuing a warrant and approving an operation are different. `approve` issues new
session authority. `approvals sign` satisfies a human-approval gate already signed
into a warrant; it cannot expand that warrant. Everything below runs locally,
without an account, approval server, or Tenuo Cloud.

An approver has their own key, separate from the issuer and Hermes holder keys.
Generate it on the approver's machine and exchange only the public key:

```sh
hermes-tenuo keygen --private-key operator.key --public-key operator.pub
```

Use a version 2 policy to declare scope and approval gates:

```yaml
version: 2
name: service-maintenance
ttl: 20m
capabilities:
  get_service_status:
    service: {exact: example}
  restart_service:
    service: {exact: example}
approvals:
  keys:
    - ./keys/operator.pub
  gates:
    restart_service:
      always: true
```

Any one signature from a listed key satisfies local policy approval. There is no
`threshold` setting. Public-key paths resolve relative to the policy file, with
no environment or home interpolation. `always: true` gates every otherwise
permitted call to that tool. A gate without keys, an ungranted tool, unknown
fields, duplicate keys, or unsupported conditional syntax is a validation error.
Version 1 scope-only policies remain supported.

```sh
hermes-tenuo policy validate maintenance.yaml
hermes-tenuo policy show maintenance.yaml  # includes resolved key fingerprints
hermes-tenuo mint --policy maintenance.yaml --issuer-key issuer.key \
  --holder-public-key holder.pub --session-id example-session --out restart.warrant
hermes-tenuo attach restart.warrant --session example-session
```

Compare public-key fingerprints independently before trusting them. Minting
embeds the actual public keys and gates in the signed warrant; editing the YAML
or key files later does not change existing authority. Gated policies require
separate issuance; legacy convenience minting never silently drops their gates.
For ad hoc issuance, use `--require-approval TOOL --approver-public-key PATH`
instead of policy approvals. Combining policy approvals with CLI approval
settings is rejected.

`request create --policy maintenance.yaml` also preserves approval gates. It
snapshots public key contents into the portable authority request, so the issuer
reviews actual keys and never follows key-file paths supplied by a request.
Renewal still rejects gated warrants rather than dropping their restrictions;
explicitly issue a new warrant from the policy.

No identity registry is required. Existing `approver register NAME --public-key
PATH` and `--identity NAME` options remain optional conveniences for matching a
key to a local label. Names are unverified annotations; the cryptographic identity
is the key fingerprint. This is not a directory or certificate service. See
[the policy format and integration boundaries](docs/policy-format.md).

Enable the local file workflow in the Hermes profile:

```yaml
plugins:
  entries:
    hermes-tenuo:
      operation_requests_dir: tenuo/operation-requests
      operation_approvals_dir: /path/to/operator-published/operation-approvals
```

Both paths must be configured and separate. Relative paths use the active profile
home. Hermes writes requests; only the operator writes approvals. Keep approver
and issuer private keys outside Hermes. Mount the approval directory read-only
into an isolated agent, just like session membership. New directories/files are
`0700`/`0600`; provision shared read-group access for a separate agent OS user.
Approval reimports preserve existing ownership and read permissions. Static mode
requires `on_denial: block`; dynamic session mode always enforces.

When a gated tool call is attempted, its handler does not execute. Hermes gets a
useful block message with the request file and review command. Requests are
self-contained JSON containing the signed warrant and exact call arguments. Send
that file manually to the authorized person using your preferred transport;
it may contain sensitive arguments. The recipient needs no running Hermes and
receives no issuer or holder private key. They independently trust the issuer's
public key, review, and sign:

```sh
hermes-tenuo approvals show restart.operation.json --trusted-root issuer.pub
hermes-tenuo approvals sign restart.operation.json --key operator.key \
  --trusted-root issuer.pub --out operator.response.json
```

The CLI verifies the warrant signature, issuer, expiry, gate, recipient holder,
and request hash. It displays the exact arguments, fingerprints and
duration before asking for confirmation. `--yes` explicitly opts into
noninteractive signing. No paths supplied by a request select credentials or
output destinations. Only the reviewed in-memory snapshot is signed.

The recipient sends **only the response file** back. On the operator's machine:

```sh
hermes-tenuo approvals import restart.operation.json --response operator.response.json \
  --trusted-root issuer.pub
```

Import defaults to configured `operation_approvals_dir`; `--directory PATH` selects
an explicit store. Each response is verified before publication. Runtime also respects the signed
requirements on externally minted warrants; it never relaxes them to the local
policy default. Ask Hermes to retry. The next tool call loads signatures and
Tenuo verifies them before execution; **no gateway restart is needed**. Import is
publication, not confirmation of execution. Audit records include the verified
approver fingerprints and signed identity labels alongside the ALLOW decision.
Identity labels are claims signed by those keys, not proof of a person's name.

Approvals bind the exact warrant, holder, tool, and arguments. Their default TTL
is five minutes (`sign --ttl` overrides it), capped at the warrant's expiry.
**They are not single-use:** identical calls may repeat until expiry. Tenuo does
not track consumed nonces; changing the tool, arguments, holder or warrant needs
a different approval. Signed session restrictions still apply, and local response
publication is isolated per session. After expiry, sign a new response and import
it; if the warrant expired, issue a new warrant first. This first file workflow
supports root warrants; delegated chains need a future portable chain format.

Malformed, unauthorized, expired, or mismatched responses never satisfy a gate.
An independent valid grant can still authorize a call: a gate on one warrant is
not a global deny on another warrant. Pending requests reuse stable filenames,
with at most 100 per session; archive reviewed requests when that limit is reached.

## Inspect warrants and revoke authority locally

`warrants show` decodes an encoded warrant file or a full warrant ID found in
published session membership:

```sh
hermes-tenuo warrants list
hermes-tenuo warrants show WARRANT_ID
hermes-tenuo warrants show diagnostic.warrant
```

The JSON view shows the full ID, capabilities and argument constraints, holder
and issuer keys/fingerprints, expiry, signed session restriction, attachments,
approval gates/keys and revocation status. Constraints use SDK representations;
gate introspection uses SDK kinds and argument names. Opaque extension bytes are
retained as base64 rather than interpreted by a second policy engine. Signature
validity, root trust and revocation are separate fields. Delegated issuer trust
requires a complete chain at runtime; indirect revocation is unknown without
that chain, with direct ID membership shown separately. A single-file inspection
is not an activation or authorization verdict. Missing revocation information is `null`,
with an error if a configured source is unavailable.

`list` inventories published session attachments, **not every warrant ever
issued**. Unattached warrants can be inspected by file. `--directory` selects a
session store, `--trusted-root` selects an issuer public-key file, and
`--revocations-dir` selects revocation data; otherwise profile configuration is
used. Corrupt manifests are reported alongside the inventory.

Revocation uses Tenuo core's native **SignedRevocationList (SRL)** CBOR artifact,
created with its builder and verified by its authorizer. There is no Hermes SRL
wrapper, hosted service or additional signing identity requirement. Keep the SRL
signer's private key outside Hermes; the signer must be an explicitly trusted
root. To enable local revocation, first publish an initial empty list:

```sh
hermes-tenuo revocations create --issuer-key issuer.key --out initial.srl
hermes-tenuo revocations import initial.srl --trusted-root issuer.pub \
  --directory /path/to/operator-published/revocations
```

Configure the profile (relative paths resolve under its home):

```yaml
plugins:
  entries:
    hermes-tenuo:
      revocations_dir: /path/to/operator-published/revocations
```

The operator writes this directory; mount it read-only into Hermes. It contains
immutable, versioned native SRL files. New directories/files use `0700`/`0600`;
provision read permissions when operator and agent use different OS users.
Missing, corrupt, untrusted or rolled-back configured data blocks tool calls.
Static revocation mode requires `on_denial: block`; dynamic sessions always
enforce. Keep the published history across restarts; deleting/restoring the
operator's entire history is outside the agent's read-only boundary.

Find and inspect the warrant, then sign an updated list outside Hermes:

```sh
hermes-tenuo warrants list
hermes-tenuo warrants show WARRANT_ID
hermes-tenuo revocations create --issuer-key issuer.key --from initial.srl \
  --revoke WARRANT_ID --out updated.srl
hermes-tenuo revocations show updated.srl --trusted-root issuer.pub
hermes-tenuo revocations import updated.srl --trusted-root issuer.pub
```

`--from` retains existing revoked IDs and advances the signed version. Repeat
`--revoke` for multiple IDs. Creating a file alone changes no runtime; import
publishes it. The next protected call reloads it without restarting the gateway.
A revoked warrant remains attached and visible but cannot authorize calls;
reattaching the same artifact does not bypass the SRL. Detach still removes only
one session's attachment. Calls already authorized cannot be cancelled by this
check, and other verifiers must receive the updated SRL to enforce it.

You can also import an SRL produced directly by Tenuo core. Import checks signer
trust, signature and core's version/content rules before publication. A newer
SRL is an **authoritative replacement snapshot**, so external producers must
retain IDs they intend to keep revoked. Core may allow re-signing the same
version with the same IDs; this immutable local publication directory accepts
exact retries but requires a new version for changed artifact bytes. Older or
conflicting versions cannot replace the published list. No cross-integration
transport or shared-package refactor is introduced.
