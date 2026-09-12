---
name: tenuo-scope
description: Scope Hermes cron, delegate_task, and gateway sessions with per-call warrants and traced delegation.
version: 1.1.0
author: Tenuo AI
license: Apache-2.0
metadata:
  hermes:
    tags: [tenuo, warrant, authorization, delegation, cron, delegate_task, gateway, kanban]
---

# Scope a Hermes agent with Tenuo

Load this skill when the user wants to limit what a Hermes agent may call,
or when they are about to add `delegate_task`, cron, kanban, or a
multi-user gateway.

The plugin checks **this call's tool name and arguments** in
`pre_tool_call` before the handler runs. Denials come back as the tool
result. A `delegate_task` child should be a **grant from the parent
warrant** (`grant_builder`), verified as a chain. Cron jobs and gateway
users each carry their own warrant.

Do the work. Do not tell the user to "be careful with `terminal`."

## When to use

- New or existing Hermes install that should not have the full tool set
- A cron / scheduled job that should die with its TTL
- `delegate_task` / subagents (researcher, writer, reviewer)
- Telegram / Discord / Slack gateway with more than one user
- Kanban workers that should not inherit the install-wide warrant
- After a surprise tool call: tighten from the audit log

If they only want to see a denial, run `hermes-tenuo demo` and stop.

## Decide the pattern first

Ask which of these is true. Do not mint a single install-wide warrant
and reuse it for all four.

| Situation | Pattern | Warrant lives on |
|---|---|---|
| One agent, one job, a time box | **Cron** | `warrant` + TTL |
| Parent calls `delegate_task` | **Child session** | parent `warrant` + `child_warrant` |
| Concurrent users on a gateway | **Per-session** | `guard.set_session_warrant(session_id, …)` |
| Kanban / queued worker | **Per-task file** | `~/.hermes/tenuo/warrants/<task_id>.warrant` |

A chat agent, a nightly job, and a Telegram user are three warrants.

## Rules (do not skip)

1. **Issuer ≠ agent.** Mint with a control key. The agent holds only
   `TENUO_SIGNING_KEY` (the holder). The plugin gets `trusted_root`
   (the issuer public key). Never put the issuer secret on the agent.
   Never mint from inside a tool handler.
2. **Constrain arguments, not just tool names.**
   `--allow read_file` is an open read of the machine.
   `--allow read_file:path=/data/reports` is a job.
3. **TTL is the job window.** Cron for one hour → `--ttl 1h`. A
   research child → minutes, not the parent's remaining day. Default
   `24h` is wrong for unattended jobs.
4. **Do not hand a child the parent's warrant.** Mint a grant from the
   parent (`grant_builder`) to the child's holder and attach it with
   `set_session_warrant(..., parent_warrant=parent)` so the hop is
   verified as a chain. Config `child_warrant` is a separately minted
   file for simple installs — prefer a grant when you care about the
   chain.
5. **No `terminal` / `execute_code` on a child or cron warrant**
   unless the user explicitly asked and the command/path is
   constrained. The plugin does not see inside an `execute_code`
   script (`subprocess.run` still runs).
6. **Signing keys stay in env or a secret source**, never in
   `config.yaml`. Under `gateway.multiplex_profiles`, put `TENUO_*`
   in that profile's `.env`.
7. **Discover, then enforce.** `on_denial: log` +
   `hermes-tenuo audit --denied` to see what the job actually calls.
   Switch back to `block` (the default) before you call it done.
   Do not ship `log`.
8. **`hermes-tenuo doctor` after every config change.** Enabled with
   no warrant is a no-op — the plugin loads and enforces nothing.

## Mint

```bash
hermes-tenuo mint --ttl 1h \
  --allow read_file:path=/data/reports \
  --allow write_file:path=/tmp/nightly \
  --allow memory
```

Paste the printed block into `plugins.entries.hermes-tenuo`. Export
`TENUO_SIGNING_KEY`. Run `hermes-tenuo doctor`.

| Syntax | Meaning |
|---|---|
| `tool` | any arguments — last resort |
| `tool:arg=/path` | that path or under it (traversal-safe) |
| `tool:arg=glob*` | glob |
| `tool:arg=a\|b\|c` | one of the choices |
| `tool:arg=value` | exact |
| `tool:arg=*` | that argument may be anything |
| `tool:a=..,b=..` | several constraints on one tool |

`--allow memory` and `--allow todo` are still tools. Add them only if
the job needs them. For numeric ranges or case-insensitive paths, mint
in Python with `Range`, `Subpath`, `Pattern` (see the repo README).

## Pattern: cron

TTL matches the schedule. Tools are the job, not the interactive agent.

```bash
hermes-tenuo mint --ttl 1h \
  --allow read_file:path=/data/reports \
  --allow write_file:path=/tmp/nightly \
  --allow memory
```

If the process is still running when the TTL ends, further tool calls
deny. That is the point.

## Pattern: `delegate_task` (grant from the parent)

This is the traced hop. The orchestrator holds a warrant minted by the
control key. It **grants** `web_search` to a different holder. Attach
the grant with `parent_warrant=` so the guard verifies control →
orchestrator → researcher.

```python
researcher_warrant = (
    orchestrator_warrant.grant_builder()
    .capability("web_search", query=Wildcard())
    .holder(researcher_key.public_key)  # different identity
    .ttl(300)
    .grant(orchestrator_key)
)
guard.set_session_warrant(
    child_session_id,
    researcher_warrant,
    researcher_key,
    parent_warrant=orchestrator_warrant,
)
```

The child cannot be the same key that grants (`holder ≠ issuer` on
that hop). Do not copy the parent warrant bytes into the child session.

`examples/subagent_scope.py` and `hermes-tenuo demo` are the runnable
form.

Config `child_warrant` is a separately minted file for simple
installs. The plugin injects it on `subagent_start`, but that file is
**not** a grant from the parent — no chain is verified. Prefer
`grant_builder` when the hop matters.

```yaml
plugins:
  entries:
    hermes-tenuo:
      warrant: ~/.hermes/tenuo/orchestrator.warrant
      child_warrant: ~/.hermes/tenuo/researcher.warrant  # convenience, not a chain
      trusted_root: <base64>
```

If the child itself calls `delegate_task`, grant *that* hop from the
researcher's warrant. Do not reuse the orchestrator grant.

## Pattern: gateway (concurrent users)

The single-agent child heuristic is **not safe** when two users are
in flight. User B's session must not be treated as a child of User A.

- Do not set a static `warrant` for the whole gateway.
- On session start: mint or load that user's grant, then
  `guard.set_session_warrant(session_id, warrant)`.
- On session end: `guard.clear_session_warrant(session_id)`.

Role examples: admin (`read_file` under `/data` + write), analyst
(reports + search), viewer (`/data/public` + search). Unknown user →
no warrant → blocked once any session warrant has been set
(`require_session_warrant`, on by default). Set
`require_session_warrant: false` only if unknown sessions should
pass through.

`examples/gateway_multiuser.py` is the runnable form.

## Pattern: kanban worker

Mint onto the path the worker loads:

```bash
hermes-tenuo mint --task <task_id> --ttl 2h \
  --allow read_file:path=/data/that-card
```

That writes `~/.hermes/tenuo/warrants/<task_id>.warrant` for the
current holder (`TENUO_SIGNING_KEY` if set). A worker with no file
is blocked entirely — it must not fall back to the install-wide
warrant. A denial marks the task blocked on the board.

## Tighten from reality

```yaml
plugins:
  entries:
    hermes-tenuo:
      warrant: ~/.hermes/tenuo/warrant
      trusted_root: <base64>
      on_denial: log
```

```bash
hermes-tenuo audit --denied
```

Add the missing `--allow` lines the job actually needed, **remove**
`on_denial: log`, run `hermes-tenuo doctor`.

## Anti-patterns

- One warrant for chat + cron + gateway + kanban
- `--allow terminal` or `--allow execute_code` "so the agent can debug"
- `--allow read_file` with no `path=`
- `child_warrant` copied from `warrant` (same bytes)
- `set_session_warrant` skipped on a multi-user gateway
- Issuer secret in the agent environment
- `TENUO_SIGNING_KEY` in `config.yaml`
- Plugin enabled, `warrant` unset (silent no-op)
- Leaving `on_denial: log` after the discovery pass
- Asking the model to stay inside `/data` instead of constraining `path=`

## Verify

```bash
hermes-tenuo demo      # cron / delegate_task / gateway transcript
hermes-tenuo doctor    # wiring, holder match, enforcement path
hermes-tenuo audit --denied
```

Blocked calls look like this to the model — the handler did not run:

```text
Constraint 'path' not satisfied: value does not match constraint
```
