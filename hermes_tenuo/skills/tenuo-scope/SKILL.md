---
name: tenuo-scope
description: Mint a Tenuo warrant that scopes a Hermes cron job, delegate_task child, or gateway session to specific tools and arguments.
version: 1.0.0
author: Tenuo AI
license: Apache-2.0
metadata:
  hermes:
    tags: [tenuo, warrant, authorization, cron, delegate_task, gateway]
---

# Scope a Hermes agent with Tenuo

Load this skill when the user wants to limit what a Hermes cron job, `delegate_task` child, or gateway session may call.

Warrants are signed locally. No account. The plugin checks each tool name and arguments in `pre_tool_call` before the handler runs.

## Mint

```bash
hermes-tenuo mint --ttl 1h \
  --allow read_file:path=/data \
  --allow web_search
```

Paste the printed block into `~/.hermes/config.yaml` and export `TENUO_SIGNING_KEY`. Then run `hermes-tenuo doctor`.

## Constraint flags

| Syntax | Meaning |
|---|---|
| `tool` | any arguments |
| `tool:arg=/path` | path or under it (traversal-safe) |
| `tool:arg=glob*` | glob |
| `tool:arg=a\|b\|c` | one of the choices |
| `tool:arg=value` | exact |
| `tool:arg=*` | that argument may be anything |
| `tool:a=..,b=..` | several constraints on one tool |

## Which shape

**Cron.** TTL matches the job window.

```bash
hermes-tenuo mint --ttl 1h \
  --allow read_file:path=/data/reports \
  --allow write_file:path=/tmp/nightly \
  --allow memory
```

**`delegate_task` child.** Parent keeps its warrant. Put the narrower grant on `child_warrant`. Authority is traced across the child session.

```yaml
plugins:
  entries:
    hermes-tenuo:
      warrant: ~/.hermes/tenuo/orchestrator.warrant
      child_warrant: ~/.hermes/tenuo/researcher.warrant
      trusted_root: <base64>
```

**Gateway user.** No static warrant. When the session starts, call `guard.set_session_warrant(session_id, warrant)`. Clear it on session end.

## See a denial without chatting

```bash
hermes-tenuo demo
```

Blocked calls return the denial as the tool result. The handler does not run. `hermes-tenuo audit --denied` lists them.
