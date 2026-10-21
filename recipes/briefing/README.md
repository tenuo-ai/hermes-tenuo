# Morning briefing

The daily briefing is the most common Hermes cron job: search the web, read a
few pages, write a summary, deliver it to Telegram or Slack. This warrant lets
it run every day without you approving anything, and limits it to exactly that.

Hermes already turns off messaging tools in cron and delivers the result through
the job's own `deliver` setting. What the warrant adds: the job can't read your
files (the kind of call that once sent a `~/.hermes/.env` to a model provider),
can't write outside its notes folder, can't run commands, and can't call any MCP
tool you have configured, because none of those are on it.

[`warrant.yaml`](warrant.yaml): `web_search` and `web_extract` with any
arguments, and `write_file` under one folder, for 30 days.

## Set it up

```bash
hermes cron list                       # the job's ID, e.g. 1a2b3c
hermes-tenuo setup                     # if you haven't: observe mode
cp recipes/briefing/warrant.yaml briefing.yaml   # set the folder
tenuo-cli warrant issue --template briefing.yaml --holder agent --out briefing.warrant
tenuo-cli session attach --session cron_1a2b3c --file briefing.warrant
tenuo-cli mode enforce
```

Reissue before the 30 days are up: `tenuo-cli warrant reissue --id <warrant id> --ttl 30d`.

## What it allows and refuses

| Call | Result |
|------|--------|
| `web_search`, `web_extract`, any arguments | allowed |
| `write_file` to `/home/you/briefings/2026-10-22.md` | allowed |
| `read_file ~/.hermes/.env` | refused: Tool 'read_file' is not authorized |
| `write_file ~/.bashrc` | refused: Constraint 'path' not satisfied |
| `terminal "cat ~/.ssh/id_rsa"` | refused: Tool 'terminal' is not authorized |
| `send_message` to another chat | refused: Tool 'send_message' is not authorized |
| an MCP tool, e.g. `mcp__github__push_files` | refused: not authorized |

## Limits

What the summary says, and which pages it reads, are up to the model; the
warrant decides what the job can touch, not what it writes.
