# Morning briefing

The daily briefing is the most common Hermes cron job: search the web, read a
few pages, write a summary, deliver it. This warrant lets it run every day with
nobody approving anything, reading and writing only its own notes folder.

What Hermes already does: cron jobs get only the toolsets you enable, messaging
tools are off in cron, and the job's `deliver` setting sends you the result.
`HERMES_WRITE_SAFE_ROOT` can keep writes under one directory, but for the whole
process, not this job, and Hermes has no read sandbox. What the warrant adds:
this job reads and writes only its folder (other jobs and your chats aren't
affected), can't run commands or call MCP tools, and stops after 30 days.

[`warrant.yaml`](warrant.yaml): `web_search` and `web_extract` with any
arguments; `read_file` and `write_file` under the notes folder.

## Set it up

```bash
hermes cron list                       # the job's ID, e.g. 1a2b3c
tenuo-cli hermes setup                     # if you haven't: observe mode
curl -O …/recipes/briefing/warrant.yaml   # set the folder
tenuo-cli warrant issue --template warrant.yaml --holder agent --out briefing.warrant
tenuo-cli hermes session attach --session cron_1a2b3c --file briefing.warrant
tenuo-cli mode enforce                 # see "Before you switch to enforce" in the index
```

Before the 30 days are up: `tenuo-cli warrant reissue --id <warrant id> --ttl 30d`,
then attach the new warrant.

## What it allows and refuses

| Call | Result |
|------|--------|
| `web_search`, `web_extract`, any arguments | allowed |
| `read_file` / `write_file` under `/home/you/briefings` | allowed |
| `read_file ~/.hermes/.env` or `…/briefings/../.ssh/id_rsa` | refused: Constraint 'path' not satisfied |
| `write_file ~/.bashrc` | refused: Constraint 'path' not satisfied |
| `terminal "cat ~/.ssh/id_rsa"` | refused: Tool 'terminal' is not authorized |
| `send_message` to another chat | refused: Tool 'send_message' is not authorized |
| an MCP tool, e.g. `mcp__github__push_files` | refused: not authorized |

## Limits

`web_extract` may fetch any URL, which is the job. That also means text the
model has in context (its memory, your profile, the notes it read) could be sent
out in a URL if a page talks it into that; the warrant decides which tools and
folders the job can touch, not what it puts in a request.
