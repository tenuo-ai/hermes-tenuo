# Recipes

Each recipe is a job people already run with Hermes, and a warrant that lets it
run without you watching. A warrant names the tools a conversation or cron job
may call and the argument values it may use (this repo, this thread, this
folder), for a set time. Anything it doesn't name is refused before the tool
runs.

| Recipe | You can now let Hermes… |
|--------|-------------------------|
| [Morning briefing](briefing/) | run a daily cron job that reads the web and one notes folder, and writes only there |
| [House-sitter](house-sitter/) | take your house-sitter's messages on your own bot: guest-room lights and scene, ending with their stay |
| [Work on issues](work-on-issues/) | take issues in one repo to pull requests: `agent/*` branches, PRs into `main`, never a merge |
| [Review PRs](review-prs/) | let a second agent review the PRs you name: read and comment, never approve or push |
| [Reply to a thread](reply-to-thread/) | send the reply itself instead of a draft: one thread, one recipient, one hour |
| [Project task](project-task/) | work in one repo: files under the project, exactly the commands you list |

What Hermes already does, and where these fit: Hermes can limit a cron job's
toolsets, keep writes under one root for the whole process, refuse some
credential files, filter MCP tools by name, and with a Home Assistant entity
allowlist limit a profile to some devices. All of that is per profile or per
process, and none of it checks argument values, expires, or differs between the
people talking to the same bot. That's what a warrant adds.

## Before you switch to enforce

`tenuo-cli mode enforce` applies to every conversation and cron job in the
profile: anything without a warrant is refused. Either give the recipe its own
Hermes profile (`hermes profile create house`, with its own `local_home`), or
attach a warrant for yourself first (see [house-sitter/owner.yaml](house-sitter/owner.yaml)).

## The steps

```bash
tenuo-cli hermes setup                       # workspace, plugin on, observe mode: nothing blocked
# use Hermes as usual for a day or two
tenuo-cli calls summary                  # what it called, with which arguments, grouped by job or person
curl -O https://raw.githubusercontent.com/tenuo-ai/hermes-tenuo/main/recipes/<recipe>/warrant.yaml
# change the lines marked EDIT
tenuo-cli warrant issue --template warrant.yaml --holder agent --out job.warrant
tenuo-cli hermes session attach --session <who> --file job.warrant
tenuo-cli mode enforce                   # the next call is checked
```

`<who>` is one of:

- `cron_<job_id>` for every run of a cron job (`hermes cron list`)
- `<platform>:<user id>` for everything one person sends, e.g. `telegram:5550001`, the ID you
  already put in `TELEGRAM_ALLOWED_USERS`; `<platform>:<chat id>` for a group
- a session ID, for one conversation (`tenuo-cli calls list` shows them as `run`)

A session that has no warrant of its own uses the one it continues or was
delegated from, so subagents and compressed sessions keep their parent's.

Every argument a warrant names must be present and match, unless it's wrapped in
`optional`; every argument it doesn't name is refused; `{}` after a tool allows
any arguments. If a call is refused for an argument the recipe didn't expect, the
refusal names it, and observe mode shows it before anything is blocked.

Hermes' API server lets a client choose the session ID it uses. If you run it with
an enforced workspace, treat its API key like the warrants themselves: anyone
holding it can speak as any session.

These use the unreleased local CLI and optional arguments
([tenuo#970](https://github.com/tenuo-ai/tenuo/pull/970),
[tenuo#923](https://github.com/tenuo-ai/tenuo/pull/923)) and hermes-tenuo's
`local_home` mode ([#47](https://github.com/tenuo-ai/hermes-tenuo/pull/47)).
`tests/test_recipes.py` checks every recipe file as shipped.
