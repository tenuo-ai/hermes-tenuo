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
see [docs/walkthrough.md](walkthrough.md).

## Install into Hermes

Install hermes-tenuo 0.4.0 on the Hermes server:

```bash
hermes plugins install tenuo-ai/hermes-tenuo
hermes plugins enable hermes-tenuo
```

`install` asks for `TENUO_WARRANT` and `TENUO_SIGNING_KEY`. You mint those
in the next step, so leave both empty for now. `enable` installs the `tenuo` and `path-jail`
dependencies into the Hermes runtime.

If you manage the Hermes venv yourself, `pip install hermes-tenuo` into it
instead, pinned to `hermes-tenuo==0.4.0`. Use one route or the other: with both
a pip install and a plugin directory, the plugin blocks every tool call until
one is removed, and `hermes-tenuo doctor` reports the pair. That also puts the
`hermes-tenuo` command on your path, so you can drop the `uvx` prefix below.

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
  expiry, that the signing key matches the warrant holder, and that
  `trusted_root` is the issuer that signed the warrant. Fix anything it
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
A tool with no constraints is allowed with any arguments. Quote a value that
contains `*`, `?` or `|`, or the shell will interpret it.

| Syntax | Meaning | Example |
|---|---|---|
| `tool` | any arguments | `--allow web_search` |
| `tool:arg=/path` | argument must be that path or under it (traversal-safe) | `--allow read_file:path=/data` |
| `tool:arg=glob*` | argument must match the glob | `--allow 'web_search:query=acme*'` |
| `tool:arg=a\|b\|c` | argument must be one of the choices | `--allow 'git:action=status\|diff\|log'` |
| `tool:arg=MIN..MAX` | argument must be a number in that range, inclusive | `--allow checkout:amount=0..4000` |
| `tool:arg=value` | argument must match exactly | `--allow deploy:env=staging` |
| `tool:arg=*` | that argument must be present and may be anything | `--allow 'write_file:path=/tmp/out,content=*'` |
| `tool:a=..,b=..` | several constraints on one tool | `--allow 'deploy:env=staging,region=eu\|us'` |

A range only matches numbers: an amount sent as the string `"40.00"` is
denied, so declare such arguments as numbers in the tool schema. Give both
ends; `0..4000` also rules out negative amounts. Only a complete numeric
`MIN..MAX` value is treated as a range, so values such as
`release..candidate` continue to be exact strings. Tenuo ranges use
IEEE-754 numbers; the CLI rejects non-finite bounds and values outside the
safe integer range (`-9007199254740991` to `9007199254740991`).

Once a tool has any constraint, the warrant must name every argument the
call sends: a call carrying an argument the warrant does not name is denied.
`arg=*` accepts any value, and the argument must then be present. So Hermes's
`write_file`, which always sends `content`, needs
`--allow 'write_file:path=/tmp/out,content=*'`. A tool with optional arguments,
such as `read_file` with `offset` and `limit`, is allowed only when the call
sends exactly the named ones. To constrain some arguments and accept any
others, mint in Python with `_allow_unknown=True` (below).

The `--ttl` flag takes `30m`, `1h`, `7d`, and so on (default `24h`).

A number range is `--allow checkout:amount=0..4000` (both ends, inclusive).
For a case-insensitive path, optional arguments, or anything else the flag
cannot express, mint in Python:

```python
import base64, os
from tenuo import SigningKey, Warrant, Subpath, Pattern

control_key = SigningKey.generate()   # keep private; its public key is trusted_root
agent_key = SigningKey.generate()     # export its secret as TENUO_SIGNING_KEY

warrant = (
    Warrant.mint_builder()
    .holder(agent_key.public_key)
    # _allow_unknown: read_file may also send offset and limit
    .capability("read_file", path=Subpath("/data", case_sensitive=False), _allow_unknown=True)
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
| **Subagents via `delegate_task`** | Attenuate the parent's warrant for each child | Every child gets a fresh holder key and a verified chain; a researcher cannot suddenly `write_file` |
| **Multi-user gateways** | Add an [`access:`](#role-based-access-for-the-gateway) block of roles, or call `guard.set_session_warrant(session_id, warrant)` yourself | Each user's tools follow their role (or warrant) every turn. A cleared session is denied; it never falls back to the config warrant. Sessionless calls from `execute_code` are attributed by task id and blocked if ambiguous. |
| **Kanban workers** | `hermes-tenuo mint --task <id> --issuer-key issuer.key --holder-public-key holder.pub --allow ...` | Writes `~/.hermes/tenuo/warrants/<id>.warrant`, signed by the issuer the worker's `trusted_root` names; a denial auto-blocks the task on the board |
| **Fleet rollout** | Pin `warrant`, `trusted_root`, `on_denial` in managed scope | Users cannot loosen them from `~/.hermes/config.yaml` |

Runnable versions of the first three live in
[`examples/`](https://github.com/tenuo-ai/hermes-tenuo/tree/main/examples).

## Role-based access for the gateway

For a shared gateway (several people in one Telegram/Discord/Slack chat), an
`access:` block gives each person a role, with no code and no keys to manage:

```yaml
plugins:
  entries:
    hermes-tenuo:
      access:
        roles:
          owner:
            match: { user: ["telegram:12345", "discord:67890"] }
            allow:
              terminal:   { command: { binaries: ["git", "ls"] } }
              read_file:  { path: "/data/**" }
              write_file: { path: "/data/**" }
              web_search: {}
          analyst:
            match: { platform: ["telegram"] }
            allow:
              read_file:  { path: "/data/reports/**" }
              web_search: {}
          guest:
            default: true          # everyone not matched above
            allow:
              web_search: {}
        on_unmatched: guest
```

- **Who.** `match` lists `user`, `chat` and/or `platform` (all given
  dimensions must hold). `user` and `chat` are `"<platform>:<id>"`. Roles are
  tried in order, then the `default` role; `on_unmatched: deny` blocks a
  sender no role matches. At most one role may be the `default`. To deny
  unmatched senders in the example, remove the entire `guest` role
  and set `on_unmatched: deny`; an explicit deny cannot coexist with a default.
- **What.** `allow` maps a tool to its argument constraints. A tool mapped to
  `{}` (or listed in `allow: [web_search, read_file]`) is allowed with no
  constraints. An argument value is `"*"` (any), `"/path/**"` (any path under
  it), a literal, or `{ binaries: [...] }` / `{ patterns: ["^...$"] }` /
  `{ range: [min, max] }`. A constrained tool still accepts its other
  arguments unless the tool sets `strict: true`.
- **Per message, not per session.** Authority follows the message's sender,
  so in a shared chat each person is authorised as themselves — the user a
  model believes it is replying to never changes who a call runs as. A message
  with no single sender gets only the default role, or is denied.
- **Keys.** None to manage: the plugin signs the role warrants with a key it
  creates once under `$HERMES_HOME/tenuo/access.key` (set `TENUO_SIGNING_KEY`
  to use your own instead). `hermes-tenuo doctor` lists the roles and checks
  they compile.
- **Turns with no chat sender.** An API-server or webhook turn and a scheduled
  (cron) run have no person behind them. They match only a role that names
  their platform, for example `match: { platform: ["cron"] }` (`api_server`,
  `webhook`, `msgraph_webhook` and `cron`); otherwise they get the default
  role, or are denied. An identity such a caller supplies is not used. A role
  that allows `cronjob_manage` lets its members schedule runs with the `cron`
  role's tools, so keep that role no wider than the people who can schedule.
- **Allowed binaries.** `binaries` checks which program a command starts, not
  what the program then does. A program that runs other programs (`git`,
  `env`, `xargs`, `find`, an interpreter) gives the role those too.
- **Local turns.** A CLI, desktop or TUI turn is the operator and is not
  matched against roles. A static `warrant:` is optional and covers those
  turns; without one they are unrestricted unless `require_session_warrant` is
  enabled.
- **Children.** A `delegate_task` child gets a grant narrowed from its
  parent's role, valid for up to an hour from the moment it is delegated.
  This needs Hermes's live subagent attribution; an older build cannot spawn
  children under a role or a static or session warrant. A child whose
  lifecycle hook was missed is denied, and grants are never assigned by
  session order when access is enabled.

## Hands: let your server's agent use your own machine

**Start here:** [your first Hands session](hands-first-session.md) uses a disposable project,
permission presets and `/hands verify`. In chat, `/hands setup` explains server configuration
when Hands is off, or offers read/edit/online choices when it is ready. On your laptop,
`uvx hermes-tenuo hands demo` creates the practice project without pairing anything.


Your Hermes runs on a server, with its skills and memory. Your code is on your
laptop. Hands lets a conversation with that server run its commands and file
tools in one folder on the laptop, for a time you choose. It needs no
enforcement warrant and works alone.

**On the server**, give Hands an address and restart Hermes:

```yaml
plugins:
  entries:
    hermes-tenuo:
      hands:
        listen: "100.64.0.10:8765"            # where the server listens
        url: "http://100.64.0.10:8765"      # the address your machine can reach
```

**In a Hermes chat**, type `/hands invite`. It prints one line.

**On your machine**, in the folder you want to work in, run that line:

```bash
uvx hermes-tenuo hands up 'hands://my-server:8765/…' --dir . --for 4h
```

Commands on your machine have no internet. Add `--network` if the work needs
to install dependencies or download anything.

**Back in the chat**, the conversation that asked for the line starts using
your machine as soon as it is up: its `terminal`, `read_file`, `write_file`
and the other file tools act there. `/hands off` returns it to the server and
`/hands on` switches it back. Other conversations, bots and scheduled jobs are
not affected. On a chat platform that says who is writing, the machine is
yours: other people cannot see it, use it or forget it, and a message from
someone else in a shared chat does not run on it.

| Command | Where | What it does |
|---|---|---|
| `/hands setup [read\|edit\|online]` | chat | Guided setup and a one-hour permission preset. |
| `/hands verify` | chat | A read-only folder probe, with machine, permissions and time remaining. |
| `/hands invite` | chat | Prints the line to run on your machine. Works once, for 10 minutes. |
| `/hands on [name]` | chat | This conversation runs on that machine. |
| `/hands off` | chat | This conversation runs on the server again. |
| `/hands status` | chat | Which machines are up, and for how long. |
| `/hands revoke <name>` | chat | Forgets a machine; it needs a new invite. |
| `hermes-tenuo hands up [INVITE] --dir FOLDER --for 4h` | your machine | Shares one folder. The invite is only needed the first time. `--read-only` lets commands look at the folder without changing it. `--read FOLDER` shows them one more folder in your home folder; `--read-home` shows all of it. `--network` lets them use the internet. `--protect-git` (macOS) keeps them from changing git settings and hooks. |
| `hermes-tenuo hands check [INVITE] --dir FOLDER` | your machine | Says whether this machine is ready: the folder, the sandbox, whether the server can be reached. Pairs nothing and runs nothing. |
| `hermes-tenuo hands up [INVITE] --dir FOLDER --preview` | your machine | Shows sharing policy locally, without connecting, pairing, or creating a key. |
| `hermes-tenuo hands log` | your machine | What the server ran here. |

Before connecting, add `--preview` to the same `hands up` command. It shows the
server, folder, access duration, network setting, readable toolchains and extra
paths, and your personal exclusions. Preview does not probe server connectivity
or run the sandbox; use `hands check` for those checks.

To keep private files out of a shared project, create
`~/.config/hermes-tenuo/never-share` (or
`$XDG_CONFIG_HOME/hermes-tenuo/never-share` when that variable is absolute):

```text
# Literal paths relative to the shared project, or absolute paths
customers/
config/production.json
```

Every listed path must exist. Missing paths, unreadable rules, glob patterns and
negation are errors, never silently ignored. Rules apply to terminal commands
and file tools, override extra read access, and require a sandbox. On macOS
access is denied; on Linux files appear empty and directories are empty,
read-only mounts. Names may remain visible. Rules are fixed for a session;
stop and restart Hands after changing them. Protect the original path and any
existing copies or hard-link aliases separately. These rules control paths,
not all copies of the same information. A file that was committed stays readable
through the repository's history. Do not move excluded data from another
local process during a session.

Hands redacts recognized credentials from tool results on the device before
signing or sending them, and from commands recorded in its local log. It matches
common token formats, and the values (of at least six characters) of
secret-looking keys — secret, token, password, api key, credential and the like
— in both the launch environment and regular project-root `.env*` files up to
64 KiB. A value under an unrecognized key is not collected this way, though a
known token format or a URL credential in it is still matched.
Redacted text uses `[redacted]`; the local console reports redaction, and
ordinary terminal results include a notice. Hermes file-read base64 samples
are scrubbed along with their plaintext pages, preserving transport framing.
The current-directory field remains intact for tool routing. Files on disk are not rewritten.
This is best-effort detection: short values, fragments, encodings and unknown
formats can escape detection. Use exclusions for data that must not be shared.
Redaction does not restrict network traffic from commands started with
`--network`. Results still go to remote Hermes and may go to its model provider.
Older Hands clients do not gain these protections merely by upgrading the server.

Commands may change the shared folder, including its repository's own settings.
Git runs some of those as programs (hooks, `core.fsmonitor`, a pager, an alias),
for whoever uses git in the folder next and outside Hands. The laptop prints a
note when a command adds or changes one, and again when Hands stops; check
`.git/config` and `.git/hooks` before using git there yourself. Repositories in
subfolders are not watched. On macOS, commands cannot open other terminal
windows, read your preferences, or read other programs' temporary files.

To refuse those changes instead of reporting them, start with `--protect-git`
(macOS only). Wherever commands can write, in the shared folder and in their
temp folder:

- no repository can be created: `git init`, `git clone`, `git worktree add`
  and `git submodule add` fail, and so do tools and tests that make a
  repository in a temp folder;
- a repository's `.git` cannot be moved, replaced or pointed somewhere else;
- its settings (`.git/config`, `config.worktree`, `commondir`), its hooks
  folder, its submodules (`.git/modules`) and its records of other worktrees
  cannot be changed;
- for the shared folder's own repository, the files its settings include and
  the hooks folder they name (`core.hooksPath`) cannot be changed either.

So `git config`, `git remote add`, `git lfs install`, hook installers and work
inside a submodule fail. `git push -u`, checking out a remote branch and
`git branch -m` do their work and then say the settings could not be written
(pass `--no-track` to avoid the message). Commit, branch, checkout, merge,
rebase, stash, tag, diff, status, fetch, pull and push work as before, also in
a linked worktree or a repository in a subfolder that was already there.
Commands get a temp folder of their own for these sessions, so caches from
sessions without the flag are not reused.

Hands does not start with the flag when it cannot lock everything git reads
its settings from: the shared folder is itself a linked worktree or a
submodule checkout (`.git` is a file), the settings name a file or a hooks
folder that is missing or reached through a link, or a settings file or hook
has a second name (a hard link). `hermes-tenuo hands check --protect-git`
says which. Reporting stays on as well.

The flag keeps settings as they are when Hands starts; it does not examine
them. A hook or setting that was already there still runs what it names, so if
a hook is a link to a script in the project, or calls one, commands can change
that script. Not covered: files in the shared folder that your git settings
outside it name, what the settings of a repository in a subfolder pull in, a
bare repository that was already in the folder, and work a command left
unfinished (look at `git status` before continuing a rebase you did not
start).

On Linux the flag is refused. Git has to create and rename files in `.git`,
and bubblewrap can make existing files read-only but cannot refuse new names
in a folder that stays writable, so a lock there would not hold. Changes are
reported, as without the flag.

What your machine enforces, whatever the server asks:

- **One folder.** Commands run in one sandbox (`sandbox-exec` on macOS,
  bubblewrap on Linux) that can write only to the shared folder and a private
  temp folder. The rest of your home folder cannot be read: not your
  documents, not other projects, not application data. Your toolchains stay
  readable (rustup, pyenv, nvm, uv and similar, and folders on your `PATH`),
  and `--read FOLDER` adds a folder of your choice. With `--read-home` the
  home folder is readable except `~/.ssh`, `~/.aws`, cloud and package-manager
  credentials, keychains, browser profiles and shell history, which are never
  readable. System files stay readable.
- **No internet unless you say so.** Commands cannot open connections to the
  internet. Start with `--network` when the work needs it: installing
  dependencies, cloning, calling an API. Without it, Linux commands have a
  network of their own with nothing else on it, and macOS commands can reach
  only programs listening on the machine itself, which includes a proxy if
  one is running there. When an install fails for this reason the agent is
  told why, and can ask you to restart with `--network`. This limits what
  commands connect to, not what the server learns: the output of every
  command still goes back to the Hermes server, over Hands's own connection.
- **Nothing outside it.** Commands can signal only processes started through
  Hands. On macOS they cannot open apps, script other apps, start system jobs,
  or use the clipboard, the keychain, the SSH agent or the Docker socket; on
  Linux they do not get your session's sockets. Commands receive a small shell
  environment, not credentials or other variables exported by the process that
  started Hands. Their home folder is a private stand-in that starts with your
  git name and email, and they are told where your toolchains are (rustup,
  pyenv, nvm and similar), so builds and commits work as usual.
- **A time window.** When it ends, your machine stops answering. Run `hands up`
  again to continue; the conversation picks the machine up again by itself.
- **No late runs.** A command that reaches your machine after the server
  stopped waiting for it (the machine slept, the network stalled) is refused,
  not run. If your machine restarts with a command in hand, the server reports
  that the outcome is unknown rather than sending it again.
- **Results are retried after a dropped connection.** If the server cannot be
  reached when a command ends, your machine keeps the result in memory and
  retries while Hands is running. After normal expiry, commands stop and
  reporting alone may continue for up to two minutes. An explicit stop or
  device restart discards pending results. If it never arrives in the command's time, the agent
  is told the outcome is unknown and to check before running it again.
- **Only your server.** Your machine signs a warrant for the server's key.
  Every command arrives signed by that key and is checked on your machine
  before it runs. A changed, replayed or forged command is refused.
- **A record.** Each command and its exit code is printed where `hands up` runs
  and kept in `hermes-tenuo hands log`.
- **You can tell where it ran.** Every result of a command or file tool that ran
  on your machine names the machine and the folder. When the sandbox refuses
  something, the result says what the machine shares.
- **It survives a restart of Hermes.** A machine that is up pairs again by
  itself when the server comes back, with the same folder and the time it had
  left, and each conversation keeps the machine it was using. A machine you
  revoked does not. A conversation whose machine was renamed or revoked stays
  routed to the unavailable name until you select another machine or use `/hands off`.

The connection goes from your machine to the server, so a laptop behind a home
router needs no open port. Commands and results are signed but not encrypted
by Hands: use an `https://` address behind a reverse proxy, or a private
network such as Tailscale or WireGuard. Your machine refuses a plain
`http://` server that is not on a private network or the machine itself,
unless you pass `--plain-http`. If the server's certificate comes from your own
certificate authority, set `SSL_CERT_FILE` to that certificate on your machine
before `hands up`. The listener serves a limited number
of connections, and fewer from any one address, so put a reverse proxy in
front of it if it is reachable from the internet.

Interrupting a command in Hermes stops it on your machine. A process a command
leaves running (a dev server started with
`terminal(background=true)`) keeps running between commands and stops when
`hands up` stops. To stop it earlier, kill it by name or port from a later
command.

**Hands on Ubuntu.** Ubuntu 24.04 and later do not let bubblewrap start a
sandbox for an ordinary user until one rule allows it. `hands check` says so.
Install bubblewrap and add the rule once:

```bash
sudo apt install bubblewrap
printf 'abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n  include if exists <local/bwrap>\n}\n' | sudo tee /etc/apparmor.d/bwrap
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

Limits today: macOS and Linux machines only; on macOS commands can reach
services that listen on the machine itself (`localhost`), with or without
`--network`; on Linux without `--network` a dev server is reachable only from
other commands in the same Hands sandbox, and with it commands reach services
on the machine too. Linux `--network` requires enabled Landlock ABI 6 or later
(available starting with Linux 6.12) to block host abstract sockets; if the
restriction cannot be installed, commands do not start. `--network` is all or nothing, not a list of allowed
sites; a machine with no sandbox refuses
to start unless you pass `--no-sandbox`; on macOS `mktemp` needs an explicit
template under `$TMPDIR`; Hands lives in one Hermes process
(the gateway), so a separate `hermes` CLI process on the same server does not
see the machines; `/hands on` needs a Hermes version with tool-execution
middleware, and on older versions `terminal.backend: hands` switches a whole
profile.

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
| `subagent_start` | Attaches the one-time child grant staged by the authorised `delegate_task` call. An unexpected child gets no authority. |
| `on_session_end` | Hermes fires this after every turn. Drops per-turn delegation state and flushes receipts. A session's own warrant stays attached until `guard.clear_session_warrant()` or its expiry. |

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
hermes-tenuo hands up [INVITE] [--dir FOLDER] [--for 4h] [--name NAME] [--read-only] [--read FOLDER] [--read-home] [--network] [--protect-git]   # on your own machine
hermes-tenuo hands check [INVITE] [--dir FOLDER] [--protect-git]
hermes-tenuo hands log [--last N]
```

After a catalog install these commands are not on your path. Prefix each
one with `uvx `.

`uvx hermes-tenuo doctor` checks the config, warrant validity and expiry,
that the signing key matches the warrant holder, that `trusted_root` signed
the warrant, and that a configured delegation plan loads. Export
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
| `signing_key_env` | | Name of the env var holding the agent's Ed25519 secret key. Default `TENUO_SIGNING_KEY`. |
| `require_warrant` | | If `true`, a loaded plugin blocks calls when no warrant is configured, including under `on_denial: log`. Default `false` preserves unconfigured passthrough. |
| `child_warrant` | `TENUO_CHILD_WARRANT` | Scope template used to attenuate a fresh, parent-chained grant for each `delegate_task` child. |
| `delegation_plan` | `TENUO_DELEGATION_PLAN` | Path to a versioned JSON plan that narrows tools, arguments, and TTL at each delegation depth. Mutually exclusive with `child_warrant`. |
| `on_denial` | | `block` (default) or `log`. |
| `require_session_warrant` | `TENUO_REQUIRE_SESSION_WARRANT` | After any `set_session_warrant` call, sessions with no warrant are blocked. `true` / `false` override the auto default. |
| `audit_log` | `TENUO_AUDIT_LOG` | Path of the JSONL audit log, or `false` to disable. Default `$HERMES_HOME/tenuo/audit.jsonl`. |
| `hands.listen` | `TENUO_HANDS_LISTEN` | `host:port` the server listens on for your machines. Unset means Hands is off. |
| `hands.url` | `TENUO_HANDS_URL` | The address put in invites. Set it when machines reach the server by another name, or over `https://`. |

Keep secret key material in env vars or a secrets manager, never in
`config.yaml`.

### Delegation plans

Use a delegation plan when different depths of a subagent tree need different
authority. The plan can only narrow the signed parent warrant; Tenuo rejects a
child grant that would widen it. Per-task `toolsets` narrow the planned level
again, and every TTL is atomically capped to the parent's remaining lifetime.

```json
{
  "version": 1,
  "root": {
    "tools": {
      "terminal": {
        "command": {
          "binaries": ["kubectl"],
          "patterns": ["^kubectl (get|logs) .+ -n shop$"]
        }
      },
      "delegate_task": {}
    }
  },
  "levels": [
    {
      "role": "investigator",
      "ttl_seconds": 900,
      "tools": {
        "terminal": {
          "command": {
            "binaries": ["kubectl"],
            "patterns": ["^kubectl (get|logs) .+ -n shop$"]
          }
        }
      }
    }
  ]
}
```

The root warrant must use matching `All(...)` constraint structure; the
`hermes_tenuo.delegation.capability_members()` helper builds its members. Keep
the plan operator-controlled, as a regular file that is not a symlink and is
not group- or world-writable. Invalid or unreadable plans fail closed during
plugin startup.

Child grants are scoped to one `delegate_task` invocation. Unclaimed grants
expire when that call returns, including failed and background calls. Cancelled,
timed-out, or errored lifecycle posts reserve their goals for the lifetime of the
guard: retries must use distinct goals because abandoned workers can announce
children late. Without an originating call ID or goal, start a new session
after cancellation. Concurrent
invocations with overlapping child goals are rejected because Hermes does not
include the originating call ID in its child-start hook. Use distinct goals for
concurrent delegations. Control actions (`list`, `steer`, `stop`) create no grants.
A spawn denied by the warrant is blocked even under `on_denial: log`. Letting
it run could attach its child to another invocation’s pending grant. Ordinary
non-spawn calls retain log-only behavior.

## Things to know

- **General tool-call authorization is off without a warrant.** Hands can still
  run with its own device grants. The authorization `doctor` fails the missing-warrant check;
  use `hands check` and `/hands verify` for Hands.
  Set `require_warrant: true` under `plugins.entries.hermes-tenuo` to block
  calls instead. This requires the plugin to load successfully; it cannot
  detect its own absence. With a warrant configured, `on_denial` continues to
  select observation (`log`) or enforcement (`block`).
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
there, with nothing else to configure.

Install the cloud extra to also deliver each decision as a signed receipt:

```bash
pip install "hermes-tenuo[cloud]"
```

The extra applies on Python 3.13 and earlier. On Python 3.14, which Hermes's
managed install uses, it installs nothing: `tenuo-cloud` has no 3.14 build yet,
so decisions stream without signed receipts there.

A receipt is signed by the agent's key, carries the proof-of-possession
signature from the call it records, and links to the receipt before it, so a
removed or edited entry shows up as a broken chain. Receipts are flushed when
a session ends and when Hermes exits. Without the extra the plugin logs a
warning and streams decisions without receipts. Delivering receipts never
blocks or allows a call; the warrant check has already decided it.

On top of that stream the control plane gives you:

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
`trusted_root` to the base64 contents of `issuer.pub` in the plugin entry
(the trusted-root setting does not read a file path). Load the holder
private file into the agent's `TENUO_SIGNING_KEY` environment variable using your
secret manager. Do not give the agent `issuer.key`.

For a kanban worker, replace `--out` with `--task ID`. The warrant is written
to `~/.hermes/tenuo/warrants/ID.warrant` and replaces any earlier one for that
task, so every task is signed by the one issuer in the worker's
`trusted_root`. Without `--issuer-key`, `mint --task` signs with a new issuer
each time and prints its public key; the worker accepts that warrant only once
its `trusted_root` is set to that value.

Optional `--session-id ID` embeds a session binding in the signed warrant. It
neither discovers a running session nor attaches the warrant to one. Ordinary
static configuration still needs a restart after replacement. The original
`mint --allow ...` quickstart remains available; it combines provisioning and
issuance and prints a holder private key, so use it only in a trusted terminal.
