# Tenuo for Hermes Agent

**Give Hermes rules it can't simply ignore.**

Instructions in a prompt are requests. A model can forget them, misread them, or be talked out of them by a web page or email it reads. hermes-tenuo checks each tool call in code, before it runs, against a signed, expiring permission you create. A call outside it never reaches the tool, and Hermes is told why. With that in place you can leave Hermes to run a nightly job, share one bot with a team, or hand a subagent a single task.

## What you can do

- **Allow only the tools a task needs.** Anything not on the list, such as `terminal` or `write_file`, is refused.
- **Limit the arguments too.** Read files only under `/data/reports`, write only under `/tmp/nightly`, keep a number in a range. Path checks resist `../` tricks.
- **Keep destructive actions off the table.** Leave shell and write tools out entirely, or limit an allowed terminal to the programs you name with a delegation plan or a role.
- **Give subagents less than their parent.** A `delegate_task` child can never get more than its parent had, and you can narrow it further with `child_warrant` or a delegation plan.
- **Give each person in a shared chat their own limits.** In a Telegram, Discord or Slack group, teammates can search and read while only you run commands. [Roles](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#role-based-access-for-the-gateway) follow who sent each message, with no keys to manage.
- **Let a subagent do one thing, once.** `max_uses` in a delegation plan [caps how often a tool is used](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#use-limits): per child, or in total for the warrant however many children it starts.
- **Scope Kanban workers per task.** Each worker needs its own task warrant. Without one it is blocked, and a refusal blocks the task on the board.
- **Limit what prompt injection can do.** hermes-tenuo doesn't detect injected instructions. It limits what a misled agent can do: a call outside its permission is refused however the model was persuaded.
- **See every decision, and watch before you enforce.** Allowed and refused calls are logged locally (`hermes-tenuo audit --denied`). While you tune a permission, `on_denial: log` logs ordinary local policy denials without blocking. Denied delegation calls and denials under incoming A2A grants still block, as do internal enforcement errors.

Installing the plugin alone leaves ordinary sessions unrestricted; configure a warrant to protect them, as shown below. Kanban workers are an exception: once the plugin is enabled, each worker needs its own task warrant or all its tool calls are blocked.

**Why it holds:** the check runs outside the model, in Tenuo's Rust core, so no prompt can argue with it. Permissions are Ed25519-signed and expire, and Hermes accepts only those signed by a key you trust. Authority can only narrow as it is handed to subagents, other agents or [guests](https://github.com/tenuo-ai/hermes-guests), and each hop is verified as a chain.

Also in this plugin:

| Want to | Start here |
|---|---|
| Limit tools, files and duration for a task | [Try Tenuo warrants](#try-tenuo-warrants) |
| Let your remote Hermes work in a folder on your laptop | [Try Hands](#try-hands) |
| Wrap MCP servers you already use and trace scoped calls | [Verify delegated MCP calls](docs/mcp-wrapper.md) |

## Try Tenuo warrants

Let a research task search without writing files, keep a reporting session to its
reports folder, or give a delegated agent fewer permissions than its parent. The
limits are checked before the tool handler runs.

A warrant is a signed permission slip with an expiry. Here is a shortened
example from the runnable demo:

```text
ALLOW  read_file  path=/data/reports/q3.csv
DENY   read_file  path=/opt/private/payroll.csv
DENY   terminal  command=ls
After expiry: DENY read_file path=/data/reports/q3.csv
```

**See the checks run locally—no Hermes process or model API key needed:**

```sh
uvx hermes-tenuo==0.4.2 demo
```

**Apply it to your Hermes:** [install and configure Tenuo](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#install-into-hermes),
mint a warrant for the task, and run `hermes-tenuo doctor` to check the configuration.
For example, this grants only `web_search` for one hour:

```sh
uvx hermes-tenuo==0.4.2 mint --ttl 1h --allow web_search
```

The command prints the configuration and signing-key instructions. Apply them
in the Hermes profile serving the task, check the configuration, and restart
that profile. In ordinary sessions, installing the plugin alone does not activate tool authorization.

[See a real-model prompt-injection walkthrough](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/walkthrough.md)
or explore [argument constraints and delegation](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#scoping-arguments).
Tool-call authorization checks the calls and arguments it covers; Hands adds
an OS sandbox for work on the connected device.

## Give your remote Hermes hands

**Your Hermes lives on a server. Your project is on your laptop.**

Open the Hermes chat you already use, connect a folder, and ask it to get to work.
You keep the same agent, memory and skills. Hands needs no manually minted warrant.

### From your chat to your local files

Ask Hermes:

> Run the tests in this folder. Fix the invoice calculation without changing
> the tests, then rerun them.

The practice project gives you a small, visible result:

```text
On your laptop                         In your existing Hermes chat
───────────────────────────────────    ─────────────────────────────
invoice.py + two failing tests     ←    Run the tests and inspect the code
invoice.py updated                ←    Fix the calculation
Two tests pass                    ←    Run the tests again
```

```diff
 def total_after_discount(subtotal, discount):
-    return subtotal * discount
+    return subtotal * (1 - discount)
```

The edited file is on your laptop, ready for you to inspect. Your Hermes keeps
its existing memory and skills. Then try your own project: investigate a test
failure, review local changes, or write a script for files in the shared folder.

You choose the folder and how long to share it. Internet access is off by default.
Press **Ctrl-C on your laptop to end access**. Commands and results are sent to
your remote Hermes and its model; keep private files out with
[personal exclusions](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/hands-first-session.md#preview-and-keep-private-files-out).

## Try Hands

You'll need a running Hermes with terminal-provider and tool-middleware support,
and a Mac or Linux laptop with Python 3. macOS uses its built-in sandbox;
Linux needs [bubblewrap](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#hands-let-your-servers-agent-use-your-own-machine).
Hands supports terminal and file work, not GUI or browser control.

**1. Server — install and connect once.**

```sh
hermes plugins install tenuo-ai/hermes-tenuo
hermes plugins enable hermes-tenuo
```

Leave the optional credential prompts empty. Enable installs the dependencies.
Follow the [Tailscale connection setup](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/hands-first-session.md#2-connect-your-server-and-laptop)
to connect the server and laptop, then restart the Hermes gateway/profile serving
your chat. An existing HTTPS endpoint works too; the guide covers both.

**2. Laptop — create a practice folder.**

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if needed:

```sh
uvx hermes-tenuo==0.4.2 hands demo
```

Follow the printed `cd` command.
The demo creates a new temporary project; it does not change your existing files.

**3. Hermes chat — connect this folder.**

Run `/hands setup edit`. Copy the command it prints into your laptop terminal
inside the practice folder. This shares the project for one hour, with internet off.
Keep that terminal open, then run `/hands verify` in the same chat.

**4. Hermes chat — ask for the fix.**

> Run `python3 -m unittest -v` in the shared folder. Fix the invoice calculation
> in invoice.py without changing the tests, then rerun the tests.

Inspect the local change. When you're done, press **Ctrl-C** in the laptop's
sharing terminal, then `/hands off` in chat to return tools to the server.
`/hands off` alone changes routing; it does not end the laptop grant.

**[Troubleshooting and the full walkthrough →](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/hands-first-session.md)**

## Keep using the Hermes you know

Hands adds a local workspace to your existing remote Hermes. Your laptop connects
outward, so it needs no incoming port or SSH server. You approve the connection
locally and can switch the conversation back to server tools when you're done.

Hermes also supports SSH terminal backends. Hands is useful when you want to
connect a laptop temporarily, choose the folder locally, and attach it to one
conversation. Browser and MCP tools stay on the server.

For read-only work, use `/hands setup read`. If a task needs network access,
choose `/hands setup online` explicitly. Linux online shares also require
Landlock ABI 6. Secret redaction is best effort; exclude files that must not be
sent to Hermes or its model.

## Delegate between Hermes agents (preview)

One Hermes can hand a bounded task to another over native A2A with `tenuo_delegate`. The receiver
gets a signed, short-lived grant held by its own key, covering only the tools and argument values you
name, and checks it before its model sees the task and at every tool call.
[Set up two agents →](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/a2a-delegation.md)

## Share your Hermes with other people

[Hermes Guests](https://github.com/tenuo-ai/hermes-guests) uses Tenuo to let people you
choose use part of your Hermes from their own Telegram chat, for as long as you choose:
chat only, or chosen tools narrowed to one device or folder.

## More

- [Hands settings, platform requirements and troubleshooting](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#hands-let-your-servers-agent-use-your-own-machine)
- [Warrants, tool authorization, delegation and advanced configuration](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#install-into-hermes)
- [Changelog](https://github.com/tenuo-ai/hermes-tenuo/blob/main/CHANGELOG.md)

Hands ships in **hermes-tenuo**, the Tenuo plugin for Hermes Agent.
[Apache-2.0 license](https://github.com/tenuo-ai/hermes-tenuo/blob/main/LICENSE).
