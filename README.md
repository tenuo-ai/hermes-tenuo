# Tenuo for Hermes Agent

**Let Hermes work. Decide what it can do.**

Give your Hermes agent **signed, expiring permissions** with Tenuo warrants:
which tools it may call, which arguments it may use, and for how long.
With **Hands**, connect your remote Hermes to a project on your Mac or Linux
laptop while its memory and skills stay on the server.

| What do you want Hermes to do? | Start here |
|---|---|
| Run a task with clear limits on tools, files and duration | [Try Tenuo warrants](#try-tenuo-warrants) |
| Work in a local project from your existing remote chat | [Try Hands](#try-hands) |

Use either feature on its own, or both together.

## Try Tenuo warrants

Give a nightly report job access to its reports folder, let a researcher search
without writing files, or give a delegated agent fewer permissions than its
parent. The limits are checked before the tool handler runs.

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
uvx --refresh hermes-tenuo demo
```

**Apply it to your Hermes:** [install and configure Tenuo](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#install-into-hermes),
mint a warrant for the task, and run `hermes-tenuo doctor` to check the configuration.
For example, this grants only `web_search` for one hour:

```sh
uvx hermes-tenuo mint --ttl 1h --allow web_search
```

The command prints the configuration and signing-key instructions. Apply them
in the Hermes profile serving the task, check the configuration, and restart
that profile. Installing the plugin alone does not activate tool authorization.

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
hermes plugins install tenuo-ai/hermes-tenuo --ref v0.4.0
hermes plugins enable hermes-tenuo
```

Leave the optional credential prompts empty. Enable installs the dependencies.
Follow the [Tailscale connection setup](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/hands-first-session.md#2-connect-your-server-and-laptop)
to connect the server and laptop, then restart the Hermes gateway/profile serving
your chat. An existing HTTPS endpoint works too; the guide covers both.

**2. Laptop — create a practice folder.**

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if needed:

```sh
uvx --refresh hermes-tenuo --version
uvx hermes-tenuo hands demo
```

Check that the version is 0.4.0 or newer. Follow the printed `cd` command.
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

## More

- [Hands settings, platform requirements and troubleshooting](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#hands-let-your-servers-agent-use-your-own-machine)
- [Warrants, tool authorization, delegation and advanced configuration](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#install-into-hermes)
- [Changelog](https://github.com/tenuo-ai/hermes-tenuo/blob/main/CHANGELOG.md)

Hands ships in **hermes-tenuo**, the Tenuo plugin for Hermes Agent.
[Apache-2.0 license](https://github.com/tenuo-ai/hermes-tenuo/blob/main/LICENSE).
