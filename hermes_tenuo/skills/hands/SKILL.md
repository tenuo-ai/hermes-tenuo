---
name: hands
description: Connect, verify, and troubleshoot a laptop workspace used by a remote Hermes conversation through Hands. Use when the user wants their existing Hermes to work on local files without moving its memory or running a second agent.
---

# Hands

Hands routes terminal and file tools to one shared folder on a paired macOS or Linux machine. Memory, skills, browser, MCP servers and other tools stay where they normally run. It works without a manually configured Tenuo enforcement warrant.

## Connect

Have the user run `/hands setup` in the Hermes conversation they want to connect. When the listener is not configured, that command explains the active profile's server settings. The Hands address is a separate listener, not the Desktop gateway address. Use an existing HTTPS reverse proxy or private network such as Tailscale; do not recommend public plain HTTP or opening a laptop port.

The user chooses `/hands setup read`, `edit`, or `online`. Read prevents project changes; edit permits changes/tests with internet off; online also permits internet and network services. The generated one-hour command is run **on the laptop, in the intended folder**, not through the server's terminal tool. The local command is the user's permission grant. It runs preflight before pairing. Do not broaden it automatically when a task fails.

After the laptop says it is up, ask the user to run `/hands verify` in the originating conversation. This executes a fixed read-only folder probe and reports machine, folder, permissions and time remaining. Automatic pairing notices are not supported on every Hermes surface. `/hands status` is the source for current routing; static session instructions are not proof of a live connection.

## Work

Use normal Hermes terminal and file tools. Check `ran_on` in execution results. Dependency installation needs an online share: ask the user to stop the laptop process and rerun locally with `--network` only if they want that access. A browser's localhost does not become the laptop's localhost. Do not claim GUI, browser or native Windows support. Do not forward credentials or mount extra folders to bypass a denial.

If a result says the outcome is unknown, inspect the device/project before retrying a potentially mutating command. A reconnect is not proof the previous command failed.

## End or recover

`/hands off` sends this conversation's subsequent terminal/file work back to the server. It does **not** end the laptop's grant. Ctrl-C in the laptop's `hands up` terminal stops device access and its background processes. Existing file edits remain. `/hands revoke <name>` forgets the device server-side; a new invite is required afterward.

The laptop prints a reconnect command with the same folder, permissions and duration, without the consumed invite. Running it locally grants a fresh time window. Expired invites require a new `/hands setup` command. For connection errors, check the laptop's preflight output, `hands.url`, proxy route, sandbox availability, and whether the correct Hermes gateway/profile was restarted. Never silently fall back to executing on the server.

For a first trial, `uvx hermes-tenuo hands demo` on the laptop creates a disposable Python project with one intentionally failing test and prints instructions. No pairing, network access or model is required to create it.
