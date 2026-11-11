# Your first Hands session

Keep your existing Hermes on its server, with its memory and skills. Give one conversation access to one folder on your laptop. This walkthrough uses a disposable project, needs Python 3 and no model-specific configuration, and should take about five minutes once the server listener is reachable.

Supported devices: macOS with sandbox-exec, or Linux with working bubblewrap. Native Windows and GUI/browser control are not supported. A Linux share with internet access additionally needs enabled Landlock ABI 6; the offline practice project does not need it.

## 1. Install and enable on the server

In the Hermes environment/profile serving your chat:

```sh
hermes plugins install hermes-tenuo
hermes plugins enable hermes-tenuo
```

Hands needs no manually minted warrant. Leave the optional enforcement credentials empty if you only want Hands. Restart that Hermes gateway/profile after installation. `/hands setup` is available even before its listener is configured.

**Before the catalog update:** the catalog still points to an older release without Hands. PR reviewers should install this PR's commit using `hermes plugins install tenuo-ai/hermes-tenuo --ref COMMIT_SHA`, and run the laptop CLI from the same commit with `uvx --from 'git+https://github.com/tenuo-ai/hermes-tenuo.git@COMMIT_SHA' hermes-tenuo …`. Do not advertise the catalog walkthrough as released until the checklist below is complete.

## 2. Configure the connection once

In the chat, run `/hands setup`. Follow its server configuration instructions: an HTTPS URL forwarded to the loopback Hands listener, or a Tailscale IP bound on that private network. This is **not** the Hermes Desktop gateway port. Restart the gateway/profile after changing configuration.

The laptop connects outward; it needs no incoming port. Keep the laptop awake and its sharing terminal open. Server-side configuration cannot prove your laptop can reach the address: preflight on the laptop checks that.

## 3. Create a practice folder on the laptop

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if `uvx` is not available, then run:

```sh
uvx hermes-tenuo hands demo
```

It prints a new temporary folder and a `cd` command. Run that command locally. Nothing has been paired yet and no existing project was changed.

## 4. Choose permissions and connect

In the originating Hermes chat, run `/hands setup edit`. Copy its generated command into the laptop terminal in the practice folder. It shares this folder for one hour and runs automatic preflight before pairing.

The other choices are `/hands setup read` (no project writes) and `/hands setup online` (writes plus internet/network access). Offline edit is sufficient for this demo. Online access is not restricted to package downloads.

When the laptop says Hands is up, run `/hands verify` in the originating chat. You should see the machine, folder, read/write mode, internet off, remaining time, and the verified folder path. This read-only probe uses the signed Hands execution path. Push notifications are not available on every Hermes surface, so verification is explicit.

## 5. Complete one useful task

Ask Hermes:

> Run `python3 -m unittest -v` in the shared folder. Fix the invoice calculation in invoice.py without changing the tests, then rerun the tests.

Inspect `invoice.py` locally and run the tests yourself. No package installation or internet access is needed. Memory and skills remain on the server. Browser and MCP tools have not moved to the laptop.

## 6. End access

Press Ctrl-C in the laptop's sharing terminal. Its commands and background processes stop; file edits remain. `/hands status` should show the device as not answering. `/hands off` sends the conversation back to the server. **Using `/hands off` alone does not end the laptop grant.** For a whole profile with `terminal.backend: hands`, change the profile's terminal backend to return to the server; `/hands off` cannot switch it. Delete the practice folder when done.

The laptop prints a reconnect command that preserves your choices and the original `TENUO_HANDS_HOME` identity directory and configured `SSL_CERT_FILE` CA path (made absolute at startup), and excludes the consumed invite. Running it locally grants a new time window. After revocation, request a new invite instead.

## When something goes wrong

| What you see | What to do |
|---|---|
| `/hands` is unknown | Enable the plugin and restart the gateway/profile serving this chat; check its version includes Hands. |
| Hands is off | Follow `/hands setup`; no laptop connection is possible until the server listener is configured. |
| Cannot reach server / wrong service | Check `hands.url`, the proxy route, port and private-network connection. Run `hands check` locally. |
| No sandbox | Follow `hands check` diagnostics. On Ubuntu, see the bubblewrap setup in the README. The demo does not need `--no-sandbox`. |
| Invite expired or already used | Generate a new invite; do not repeatedly reuse the old one. |
| Install/download fails | Internet is off in read/edit shares. Choose online only if you want that access, then restart locally. |
| Device disconnected or expired | Inspect the laptop terminal and use its reconnect command. No silent server fallback occurs. |
| Outcome unknown | Check the device and files before retrying; a lost reply does not mean a command failed. |

## Release validation before repinning

- Publish the laptop package containing these changes before updating the reviewed catalog SHA.
- Update marketplace description, permission disclosures and demo to cover Hands; preserve the existing authorization feature documentation.
- From clean supported macOS and Ubuntu installations, complete this walkthrough through Desktop and a messaging gateway. Record actual versions and results; automated tool-dispatch tests are not a substitute for UI checks.
- Exercise unreachable server, missing sandbox, expired invite, laptop disconnect and offline dependency-install cases.
- Confirm read-only leaves files unchanged; edit stays offline; online is explicitly chosen.
- Confirm the catalog install and the default `uvx` package interoperate and show the same permissions.
- Repin only after those checks pass. This PR does not publish or change the upstream catalog pin.

## Preview and keep private files out

Before running the generated `hands up` command, append `--preview` to inspect
its permissions locally. Remove `--preview` to connect. Preview does not consume
the invite or test the server connection.

Personal exclusions live in `~/.config/hermes-tenuo/never-share`, one existing
literal path per line, relative to the shared folder or absolute. For example,
`customers/` keeps that directory's contents out of terminal and file operations.
Missing paths are errors; globs are not supported. Restart Hands to apply rule
changes. See the README for platform behavior and path-alias limitations.

Recognized secrets in results and command logs are redacted locally. A result
says when redaction occurred; it does not modify project files. Detection is
best effort, so exclude material you must not send to Hermes or its model.
