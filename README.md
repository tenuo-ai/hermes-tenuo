# Tenuo for Hermes Agent

**Scoped tool permissions and sandboxed local workspaces for Hermes Agent.**

Give Hermes scoped, expiring tool permissions. With **Hands**, let your remote
Hermes work in a folder on your Mac or Linux machine while its memory and skills
stay on the server. Choose the folder, access level, and duration locally.

## Choose your first task

| I want to… | Start here | Manual warrant? |
|---|---|---|
| Let remote Hermes work in a local project | [Your first Hands session](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/hands-first-session.md) | No |
| Restrict which tools and arguments Hermes may use | [Tool authorization setup](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#install-into-hermes) | Yes |

These features work independently or together. Installing the plugin alone does
not turn on a Hands listener or configure general tool-call authorization.

## Install

On the Hermes server, install and enable the plugin, then restart the gateway or
profile serving your chat:

```sh
hermes plugins install tenuo-ai/hermes-tenuo --ref v0.4.0
hermes plugins enable hermes-tenuo
```

Leave optional warrant credentials empty if you only want Hands. Enable installs
the runtime dependencies. Run `/hands setup` in your chat to configure the connection.

On your Mac or Linux laptop, install [uv](https://docs.astral.sh/uv/getting-started/installation/)
if needed, then check the CLI and create a practice project:

```sh
uvx --refresh hermes-tenuo --version
uvx hermes-tenuo hands demo
```

Hands requires hermes-tenuo 0.4.0 or newer. The refresh ensures an older cached CLI
is updated. Follow the printed `cd` command to enter the practice folder.

If you manage the Hermes Python environment yourself, installing
`hermes-tenuo==0.4.0` into that environment with pip is an alternative to the
directory plugin. Use one installation route. `hermes-tenuo status` reports the
invoked CLI's version and source path.

## First success with Hands

1. In Hermes, run `/hands setup` and configure a reachable HTTPS or private-network listener.
2. On the laptop, run `uvx hermes-tenuo hands demo` and enter its disposable folder.
3. In Hermes, run `/hands setup edit`; run its command locally.
4. Run `/hands verify` in the same chat, then ask Hermes to fix the demo's invoice test.
5. Press Ctrl-C on the laptop to end access. `/hands off` switches routing but does not end the grant.

Follow the [complete walkthrough](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/hands-first-session.md)
for prerequisites, troubleshooting, privacy exclusions and permission choices.
Devices need macOS sandbox-exec or Linux bubblewrap; Linux network access also
requires Landlock ABI 6. Internet is off by default. Commands and results go to
remote Hermes and its model. Browser/MCP tools remain on the server. Secret
redaction is best effort; exclude files that must never leave the device.

## Documentation

- [Authorization, argument constraints, delegation, audit and configuration reference](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md)
- [Hands operational reference and Linux sandbox setup](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/reference.md#hands-let-your-servers-agent-use-your-own-machine)
- [0.4.0 release checklist](https://github.com/tenuo-ai/hermes-tenuo/blob/main/docs/releasing-0.4.0.md)
- [Changelog](https://github.com/tenuo-ai/hermes-tenuo/blob/main/CHANGELOG.md)

Apache-2.0. [License](https://github.com/tenuo-ai/hermes-tenuo/blob/main/LICENSE).
