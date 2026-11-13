# Verify delegated authority on MCP servers you already use

Use `hermes-tenuo mcp` to put one or more existing MCP servers behind a local
Tenuo verifier. Start with a tool that can safely touch a disposable file,
repository, or test resource. The exercise sends a denied call and an allowed
call over MCP with a real holder-signed warrant chain, then shows both in one
audit view. It runs without a model or a Hermes process.

## Wrap your servers

Install the optional extra in your Python environment:

```sh
python -m pip install 'hermes-tenuo[mcp]==0.4.0'
```

Then use the JSON or YAML file that already contains
your `mcpServers` or Hermes `mcp_servers` settings.

```sh
hermes-tenuo mcp wrap ./mcp.json ./wrapped-mcp --server files --server git
hermes-tenuo mcp tools ./wrapped-mcp
```

Replace `files` and `git` with the names in your config. Omit `--server` to
select all enabled servers. The source stays in place and the workspace
references it without copying credentials. `tools` connects to those servers
and shows the exact names and argument schemas you can use. Tool names have
the form `server__tool`, so two servers can both expose a tool called `search`.

The wrapper accepts stdio `command`, `args`, `cwd`, and `env`, or
Streamable HTTP `url` and optional `headers`. It resolves `${VAR}` references
from the environment at `wrap` time and verifies the resolved settings at launch.
Set those variables before running `wrap`. Only fingerprints are saved, not their
expanded values. Changes to referenced variables, including credential rotation,
require a new workspace. Run `wrap` from the directory your
original stdio commands expect. Hermes `tools.include` and `tools.exclude`
lists and `connect_timeout` and `timeout` settings are preserved. If a selected
connection setting changes, create a new workspace so existing warrants
cannot silently follow the changed target.

## Preview, then prove allow and deny

Pick one tool and two valid sets of arguments for it. Use the same argument
names and change a resource or value the grant should constrain. Save the cases
as `cases.json`. Include more than one tool to see the same grant reach multiple
servers. Here is a case for the Filesystem MCP. Replace the paths with files
inside its disposable allowed directory.

```json
[
  {
    "tool": "files__write_file",
    "allow": {"path": "/tmp/mcp-test/allowed.txt", "content": "approved"},
    "deny": {"path": "/tmp/mcp-test/denied.txt", "content": "approved"}
  }
]
```

```sh
hermes-tenuo mcp check ./wrapped-mcp ./cases.json
hermes-tenuo mcp check ./wrapped-mcp ./cases.json --run
```

Preview displays the exact calls without connecting. `--run` validates the
arguments against the tool schemas, mints a short-lived grant, narrows it to
the selected arguments for a separate holder, and sends the two calls.
It expects a Tenuo constraint denial before forwarding, and a tool-reported
success for the authorized call. Verify the service state independently when
testing a write. In the example, only `allowed.txt` should exist.

The guided check accepts named scalar or array arguments with compatible
schemas. Use a real warrant with `mcp call` to exercise custom constraints
or tools that take no arguments.

## Follow a grant across tools

```sh
hermes-tenuo mcp audit ./wrapped-mcp
hermes-tenuo mcp audit ./wrapped-mcp ./another-workspace --warrant tnu_wrt_EXAMPLE
hermes-tenuo mcp audit ./wrapped-mcp --denied --json
```

Use the warrant ID printed by `check` to follow the same delegated grant across
calls. The audit shows the tool, authorization decision, and separately whether
the call was forwarded and what the tool reported. An upstream connection
failure can leave the backend outcome unknown. Check the service before
retrying an operation in that state. JSON output includes the workspace,
call ID, parent warrant IDs, and the trusted root and holder fingerprints on
allowed calls. IDs in denial records are the IDs presented by the caller.
The local audit excludes arguments, tool responses, credentials, and signatures.

For a delegated Hermes task, include each agent's local Tenuo audit file with
`--hermes-log`. Copy the files locally first when the agents run on separate
machines. Use the grant ID returned by `tenuo_delegate` to see the sender's
record, the receiver's decisions, and the wrapper's upstream outcomes.

```sh
hermes-tenuo mcp audit ./wrapped-mcp --hermes-log ./sender.jsonl \
  --hermes-log ./receiver.jsonl --warrant tnu_wrt_EXAMPLE
```

## Use an existing issuer or client

Create a workspace with `--trust-root issuer.pub` to use an existing issuer and
keep its private key outside the wrapper. Issue authority over qualified names
such as `files__write_file`. If an issuer is trusted by multiple independent
workspaces, give their servers distinct names so a grant cannot name two
different destinations. Install a binary Tenuo signed revocation list as
`revocations.srl` in the workspace to enforce its revocations. The verifier
reloads updates on calls. After accepting a list it requires that exact list
or a newer signed version, including after a restart. Keep the revocation
database with the workspace when moving or restoring it.

```sh
hermes-tenuo mcp call ./wrapped-mcp files__write_file \
  --warrant parent.warrant --warrant delegated.warrant --holder-key holder.key \
  --args '{"path":"/tmp/mcp-test/allowed.txt","content":"approved"}'
```

Pass the chain root to leaf and use the leaf holder's key. `mcp config` prints
the stdio launch entry for another client. That client must send Tenuo warrant
and proof-of-possession metadata with each call. Standard MCP discovery still
works without authority. A regular MCP client without Tenuo metadata will be
denied when it calls a tool.

## Call wrapped tools from Hermes

Add the wrapper to the agent's `mcp_servers` under the name `mcp config` prints (`tenuo_mcp`), and
let `hermes-tenuo` sign those calls:

```yaml
plugins:
  entries:
    hermes-tenuo:
      mcp_proofs:
        servers: [tenuo_mcp]
```

For each call to a wrapped tool, `hermes-tenuo` adds the session's warrant chain and a proof signed with
its key, so the agent needs an enforcing warrant that names the wrapper's tools (`files__write_file`).
The local guard authorizes the call under that same name. On a task delegated from another Hermes
([A2A delegation](a2a-delegation.md)), the proof carries the delegated chain, and the wrapper verifies
it to the operator root: create the workspace with `--trust-root` set to that root.
Use the original names from `hermes-tenuo mcp tools` in warrants. The plugin maps
Hermes's registered names back to discovered wrapper names, including names
that Hermes rewrites or shortens. If two names collide, exclude one or rename
it and reload MCP discovery.

The wrapper covers direct tool calls. Resources, prompts, interactive
continuations, legacy SSE, and OAuth setup are outside this workflow. The
enforcement boundary is the local wrapper. Keep the original MCP connection
and credentials out of the calling agent's reach when using it to protect a
service. Local audit files can be inspected together or exported as JSONL.
