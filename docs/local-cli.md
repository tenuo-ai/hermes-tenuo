# Shared local CLI setup

This mode uses the common Tenuo Python SDK for YAML templates, issuance, keys,
signed revocation lists, portable approvals and session attachments. The plugin
only connects those artifacts to Hermes hooks. It does not implement another
warrant-template parser or signer.

This is unreleased. Install the matching Tenuo SDK and plugin checkouts into
your test environment; the published SDK may not expose these APIs yet. An
unavailable SDK helper blocks tools rather than falling back to legacy mode.

## Start in one command

```bash
tenuo-cli hermes setup
```

This creates the Tenuo workspace at `TENUO_HOME` or `~/.tenuo` with
development identities if there isn't one, puts it in observe mode, and adds
`local_home` to this profile's `config.yaml` (the previous file is kept as
`config.yaml.before-hermes-tenuo`). Use `--home DIR` for another workspace and
`--enforce` to start enforcing. Then run Hermes as usual and continue at
[observe before you write a warrant](#observe-before-you-write-a-warrant).
The sections below set the same things up by hand.

## Issue outside Hermes

In your controller workspace:

```bash
tenuo-cli init --dev
tenuo-cli template validate --file reports.yaml
tenuo-cli warrant issue --template reports.yaml --holder agent
tenuo-cli warrant list
```

For example, `reports.yaml` can allow Hermes' `read_file` tool under a dedicated
report directory that you prepared:

```yaml
version: 2
name: report-reader
ttl: 30m
capabilities:
  read_file:
    path: {subpath: /data/reports}
```

Use registered tool and argument names from your Hermes installation. Other
tools and ungranted arguments are denied. Do not add terminal or code execution
merely to avoid defining the structured operations you need.

A one-off request uses the same YAML plus `kind: warrant-request` and
`holder: agent`, issued with `tenuo-cli warrant issue --request FILE`.
The controller reads only the holder's public key. The agent never receives
the issuer private key or permission to issue its own grants.

## Configure a dedicated profile

Configure that profile's Hermes `config.yaml`:

```yaml
plugins:
  enabled: [hermes-tenuo]
  entries:
    hermes-tenuo:
      local_home: /run/tenuo
      local_key: agent
```

`local_home` is absolute or relative to the selected Hermes profile home.
Use a separate workspace, holder identity, state and credentials per profile.
`local_key` can be a local key name or an explicit private-key path. Do not mix
this mode with legacy warrant, key, session-directory or approval settings.
It refuses `on_denial: log`; to watch calls without blocking, put the workspace
in observe mode instead (below). It has no static install-wide warrant fallback.
Legacy environment credentials are not used by the shared local mode.

Provision only these files inside the agent boundary:

| Files | Agent access |
| --- | --- |
| `config.yaml`, `keys/agent.key` | Read; the private key is mode `0600` |
| `trust/*.pub`, `revocations.srl` | Read-only verification data |
| `warrants/*.warrant`, `sessions/*.yaml` | Read-only operator publications |
| `approvals/*.yaml` | Read-only signed responses |
| `requests/`, configured receipt destination, `observations.jsonl` | Writable runtime state |

The controller and approver private keys stay outside these mounts. Local
development under one OS user does not provide process isolation. Mount parent
verification directories read-only so atomic replacements are visible; a bind
mount of one file can retain an old inode. Transporting files is the operator's
deployment responsibility; no networking or hosted service is required by the
file protocol.

## Observe before you write a warrant

Start the profile with the workspace in observe mode to see what Hermes calls
before you scope it:

```bash
tenuo-cli mode observe
# run the profile for a few tasks
tenuo-cli calls summary
```

In observe mode no tool call is blocked and no session attachment is needed.
Each call is appended to `observations.jsonl` in the workspace with its
arguments. A call checked against an attached warrant also records what
enforcement would have decided: `allow`, or `deny` with the reason, including
`approval_required` for a gated call; no approval request is written. The
Hermes session ID is the recorded `run`, and `local_step` (default `hermes`)
the `step`. That is the trace format
[warrantgen](https://github.com/RajanChavada/warrantgen) reads, so you can draft
a template from the recorded calls, issue it, attach it and run
`tenuo-cli mode enforce`. The switch applies on the next call; no gateway
restart is needed. `hermes-tenuo doctor` reports the mode.

The file holds argument values, so it is created readable by its owner only.
Observe mode writes no signed receipts.

## Attach to a session

The first blocked tool call reports the session ID and an attachment command.
Use that exact session ID in the controller workspace:

```bash
tenuo-cli hermes session attach --session SESSION_ID --file .tenuo/warrants/WARRANT_ID.warrant
tenuo-cli hermes session show --session SESSION_ID
```

Deliver the updated public artifacts and manifest to the runtime directory,
then retry in the same Hermes conversation. No gateway restart is needed.
Attachments survive turn end. A new child session needs its own attachment.
Several grants can be attached, but every call must fit one whole warrant;
partial scopes are never combined.

Signing grants authority until expiry or revocation. Attachment only routes an
existing grant; it is not activation. `session detach` removes one reference,
while `revocations add --id ID` denies the warrant wherever the updated list is
enforced. Issuing a replacement does not revoke the previous grant. Attach the
new ID explicitly and detach or revoke the old one as intended.

### Cron jobs

Hermes names each cron run `cron_<job_id>_<date>_<time>`, so a run's session ID
isn't known in advance. Attach the warrant to the job instead; it covers every
run of that job and no other session:

```bash
tenuo-cli hermes session attach --session cron_JOB_ID --file nightly.warrant
```

A run's own attachment, if it has one, takes precedence over its job's. In
observe mode each cron run is recorded with the job as its `step`, so
`tenuo-cli calls summary` prints one `warrantgen template` command per job.
Give the warrant a TTL that covers the runs you expect, and reissue it with
`tenuo-cli warrant reissue` before it expires.

## Approvals, inspection and validation

Gated calls write the shared approval-request YAML under `requests/`. Send it to
an approver who has their own key and independently configured public trust:

```bash
tenuo-cli approval show --file REQUEST.yaml
tenuo-cli approval approve --file REQUEST.yaml --out RESPONSE.yaml --yes
```

Return the response to the runtime's indicated `approvals/<request_hash>.yaml`
path and retry. Runtime verification checks the native signature and exact
warrant, holder, tool and arguments. Approval does not widen scope, extend a
warrant or bypass revocation. It remains reusable for that identical call until
expiry; it is not a one-use execution token or verified human identity.

```bash
tenuo-cli warrant show --file WARRANT
tenuo-cli warrant verify --file WARRANT
tenuo-cli audit list --denied
tenuo-cli audit verify
hermes-tenuo doctor
```

Choose the runtime workspace with `--home` when inspecting its receipts. Doctor
checks common file readiness and current attachments, and distinguishes that
from confirming a running Hermes process loaded the plugin. Verify a real
allowed tool call, then a signed but out-of-scope argument, and confirm the
denied handler did not run. The tests also cover registration through the real
Hermes plugin loader and dispatcher.

The hook mediates Hermes tool dispatch, including missing-session cases. It is
not an OS sandbox and cannot constrain arbitrary subprocesses or code that
accesses resources directly. Keep that boundary separate.

This YAML uses the shared SDK's `approvals.required` syntax. The old
`hermes-tenuo mint --policy` grammar remains a legacy compatibility path; its
`approvals.gates` documents are not silently interpreted as the new format.
