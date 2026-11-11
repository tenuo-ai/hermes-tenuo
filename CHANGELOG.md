# 0.4.0 (unreleased)

- Add Hands: scoped, expiring local workspaces for remote Hermes, with sandboxing, per-conversation routing, setup/verify, privacy exclusions and local result redaction.
- Reuse Tenuo path-jail for workspace containment.
- Separate Hands and tool-authorization onboarding and diagnostics; align plugin and package descriptions.
- Prefer the selected directory checkout, reject already-loaded conflicting installations, and validate release artifacts before publishing.

# Changelog

## Unreleased

### Access

- Add role-based gateway access: an `access:` block of roles (`match` + `allow`)
  compiles to one warrant per role and the guard resolves each messaging turn to
  its sender's role. Authority follows the message's sender, so a shared chat is
  authorised per message; a sender no role grants is blocked. A constrained tool
  keeps its other arguments unless `strict: true`; `terminal` takes a `binaries`
  allowlist. The signing key is auto-provisioned under `$HERMES_HOME/tenuo` so no
  key need be configured; `doctor` validates the block. API-server, webhook and
  scheduled turns match roles by platform; local (CLI/desktop) turns are not
  governed. A `delegate_task` child gets a grant narrowed from its parent's role.

### Hands

- Reuse Tenuo’s Python `path-jail` for workspace selection and signed command
  directory containment. Keep sandbox enforcement and the canonical-path rule
  for commands; this is validation at call time, not descriptor-pinned access.

- Preview sharing locally with `hands up --preview`, without connecting or pairing.
- Enforce personal literal-path exclusions from `~/.config/hermes-tenuo/never-share`
  in both terminal and file operations; retain the policy location on reconnect.
- Redact recognized secrets on the device before sending results or recording
  command logs, including Hermes's encoded file-read samples. Detection is best effort.
  A `.env` value is treated as a secret only under a secret-looking key, and an assignment to
  a secret-named field redacts a quoted string literal while leaving a bare expression, a
  reference or a file path as is, so ordinary settings and source are not redacted.
- Keep serving when the server's answer is not in the expected form: it is retried like a
  lost connection instead of ending the device.
- Exercise both client/server directions against a pinned previous Hands version in CI.

- Add Hands: a conversation with a remote Hermes can run its terminal and file
  tools in one folder on your own machine, for a set time. `/hands invite`,
  `/hands on|off|status|revoke` in chat; `hermes-tenuo hands up` and
  `hermes-tenuo hands log` on the machine.
- The machine signs a warrant for the server's key, checks every command
  against it before running, and runs it in a sandbox limited to the folder.
  Commands share one sandbox per session, so a later command can stop a
  process an earlier one started, and nothing outside it can be signalled or
  launched.
- Processes left running survive between commands and stop with `hands up`.
- A command that arrives after the server stopped waiting is refused instead
  of run late; a conversation follows its machine across restarts and new
  time windows, and `/hands on <name>` moves it to another machine.
- Results of commands and file tools that ran on a machine name it and its
  folder; a refusal by its sandbox says what the machine shares.
- `hermes-tenuo hands check` says whether a machine is ready without pairing
  it, and `hands up` prints what commands can and cannot do. `--read-only`
  lets commands read the folder without changing it.
- A machine that is up pairs again by itself when Hermes restarts, and each
  conversation keeps the machine it was using.
- A result that cannot be reported because the connection dropped is kept and
  sent when it is back. A command whose result never arrives is reported as
  outcome unknown.
- A certificate the machine does not trust is explained, with `SSL_CERT_FILE`
  for a private certificate authority.
- Behind a reverse proxy on the same host, connection limits apply to each
  caller's forwarded address.
- Commands cannot read the home folder outside the shared folder, except
  toolchains and folders on `PATH`. `--read FOLDER` shows one more folder and
  `--read-home` shows the home folder except credentials and browser data.
- Commands have no internet unless `hands up` is started with `--network`.
  Results from a machine without it say so, and a failed download or install
  tells the agent how the person can allow it.
- The conversation that asked for an invite starts using the machine when it
  comes up. Where the chat platform says who is writing, a machine belongs to
  the person who invited it: others cannot see, use or forget it.
- A machine refuses an unencrypted server that is not on a private network,
  unless started with `--plain-http`.
- On Linux a folder hidden from commands is read-only. `hands check` explains when bubblewrap is installed but not allowed to run,
  as on Ubuntu 24.04.
- Off unless `hands.listen` is configured. Works with or without an
  enforcement warrant.

## 0.3.1 - 2026-11-10

This patch release keeps a session's own warrant in force for as long as the
session runs, and makes `doctor`, `status`, the audit log, and task minting
agree with what the plugin does at runtime. Upgrading is recommended for every
0.3.0 install.

### Session warrants

- Keep a session's own warrant attached across turns. `on_session_end`, which
  Hermes fires after every turn, no longer removes it; a `delegate_task` child
  keeps its grant for as long as it runs.
- A session whose warrant was cleared with `clear_session_warrant`, or a child
  whose grant has expired, is denied. It does not use the config warrant. Call
  `set_session_warrant` again to give the session authority.
- The record of denied sessions is bounded at 65,536 per process. Past that,
  sessions with no warrant of their own are blocked and `delegate_task` is
  refused until Hermes restarts.

### Diagnostics and audit

- `hermes-tenuo doctor` now fails when `trusted_root` is not a public key or
  did not sign the warrant, when a configured delegation plan does not load,
  and when `on_denial` is not `block` or `log`.
- `hermes-tenuo status` says whether an incomplete configuration blocks every
  call or enforces nothing.
- `mint --task` accepts `--issuer-key` and `--holder-public-key`, so task
  warrants can be signed by the issuer the worker already trusts. Task ids
  that are paths are refused.
- Calls blocked for a missing signing key, a session without a warrant, or an
  internal error are written to the audit log as denials.

### Documentation

- Correct the argument rules: once a tool has any constraint, an argument the
  warrant does not name is denied. Examples now name `content` for
  `write_file` and show `_allow_unknown=True` for optional arguments.

## 0.3.0 - 2026-11-09

This minor release hardens every subagent delegation boundary, fails closed on
plugin enforcement errors, and moves the integration to Tenuo 0.3.6.

### Delegation security

- Give every authorized `delegate_task` child a one-time grant, a fresh holder
  key, and the complete verified ancestor chain.
- Require an authorized spawn before a child receives authority; reject
  unstaged, ambiguous, cancelled, and mismatched child activity.
- Attribute sessionless tool calls by task ID and fail closed when attribution
  is missing, ambiguous, or capacity-limited.
- Add strict operator-controlled delegation plans for per-depth tool, argument,
  and TTL narrowing, with atomic parent TTL caps.
- Preserve inherited constraints, terminal delegation semantics, and exact
  capability restrictions across conventional `tool:` aliases.

### Fail-closed operation

- Convert escaped authorization-hook failures and malformed hook results into
  explicit denials without exposing arguments or backend error details.
- Keep denials effective even if secondary kanban bookkeeping fails.
- Record final grant rejections, unauthorized children, and unattributed post
  hooks as denials in local audit and control-plane output.

### Compatibility and dependencies

- `hermes plugins install` no longer fails on Hermes's Python 3.14 environment.
  The `cloud` extra now applies on Python 3.13 and earlier only, because
  `tenuo-cloud` has no 3.14 build yet.
- Require Tenuo 0.3.6 for hardened negated and numeric policies, stricter URL
  parsing, complete delegated Python chains, and current security remediations.

## 0.2.0 - 2026-10-31

This minor release adds explicit issuer/holder separation and signed Cloud
receipts while retaining fail-closed authorization and compatibility with the
existing local quickstart.

### Authority separation

- Generate holder and issuer identities without printing private key material.
- Issue scoped warrants using only the issuer private key and holder public key,
  with optional explicit session binding.
- Create identity and warrant files atomically with mode `0600`, never overwrite
  existing identities, and clean up partial key generation safely.
- Document the production trust boundary: the agent receives its holder key and
  warrant, but never the issuer private key.

### Signed Cloud receipts

- Add the `hermes-tenuo[cloud]` extra and deliver signed, chained receipts when
  `TENUO_CONNECT_TOKEN` is configured.
- Bound receipt flushing at session end and process exit without letting audit
  delivery failures affect authorization decisions.
- Fall back to ordinary decision streaming when Cloud receipt setup is
  unavailable, and redact the connect token from SDK error logs.

### Security and maintenance

- Require Tenuo 0.3.5, including the coordinated verifier and filesystem-jail
  security fixes from Tenuo 0.3.4 and 0.3.5.
- Keep the Cloud extra on the same `tenuo>=0.3.5,<0.4` security floor.
- Update GitHub Actions to supported Node.js runtimes.

## 0.1.4 - 2026-10-23

This release requires Tenuo 0.3.3, a security and correctness release, and
includes the Hermes integration fixes accumulated since 0.1.3.

### Security and correctness

- Never derive the trust anchor from the warrant being verified.
- Decode warrants, signing keys, and trusted roots consistently.
- Carry the full ancestor chain when attenuating warrants for sub-agents.
- Block both registry-dispatched and inline tools when configured authority is
  missing, including `require_warrant` deployments and kanban workers.

### Compatibility and documentation

- Require `tenuo>=0.3.3,<0.4` and validate the integration on Python 3.10-3.14.
- Test both package-entry-point and directory-plugin loading against upstream
  Hermes Agent.
- Document catalog installation by supported Hermes version and clarify which
  warrant protects `execute_code`.
- Keep `hermes-tenuo doctor` output aligned with current Hermes configuration.

### Packaging

- Reject release tags that do not match the package version before publishing.
- Test and validate both distributions before uploading them to PyPI.
