# Changelog

## Unreleased

### Session warrants

- Keep a session's own warrant attached across turns. `on_session_end`, which
  Hermes fires after every turn, no longer removes it; a `delegate_task` child
  keeps its grant for as long as it runs.
- A session whose warrant was cleared with `clear_session_warrant`, or a child
  whose grant has expired, is denied. It does not use the config warrant. Call
  `set_session_warrant` again to give the session authority.

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
