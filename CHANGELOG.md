# Changelog

## Unreleased

### Hands

- Add Hands: a conversation with a remote Hermes can run its terminal and file
  tools in one folder on your own machine, for a set time. `/hands invite`,
  `/hands on|off|status|revoke` in chat; `hermes-tenuo hands up` and
  `hermes-tenuo hands log` on the machine.
- The machine signs a warrant for the server's key, checks every command
  against it before running, and runs it in a sandbox limited to the folder.
- Off unless `hands.listen` is configured. Works with or without an
  enforcement warrant.

### Fixed

- `hermes plugins install` no longer fails on Hermes's Python 3.14 environment.
  The `cloud` extra now applies on Python 3.13 and earlier only, because
  `tenuo-cloud` has no 3.14 build yet.

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
