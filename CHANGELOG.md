# Changelog

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
