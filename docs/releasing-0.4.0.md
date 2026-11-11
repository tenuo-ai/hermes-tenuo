# Preparing 0.4.0

This is a release candidate checklist, not an announcement. No release, PyPI
publication, live GitHub About edit or upstream catalog repin is performed by
this preparation PR.

## Copy to use at release

Short description (package, GitHub About and catalog summary):

> Scoped tool permissions and sandboxed local workspaces for Hermes Agent.

Expanded description:

> Give Hermes scoped, expiring tool permissions. With Hands, let your remote
> Hermes work in a folder on your Mac or Linux machine while its memory and skills
> stay on the server. Choose the folder, access level, and duration locally.
> Hands requires no manually minted warrant.

Keep the operational disclosures in the catalog draft: optional listener,
commands/results sent to the server, network off by default, platform sandbox
requirements, and browser/MCP tools staying on the server.

## Before publication

- Verify the candidate commit through both Hermes install routes. Test a clean
  installed wheel outside the checkout, plus the source archive and bundled skills.
- Run release-artifact CI, unit/integration tests and real upstream Hermes dispatch
  tests. The wheel must be built from the source archive, not just the checkout.
- Complete a two-host Hands session with the candidate wheel on both ends:
  setup/pair, verify, read/write, sandbox exclusions, redaction and disconnect.
- Complete the first-session demo in Desktop and a messaging gateway on supported
  macOS/Linux devices; record Hermes versions. Backend tests do not prove UI behavior.
- Keep catalog/PyPI install instructions explicitly conditional until available.
- Check version agreement across pyproject, plugin manifest, source version and lockfile.
- Record outstanding validation below; do not publish with unchecked required gates.

## Publication and catalog order (separate approval/action)

1. Mark the changelog released and replace candidate README instructions with
   pinned `0.4.0` client instructions and the actual release commit server install.
2. Tag the reviewed commit `v0.4.0`; the publication workflow validates the tag,
   artifacts and isolated installed-wheel smoke checks before PyPI publication.
3. Verify a fresh `uvx --from hermes-tenuo==0.4.0 hermes-tenuo --version` and
   a full Hands session against the proposed catalog commit.
4. Update GitHub About using the short copy above. Suggested topics: hermes-agent,
   agents, security, authorization, sandbox, remote-workspace.
5. Replace the all-zero SHA in `plugin-catalog-entry.yaml` with the release commit
   and validate against current upstream catalog requirements. Submit upstream
   only after its review/age requirements and all first-session checks pass.
6. After the catalog update lands, switch default install examples back to the
   catalog command and verify it with the published client. Do not assume a
   source release alone updates the reviewed catalog pin.

## Candidate validation

Results and remaining gates are recorded in the preparation PR. Publication and
catalog repinning remain separate actions even if every automated check passes.
