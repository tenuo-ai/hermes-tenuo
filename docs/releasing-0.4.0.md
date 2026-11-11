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

## Testing before the release exists

The user guides describe the published 0.4.0 experience. Until the tag and PyPI
package exist, maintainers test the candidate commit instead:

```sh
hermes plugins install tenuo-ai/hermes-tenuo --ref COMMIT_SHA
hermes plugins enable hermes-tenuo
uvx --from 'git+https://github.com/tenuo-ai/hermes-tenuo.git@COMMIT_SHA' hermes-tenuo --version
```

Use that same CLI prefix for candidate commands, including generated setup
commands. This substitution belongs in release testing, not user onboarding.

## Before publication

- Verify the candidate commit through both Hermes install routes. Test a clean
  installed wheel outside the checkout, plus the source archive and bundled skills.
- Run release-artifact CI, unit/integration tests and real upstream Hermes dispatch
  tests. The wheel must be built from the source archive, not just the checkout.
- Complete a two-host Hands session with the candidate wheel on both ends:
  setup/pair, verify, read/write, sandbox exclusions, redaction and disconnect.
- Complete the first-session demo in Desktop and a messaging gateway on supported
  macOS/Linux devices; record Hermes versions. Backend tests do not prove UI behavior.
- Do not announce the user walkthrough until its v0.4.0 tag and PyPI package exist.
- Check version agreement across pyproject, plugin manifest, source version and lockfile.
- Record outstanding validation below; do not publish with unchecked required gates.

## Publication and catalog order (separate approval/action)

1. Mark the changelog released. Confirm the user guides target `v0.4.0` and the
   published CLI; keep prerelease testing substitutions in this checklist only.
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
