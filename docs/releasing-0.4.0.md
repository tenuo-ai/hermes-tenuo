# Preparing 0.4.0

This is a release candidate checklist, not an announcement. No release, PyPI
publication, live GitHub About edit or upstream catalog repin is performed by
this preparation PR.

## Copy to use at release

Short description (package, GitHub About and catalog summary):

> Signed, expiring tool permissions and local workspaces for Hermes Agent.

Expanded description:

> Tenuo warrants control which tools and arguments each task can use, including
> delegated agents. Hands lets your remote Hermes work in a folder on your Mac
> or Linux machine while memory and skills stay on the server. Use either feature
> independently or together.

Keep the operational disclosures in the catalog draft: optional listener,
commands/results sent to the server, network off by default, platform sandbox
requirements, and browser/MCP tools staying on the server.

## Testing before the release exists

The user guides describe the published 0.4.0 experience. The repository install
uses its default branch; Hermes `--ref` accepts a full commit SHA, not a version
tag. Until the PyPI package exists, maintainers test the candidate commit instead:

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
- Complete the first-session demo in Desktop on a supported device and record
  the Hermes version. Record messaging-gateway UI coverage separately; do not
  claim it from backend tests. Missing messaging UI coverage is a documented
  limitation, not a blocker for the independently validated core release.
- Do not announce the user walkthrough until the default branch includes the
  release and its PyPI package exists.
- Check version agreement across pyproject, plugin manifest, source version and lockfile.
- Record outstanding validation below; do not publish with unchecked required gates.

## Publication and catalog order (separate approval/action)

1. Mark the changelog released. Confirm the repository install resolves to the
   released code and the CLI comes from PyPI; keep candidate SHA substitutions
   in this checklist only.
2. Tag the reviewed commit `v0.4.0`; the publication workflow validates the tag,
   artifacts and isolated installed-wheel smoke checks before PyPI publication.
3. Verify a fresh `uvx --from hermes-tenuo==0.4.0 hermes-tenuo --version` and
   a full Hands session against the proposed catalog commit.
4. Update GitHub About using the short copy above. Suggested topics: hermes-agent,
   agents, authorization, warrants, hands, sandbox, remote-workspace.
5. Replace the all-zero SHA in `plugin-catalog-entry.yaml` with the release commit
   and validate against current upstream catalog requirements. Submit upstream
   only after its current review requirements and all first-session checks pass.
6. After the catalog update lands, switch default install examples back to the
   catalog command and verify it with the published client. Do not assume a
   source release alone updates the reviewed catalog pin.

## Candidate validation

Results and remaining gates are recorded in the preparation PR. Publication and
catalog repinning remain separate actions even if every automated check passes.

### Candidate code validation — 2026-11-11

Run against the default branch at `a0b0bfa` with the follow-up to the lost-result
change applied, an earlier candidate baseline, with
tenuo 0.3.6 and Hermes 0.23.1 (checkout `95fc3e6`).

- Unit and integration tests: 786 passed on macOS (Python 3.12) and 776 on
  Ubuntu 24.04 with bubblewrap; the Hermes-enabled tests passed under the
  installed Hermes.
- Role-based access through a real Hermes agent loop with a scripted model and
  real tool execution: per-sender roles, parallel calls, inline and background
  children, `execute_code`, shared sessions, API-server and webhook turns, and a
  scheduled run through Hermes's cron scheduler. Six malformed `access:` blocks
  each blocked every call.
- A 0.3-style static-warrant configuration behaved as it does on 0.3.1.
- With hermes-tenuo installed both by pip (0.3.1, then 0.4.0) and as a
  directory plugin, every tool call was blocked with the message naming both.
- Hands on macOS: first session, daily work, lifecycle, privacy exclusions,
  multi-person use, and the sandbox boundary checks.
- Lost and late results through Hermes's real terminal path: an answer just
  after Hermes's deadline, a result the hub gave up on, no answer at all, a
  laptop killed mid-command, a timeout the laptop confirmed, and a command that
  exits 124 by itself.
- A Hands session started with `--protect-git` on macOS: commits, branches,
  diffs and stashes worked; changing git settings, writing a hook and renaming
  the repository folder were refused.
- Wheel and source archive built; a clean install reported 0.4.0, and `doctor`
  and `status` were correct for a static warrant and for an `access:`-only home.

Not covered here: a live messaging-app conversation, and Windows.

### Desktop acceptance — 2026-11-11

Passed with Hermes Desktop 0.23.1+1096, Hermes backend 0.23.1, and the
0.4.0 wheel in a fresh local Python environment. The backend and device used
separate temporary state directories. Model credentials remained on the Mac.

- `/hands setup` displayed read/edit/online choices in Desktop.
- `/hands setup edit` produced a one-use invite; device preflight and pairing passed.
- `/hands verify` showed the chosen folder, read/write access and internet off.
- A real gpt-4o-mini conversation ran the invoice tests, observed two failures,
  edited `invoice.py`, and reran both tests successfully. An independent local
  test run passed and the original test file was byte-for-byte unchanged.
- Stopping the device made `/hands status` report it not answering;
  `/hands off` returned the conversation to server tools.
- Desktop was restored to its original local gateway and the test connection removed.

The supported repository-install command also passed in a separate fresh Hermes
home; `hermes plugins doctor hermes-tenuo` confirmed discovery, manifest parsing,
import and registration. A pre-existing multi-profile install hit an upstream
workspace collision with duplicate package names; the clean install did not.

This Desktop check used a loopback backend. The earlier GCP-to-Mac integration
run separately validated the two-host execution path. No messaging-app UI test
is claimed. CI, artifact checks and final PyPI smoke checks are recorded with the
release PR and publication run.


### Final candidate preparation — 2026-11-12

The candidate includes the Hands timeout follow-up (#79), Git protection (#78),
opt-in A2A feasibility work (#80), and MCP wrapping (#81). A2A remains experimental;
D1–D3 work in #82 is outside this release.

- Real Hermes 0.23.1 (`95fc3e668f`), with its complete runtime dependencies:
  36 Hands dispatch and timeout/output regressions passed on the merged candidate
  code (`55dd9f5`). Copilot has no remaining issues on #79.
- Built a source archive and then a wheel; artifact contents, version agreement,
  bundled skills and Twine checks passed.
- Installed the wheel with its MCP extra in a fresh environment outside the
  checkout. Version, CLI discovery and MCP gateway imports passed.
- The installed wheel passed local pairing, file read/write, secret redaction,
  sandbox write exclusions, macOS Git protection and disconnect checks.
- Both release workflows now test the MCP extra from the installed wheel. The
  publishing workflow also runs the MCP regression suite.
- The current catalog admission rules require an exact SHA and a reviewed
  upstream pin-update PR; the old two-week-age note has been removed.

Required gates still pending at this preparation commit:

- Repeat the two-host GCP-to-Mac Hands smoke with this candidate wheel on both
  endpoints. GCP reauthentication is currently required.
- Verify final merged-commit CI and artifact jobs, then publish the reviewed tag.
- Verify a fresh PyPI installation and Hands session before submitting the
  catalog repin. The catalog draft deliberately retains its placeholder until
  the final release commit is known.
