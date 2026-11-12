# Agent and contributor notes

This repository is public. Everything committed here, including docs, code comments, test names,
lab scripts, commit messages and PR descriptions, should make sense to an outside user and reveal
nothing internal.

Keep out of this repository:

- Planning vocabulary: milestones, phase labels, go/no-go decisions, internal team or agent workstream
  names, and branch names used for internal coordination.
- Names of unreleased products, and links to private repositories.
- Customer, prospect and partner names, and go-to-market plans.
- Internal hostnames, container, image and profile names, network addresses, usernames and local paths.
  Use placeholders such as `~/.hermes`, `100.64.0.10` or a required `IMG` setting.
- How the team accesses models or accounts.
- Secrets, keys and tokens. Tests use generated keys and obvious placeholders.

Write design and evidence docs as user-facing documentation: what was built, how it was tested and
its limits. Working notes and plans don't belong here.
