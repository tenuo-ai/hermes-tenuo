# Review PRs

Hand the review of the pull requests you name to a second agent: a separate
Hermes profile with its own key, the way Hermes runs teams of agents. It can read
those PRs and leave review comments. It can't approve, push, or touch another
PR, and because the warrant is bound to the reviewer's key, no other agent can
use it.

What Hermes and GitHub already do: a second profile can use a token with
read-only tools, but GitHub's permission to comment on a PR is the permission to
approve it, and a token covers every PR in the repositories it reaches. What the
warrant adds: these PR numbers, comments only, for a day.

[`warrant.yaml`](warrant.yaml): `pull_request_read` and
`pull_request_review_write` (`create`, `COMMENT`) on PRs 57 and 58.

## Set it up

```bash
tenuo-cli key new reviewer                           # the reviewer profile's key
hermes profile create reviewer                       # in its config: hermes-tenuo with
                                                     # local_home: ~/.tenuo and local_key: reviewer,
                                                     # and the same github MCP server
curl -O …/recipes/review-prs/warrant.yaml            # owner, repo, the PR numbers
tenuo-cli warrant issue --template warrant.yaml --holder reviewer --out review.warrant
hermes-tenuo session attach --session <reviewer's user ID or job> --file review.warrant --holder reviewer
```

New PRs to review: issue a warrant naming them and attach it alongside.

## What it allows and refuses

| Call | Result |
|------|--------|
| `pull_request_read` (`get`, `get_diff`, `get_files`, comments) on #57 or #58 | allowed |
| `pull_request_review_write create COMMENT` on #57 or #58 | allowed |
| the same with `event: APPROVE` | refused: Constraint 'event' not satisfied |
| `pull_request_read` on #59 | refused: Constraint 'pullNumber' not satisfied |
| `push_files` | refused: not authorized |
| the warrant attached to a profile with another key | refused: holder doesn't match |

## Handing it on from the issue agent

The issue agent can hand over its own authority instead: issue its warrant with
these two tools on the same PR numbers, then issue this one with
`--from issues.warrant`. It can only be narrower, a request for more (`APPROVE`)
is refused at issue time, and it stops when the issue agent's warrant expires or
is revoked.
