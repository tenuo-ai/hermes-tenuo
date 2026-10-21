# Review a PR

Hand the review of the PR that [Fix an issue](../fix-issue/) opened to a second
agent: a separate Hermes profile with its own key, the way Hermes runs teams of
agents. Its warrant is issued from the first one with `--from`, so it can only
be narrower: read that one PR and leave review comments. It can't approve,
push, or touch another PR, and a request for more than the first agent holds is
refused when it is issued, not when the reviewer tries it.

Today the second agent usually gets a copy of the same token.

[`warrant.yaml`](warrant.yaml): `pull_request_read` (`get`, `get_diff`,
`get_files`) and `pull_request_review_write` (`create`, `COMMENT`) on PR #57,
for 30 minutes.

## Set it up

```bash
tenuo-cli key new reviewer                     # the reviewer profile's key
hermes -p reviewer …                           # its config: local_home, local_key: reviewer, the same github MCP server
cp recipes/review-pr/warrant.yaml review.yaml  # the PR number
tenuo-cli warrant issue --template review.yaml --holder reviewer \
    --from fix-412.warrant --out review-57.warrant
tenuo-cli session attach --session <reviewer's session ID> --file review-57.warrant --holder reviewer
```

## What it allows and refuses

| Call | Result |
|------|--------|
| `pull_request_read get_diff` on #57 | allowed |
| `pull_request_review_write create COMMENT` on #57 | allowed |
| the same with `event: APPROVE` | refused: Constraint 'event' not satisfied |
| `pull_request_read` on #58 | refused: Constraint 'pullNumber' not satisfied |
| `push_files` | refused: not authorized |
| issuing it with `APPROVE`, or any tool fix-issue lacks | refused at issue time (`MonotonicityError`) |

The chain records both agents: the reviewer's warrant carries the one it came
from, and each check verifies the whole chain.
