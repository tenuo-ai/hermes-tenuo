# Fix an issue

Send "fix #412" from Telegram and let Hermes take it to a pull request on its
own: read the issue and the code, create a branch, push, open the PR, comment
on the issue. This warrant holds it to that one issue, its own branch, and a PR
into `main`, for two hours. It can't push to `main`, merge, close issues, or
read any other repository, which is what a poisoned issue asked for in the
GitHub MCP prompt-injection attack Invariant Labs published.

A fine-grained token can limit repositories; it can't say "this issue, this
branch, this afternoon", and the same token is still there tomorrow.

[`warrant.yaml`](warrant.yaml) uses the GitHub MCP server's tool names as Hermes
registers them (`mcp__github__…`) for a server configured as `github`. It also
grants reading the PR and commenting on it, so the review can be handed on
([Review a PR](../review-pr/)).

## Set it up

In Hermes' `config.yaml`:

```yaml
mcp_servers:
  github:
    command: github-mcp-server
    args: [stdio, --toolsets, "issues,pull_requests,repos"]
    env: {GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"}
```

Per issue, edit the owner, repo, issue number and branch, then:

```bash
tenuo-cli warrant issue --template fix-issue.yaml --holder agent --out fix-412.warrant
hermes-tenuo session attach --session <the chat's session ID> --file fix-412.warrant
```

## What it allows and refuses

| Call | Result |
|------|--------|
| `issue_read` #412, `get_file_contents` in the repo | allowed |
| `create_branch agent/issue-412` from `main`, `push_files` to it | allowed |
| `create_pull_request` head `agent/issue-412`, base `main` | allowed |
| `add_issue_comment` on #412 | allowed |
| `push_files` to `main` | refused: Constraint 'branch' not satisfied |
| `merge_pull_request` | refused: Tool 'mcp__github__merge_pull_request' is not authorized |
| `get_file_contents` in `your-org/private-payroll` | refused: Constraint 'repo' not satisfied |
| `add_issue_comment` on #413 | refused: Constraint 'issue_number' not satisfied |
| `issue_write` (close the issue) | refused: not authorized |

## Limits

`create_branch` lists `from_branch: main`; the server treats it as optional, and
a call without it is refused with "missing required argument" until the model
passes it. What the pushed code does is reviewed in the PR, not by the warrant.
