# Work on issues

Send "fix #412" from Telegram, or point a cron job at the issue queue, and let
Hermes take issues in one repository to pull requests on its own: read the issue
and the code, create a branch under `agent/`, push, open a PR into `main`,
comment on the issue. You issue the warrant once for the repository. It can't
push to `main` or any other branch, merge, close issues through the API, or read
another repository, which is what a poisoned issue asked for in the GitHub MCP
prompt-injection attack Invariant Labs published.

What Hermes and GitHub already do: Hermes can drop tools by name
(`tools.exclude: [merge_pull_request]`) and ask for approval on MCP writes; a
fine-grained token limits repositories and permissions. Neither checks the
branch a push goes to, the base of a PR, or the repository in each call, and the
token doesn't expire with the task. What the warrant adds: those arguments, on
every call, for a week.

Files: [`warrant.yaml`](warrant.yaml) for the repository;
[`one-issue.yaml`](one-issue.yaml) when you hand over a single issue and want
nothing else touched. Tool names are `mcp__github__…`, for a server configured in
Hermes as `github`.

## Set it up

```yaml
# Hermes config.yaml
mcp_servers:
  github:
    command: github-mcp-server
    args: [stdio, --toolsets, "issues,pull_requests,repos"]
    env: {GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"}
```

Give it a fine-grained token for this repository only, without the Workflows
permission, and protect `main` with required reviews.

```bash
tenuo-cli warrant issue --template ~/.tenuo/recipes/hermes/work-on-issues.yaml --holder agent \
  --set owner=your-org --set repo=your-repo --out issues.warrant
tenuo-cli hermes session attach --session telegram:<your user ID> --file issues.warrant
```

Attach it to whoever hands out the work: your user ID for issues sent from chat,
or `cron_<job_id>` for a job that picks up labelled issues.

## What it allows and refuses

| Call | Result |
|------|--------|
| `issue_read`, `get_file_contents` in the repo (any ref) | allowed |
| `create_branch agent/issue-412`, `push_files` to it | allowed |
| `create_pull_request` head `agent/…`, base `main` | allowed |
| `add_issue_comment` | allowed |
| `push_files` to `main`, or `create_branch release-1` | refused: Constraint 'branch' not satisfied |
| `create_pull_request` into `release` | refused: Constraint 'base' not satisfied |
| `merge_pull_request`, `issue_write` | refused: not authorized |
| `get_file_contents` in `your-org/private-payroll` | refused: Constraint 'repo' not satisfied |
| `pull_request_review_write` on any PR | refused: not authorized |

## Limits

- `files` is pushed as written. A push that adds `.github/workflows/…` runs that
  workflow on the agent's branch with the repository's secrets, which is why the
  token above has no Workflows permission.
- A PR body with "Closes #2" closes that issue when someone merges the PR.
- `get_file_contents` takes any `path`, because reading the code is the job.
  It's a path inside the one repository the warrant names, not on your machine,
  but it does mean the agent can read every file in that repository, including
  anything secret committed to it. `tenuo-cli warrant review` flags it for that
  reason. If parts of the repository are off limits, replace `any` with
  `{pattern: "src/*"}` or a list of folders.
- The warrant decides where code goes, not what it does; that's for the PR
  review.
