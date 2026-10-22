# Project task

Let Hermes work on one repository by itself with its own tools (`read_file`,
`search_files`, `write_file`, `patch`, `terminal`): files under the project,
exactly the commands you list, run in the project directory.

What Hermes already does: `approvals.deny` and the hardline blocklist refuse
known-dangerous commands, `command_allowlist` pre-approves commands that would
otherwise prompt (other commands still run), `HERMES_WRITE_SAFE_ROOT` keeps
writes under one root for the whole process, and `terminal.cwd` sets a starting
directory. Hermes' own docs call these defense in depth, not a boundary. What
the warrant adds: an allowlist, so only the exact commands listed run, in the
project directory, with reads and writes under the project, for this task.

[`warrant.yaml`](warrant.yaml): the five tools for four hours. Edit the project
path and the commands.

## Set it up

Issue and attach as in the other recipes. List each command exactly as it should
run: the warrant compares the whole string, so `pytest -q` doesn't allow
`pytest -q -p plugin` or `pytest; id`. Tell the task to use absolute paths under
the project: `billing/invoice.py` and `~/code/…` are checked as written and
refused.

The warrant requires `workdir` on every `terminal` call, so commands run in the
project and not wherever Hermes happens to be. Hermes often leaves it out, and
then the call is refused with `Constraint 'workdir' not satisfied: missing
required argument`. Tell the task to pass `workdir`. To see this before
enforcing, attach the warrant while still in observe mode: `tenuo-cli calls
summary` shows `denied_on: workdir` for those calls.

## What it allows and refuses

| Call | Result |
|------|--------|
| `read_file`, `search_files`, `patch` under the project | allowed |
| `terminal "pytest -q"` or `"git diff"` in the project | allowed |
| `read_file ~/.ssh/id_rsa`, or `…/billing/../../.hermes/.env` | refused: Constraint 'path' not satisfied |
| `terminal "git status \nrm -rf ~"` | refused: Constraint 'command' not satisfied |
| `terminal "git diff --output=/home/you/.bashrc"` | refused: Constraint 'command' not satisfied |
| `terminal "pytest -q"` with `workdir: /` | refused: Constraint 'workdir' not satisfied |
| `terminal "pytest -q"` with no `workdir` | refused: Constraint 'workdir' not satisfied: missing required argument |
| `terminal` with `background: true` | refused: unknown field not allowed |

## Limits

- Writing files and running the tests together is running code: a test or a
  `conftest.py` the agent writes runs when `pytest` does, and a `.git/config` it
  writes can run commands when `git` does. The warrant limits which commands
  start, not what the project's code does. For untrusted work, run Hermes'
  terminal in its Docker backend as well.
- Paths are checked as written. A symlink already in the project that points
  outside it is followed by the tools.
