# Recipes

Each recipe is a job people already run with Hermes, and a warrant that lets it
run without you watching. A warrant names the tools a session may call and the
argument values it may pass (this repo, this thread, this folder), for a set
time. Anything it doesn't name is refused before the tool runs.

| Recipe | You can now let Hermes… |
|--------|-------------------------|
| [Morning briefing](briefing/) | run a daily cron job that reads the web and writes notes, with no way to read your files or run commands |
| [House-sitter](house-sitter/) | answer your house-sitter for their stay: the guest room and nothing else, ending on its own |
| [Fix an issue](fix-issue/) | take one GitHub issue to a pull request: its own branch, never `main`, never a merge |
| [Review a PR](review-pr/) | hand the review to a second agent that can only read that PR and comment on it |
| [Reply to a thread](reply-to-thread/) | send the reply itself instead of a draft: one thread, one recipient, one hour |
| [Project task](project-task/) | work in one repo on its own: files under the project, only the commands you list |

## The same steps every time

```bash
hermes-tenuo setup                     # Tenuo workspace, plugin on, observe mode: nothing blocked
# use Hermes as usual for a day or two
tenuo-cli calls summary                # what it called, with which arguments, in which sessions
cp recipes/<recipe>/warrant.yaml .     # change the lines marked EDIT to your values
tenuo-cli template validate --file warrant.yaml
tenuo-cli warrant issue --template warrant.yaml --holder agent --out job.warrant
hermes-tenuo session attach --session <session or cron_JOB_ID> --file job.warrant
tenuo-cli calls summary                # still observing: what this warrant would allow and refuse
tenuo-cli mode enforce                 # the next call is checked
```

Without a clone of this repo, fetch a recipe with
`curl -O https://raw.githubusercontent.com/tenuo-ai/hermes-tenuo/main/recipes/<recipe>/warrant.yaml`.

`tenuo-cli calls list` shows each call's `run`, which is the Hermes session ID to
attach to. For a cron job, attach to `cron_<job_id>` (from `hermes cron list`):
one attach covers every run of that job.

Every argument a warrant names must be present and match, and every argument it
doesn't name is refused. `{}` after a tool name allows any arguments. If a model
leaves out or adds an argument the recipe doesn't expect, the refusal says which
one; observe mode shows these before anything is blocked.

These run on the unreleased local CLI ([tenuo#970](https://github.com/tenuo-ai/tenuo/pull/970))
and hermes-tenuo's `local_home` mode ([#47](https://github.com/tenuo-ai/hermes-tenuo/pull/47)).
`tests/test_recipes.py` checks every recipe file as shipped.
