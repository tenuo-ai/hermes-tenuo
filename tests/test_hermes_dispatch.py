"""delegate_task children and execute_code calls through Hermes's real dispatch.

Skipped unless ``hermes_cli`` is importable. Each scenario runs in a fresh
subprocess with its own ``HERMES_HOME``: the plugin is loaded by Hermes's
plugin loader, ``delegate_task`` goes through ``resolve_pre_tool_block``
(as the agent loop does), the child is announced with
``invoke_hook("subagent_start", ...)`` using the keyword arguments Hermes's
``delegate_tool`` sends, and child tool calls go through
``model_tools.handle_function_call``. A denied call must never reach the
handler, so the tests check that a secret file's contents never come back.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytest.importorskip("hermes_cli.plugins")
pytest.importorskip("model_tools")

SECRET = "PAYROLL-SECRET-7731"
PUBLIC = "PUBLIC-NOTES-4410"

_DRIVER = textwrap.dedent(
    """
    import base64, json, os, sys
    import yaml
    from tenuo import SigningKey, Subpath, Warrant, Wildcard

    home, data, scenario = os.environ["HERMES_HOME"], os.environ["HT_DATA"], os.environ["HT_SCENARIO"]
    b64 = lambda raw: base64.b64encode(raw).decode()
    root, agent = SigningKey.generate(), SigningKey.generate()
    parent = (Warrant.mint_builder().holder(agent.public_key)
              .capability("read_file", path=Subpath(data), _allow_unknown=True)
              .capability("web_search", query=Wildcard())
              .capability("delegate_task")
              .ttl(3600).mint(root))
    entry = {"warrant": b64(parent.to_bytes()), "trusted_root": b64(root.public_key.to_bytes()),
             "audit_log": False}
    if scenario.startswith("cw"):
        child = (Warrant.mint_builder().holder(agent.public_key)
                 .capability("read_file", path=Subpath(os.path.join(data, "pub")), _allow_unknown=True)
                 .ttl(600).mint(root))
        entry["child_warrant"] = b64(child.to_bytes())
    with open(os.path.join(home, "config.yaml"), "w") as fh:
        yaml.safe_dump({"plugins": {"enabled": ["hermes-tenuo"], "entries": {"hermes-tenuo": entry}}}, fh)
    os.environ["TENUO_SIGNING_KEY"] = b64(agent.secret_key_bytes())

    from hermes_cli.plugins import get_plugin_manager, invoke_hook, resolve_pre_tool_block
    get_plugin_manager().discover_and_load()
    import model_tools

    secret, public = os.path.join(data, "secret.txt"), os.path.join(data, "pub", "notes.txt")
    out = {}

    def delegate(parent_sid, args):
        return resolve_pre_tool_block("delegate_task", args, session_id=parent_sid, task_id="t-" + parent_sid)

    def start(parent_sid, child_sid, goal, subagent_id):
        invoke_hook("subagent_start", parent_session_id=parent_sid, child_session_id=child_sid,
                    parent_turn_id="", parent_subagent_id=None, child_subagent_id=subagent_id,
                    child_role="leaf", child_goal=goal)

    def read(path, **ids):
        return model_tools.handle_function_call("read_file", {"path": path}, **ids)

    if scenario in ("cw_single_goal", "cw_batch"):
        tasks = {"goal": "summarise"} if scenario == "cw_single_goal" else {
            "tasks": [{"goal": "a"}, {"goal": "b"}]}
        out["delegate"] = delegate("p", tasks)
        goals = ["summarise"] if scenario == "cw_single_goal" else ["a", "b"]
        for i, goal in enumerate(goals):
            start("p", f"c{i}", goal, f"sa-{i}-x")
            out[f"c{i}_secret"] = read(secret, session_id=f"c{i}", task_id=f"sa-{i}-x")
            out[f"c{i}_public"] = read(public, session_id=f"c{i}", task_id=f"sa-{i}-x")
        out["parent_secret"] = read(secret, session_id="p", task_id="t-p")
    elif scenario == "cw_toolsets_leave_nothing":
        out["delegate"] = delegate("p", {"goal": "g", "toolsets": ["web"]})
        start("p", "c0", "g", "sa-0-x")
        out["c0_public"] = read(public, session_id="c0", task_id="sa-0-x")
    elif scenario == "per_task_toolsets":
        out["delegate"] = delegate("p", {"tasks": [{"goal": "web only", "toolsets": ["web"]},
                                                   {"goal": "inherit"}]})
        # Announced out of order: grants follow the goal, not arrival order.
        start("p", "c1", "inherit", "sa-1-x")
        start("p", "c0", "web only", "sa-0-x")
        out["c0_public"] = read(public, session_id="c0", task_id="sa-0-x")
        out["c1_public"] = read(public, session_id="c1", task_id="sa-1-x")
    elif scenario == "unauthorised_child":
        read(public, session_id="p", task_id="t-p")
        start("p", "c0", "never delegated", "sa-0-x")
        out["c0_public"] = read(public, session_id="c0", task_id="sa-0-x")
    elif scenario == "cw_execute_code":
        out["delegate"] = delegate("p", {"goal": "summarise"})
        start("p", "c0", "summarise", "sa-0-x")
        # The child's own call (carries both ids); a different file, since
        # Hermes answers a repeated read of one file from its cache.
        read(os.path.join(data, "pub", "warm.txt"), session_id="c0", task_id="sa-0-x")
        # Calls from inside execute_code: Hermes sends the task id, no session id.
        out["child_script_secret"] = read(secret, task_id="sa-0-x")
        out["child_script_public"] = read(public, task_id="sa-0-x")
        out["unknown_task_secret"] = read(secret, task_id="sa-9-unknown")
        out["parent_script_secret"] = read(secret, task_id="t-p")
    print("RESULT " + json.dumps(out))
    """
)


def _run(scenario: str, tmp_path: Path) -> dict:
    home, data = tmp_path / "home", tmp_path / "data"
    (data / "pub").mkdir(parents=True)
    home.mkdir()
    (data / "secret.txt").write_text(SECRET)
    (data / "pub" / "notes.txt").write_text(PUBLIC)
    (data / "pub" / "warm.txt").write_text("warm")
    env = {k: v for k, v in os.environ.items() if not k.startswith("TENUO_")}
    env.update({"HERMES_HOME": str(home), "HOME": str(tmp_path), "HT_DATA": str(data),
                "HT_SCENARIO": scenario})
    proc = subprocess.run(
        [sys.executable, "-c", _DRIVER], cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    line = next(row for row in proc.stdout.splitlines() if row.startswith("RESULT "))
    return json.loads(line[len("RESULT "):])


def _ran(result: str, marker: str) -> bool:
    return marker in result


def _blocked(result: str) -> bool:
    return '"error"' in result and SECRET not in result and PUBLIC not in result


@pytest.mark.parametrize("scenario", ["cw_single_goal", "cw_batch"])
def test_child_warrant_applies_to_every_delegated_child(scenario, tmp_path):
    r = _run(scenario, tmp_path)
    assert r["delegate"] is None
    children = [k[:-len("_secret")] for k in r if k.startswith("c") and k.endswith("_secret")]
    assert children
    for c in children:
        assert _blocked(r[f"{c}_secret"]), r[f"{c}_secret"]
        assert _ran(r[f"{c}_public"], PUBLIC), r[f"{c}_public"]
    assert _ran(r["parent_secret"], SECRET)


def test_toolsets_that_leave_the_child_nothing_block_the_delegation(tmp_path):
    r = _run("cw_toolsets_leave_nothing", tmp_path)
    assert r["delegate"] and "no tools" in r["delegate"]
    assert _blocked(r["c0_public"]), r["c0_public"]


def test_per_task_toolsets_narrow_only_their_task(tmp_path):
    r = _run("per_task_toolsets", tmp_path)
    assert r["delegate"] is None
    assert _blocked(r["c0_public"]), r["c0_public"]
    assert _ran(r["c1_public"], PUBLIC), r["c1_public"]


def test_subagent_without_an_authorised_delegation_holds_nothing(tmp_path):
    r = _run("unauthorised_child", tmp_path)
    assert _blocked(r["c0_public"]), r["c0_public"]


def test_execute_code_calls_follow_the_session_that_ran_the_script(tmp_path):
    r = _run("cw_execute_code", tmp_path)
    assert r["delegate"] is None
    assert _blocked(r["child_script_secret"]), r["child_script_secret"]
    assert _ran(r["child_script_public"], PUBLIC), r["child_script_public"]
    assert _blocked(r["unknown_task_secret"]), r["unknown_task_secret"]
    assert _ran(r["parent_script_secret"], SECRET), r["parent_script_secret"]
