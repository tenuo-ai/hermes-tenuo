"""``max_uses`` in a delegation plan: how many times a child's grant may use a tool."""

import copy
import threading

import pytest
from tenuo import All, AnyOf, Regex, SigningKey, Warrant
import tenuo_core

from hermes_tenuo.delegation import DelegationPlanError, parse_plan
from hermes_tenuo.hermes_guard import HermesGuard

PUSH = {"binaries": ["git"], "patterns": [r"^git push origin fix/123$"]}

PLAN = {
    "version": 1,
    "root": {"tools": {"terminal": {"command": PUSH}, "delegate_task": {}}},
    "levels": [
        {
            "role": "pusher",
            "ttl_seconds": 300,
            "tools": {"terminal": {"max_uses": 1, "command": PUSH}},
        },
    ],
}

NESTED = {
    "version": 1,
    "root": {"tools": {"terminal": {"command": PUSH}, "delegate_task": {}}},
    "levels": [
        {
            "ttl_seconds": 300,
            "tools": {"terminal": {"max_uses": 2, "command": PUSH}, "delegate_task": {"max_uses": 1}},
        },
        {"ttl_seconds": 120, "tools": {"terminal": {"command": PUSH}}},
    ],
}


def _guard(plan, **kwargs):
    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    constraint = All([tenuo_core.Shlex(allow=PUSH["binaries"]), AnyOf([Regex(p) for p in PUSH["patterns"]])])
    builder = Warrant.mint_builder().holder(agent_key.public_key).capability("delegate_task")
    for tool in plan["root"]["tools"]:
        if tool.removeprefix("tool:") == "terminal":
            builder.capability(tool, command=constraint)
        elif tool != "delegate_task":
            builder.capability(tool)
    warrant = builder.ttl(3600).mint(root_key)
    events = []
    guard = HermesGuard(
        warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key],
        delegation_plan=parse_plan(plan), audit_callback=events.append, **kwargs,
    )
    return guard, events


def _push(guard, session, call_id="", **kwargs):
    return guard.pre_tool_call(
        "terminal", {"command": "git push origin fix/123"}, session_id=session, tool_call_id=call_id, **kwargs,
    )


def _delegate(guard, parent, child, goal="push the fix", call_id=""):
    blocked = guard.pre_tool_call("delegate_task", {"goal": goal}, session_id=parent, tool_call_id=call_id)
    if blocked is None:
        guard.on_subagent_start(parent_session_id=parent, child_session_id=child, child_goal=goal)
    return blocked


def test_a_child_uses_the_tool_once_then_is_refused():
    guard, events = _guard(PLAN)
    assert _delegate(guard, "s0", "s1") is None
    assert _push(guard, "s1") is None
    refused = _push(guard, "s1")
    assert refused["action"] == "block"
    assert "use limit reached" in refused["message"] and "terminal 1 time" in refused["message"]
    assert _push(guard, "s1") is not None  # and stays refused
    assert [e.decision for e in events if e.tool == "terminal"] == ["ALLOW", "DENY", "DENY"]
    assert "use limit" in events[-1].reason


def test_a_call_the_warrant_refuses_takes_no_use():
    guard, _ = _guard(PLAN)
    _delegate(guard, "s0", "s1")
    assert guard.pre_tool_call("terminal", {"command": "git push origin main"}, session_id="s1") is not None
    assert _push(guard, "s1") is None


def test_each_delegation_gets_its_own_count_and_the_parent_has_none():
    guard, _ = _guard(PLAN)
    _delegate(guard, "s0", "s1", goal="first")
    _delegate(guard, "s0", "s2", goal="second")
    assert _push(guard, "s1") is None
    assert _push(guard, "s2") is None
    assert _push(guard, "s1") is not None
    assert _push(guard, "s2") is not None
    for _ in range(3):
        assert _push(guard, "s0") is None  # the plan sets no limit on the parent


def test_grants_below_share_the_limit_of_the_grant_above():
    guard, _ = _guard(NESTED)
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1") is None                # 1 of the child's 2
    assert _delegate(guard, "s1", "s2") is None
    assert _push(guard, "s2") is None                # the grandchild takes the 2nd
    assert _push(guard, "s2") is not None            # nothing left above it
    assert _push(guard, "s1") is not None


def test_delegating_can_be_limited_too():
    guard, _ = _guard(NESTED)
    _delegate(guard, "s0", "s1")
    assert _delegate(guard, "s1", "s2", goal="a") is None
    refused = _delegate(guard, "s1", "s3", goal="b")
    assert refused is not None and "delegate_task 1 time" in refused["message"]


def test_a_delegation_that_is_rejected_gives_its_use_back():
    plan = copy.deepcopy(NESTED)
    guard, _ = _guard(plan)
    _delegate(guard, "s0", "s1")
    # A toolset that leaves the child with no tools is rejected after the warrant allowed the call.
    rejected = guard.pre_tool_call(
        "delegate_task", {"goal": "x", "toolsets": ["no-such-toolset"]}, session_id="s1",
    )
    assert rejected is not None and "use limit" not in rejected["message"]
    assert _delegate(guard, "s1", "s2") is None


def test_concurrent_calls_cannot_exceed_the_limit():
    plan = copy.deepcopy(PLAN)
    plan["levels"][0]["tools"]["terminal"]["max_uses"] = 5
    guard, _ = _guard(plan)
    _delegate(guard, "s0", "s1")
    allowed, start = [], threading.Barrier(16)

    def call():
        start.wait()
        if _push(guard, "s1") is None:
            allowed.append(1)

    threads = [threading.Thread(target=call) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(allowed) == 5


def test_log_only_mode_reports_the_limit_without_blocking():
    guard, events = _guard(PLAN, on_denial="log")
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1") is None
    assert _push(guard, "s1") is None
    assert [e.decision for e in events if e.tool == "terminal"] == ["ALLOW", "DENY"]


def test_a_retired_child_stays_refused():
    guard, _ = _guard(PLAN)
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1") is None
    guard.clear_session_warrant("s1")
    assert _push(guard, "s1") is not None


# Hermes builds whose tool registry checks a call after the plugin hook did.

def test_hook_then_registry_check_of_one_call_takes_one_use():
    plan = copy.deepcopy(PLAN)
    plan["levels"][0]["tools"]["terminal"]["max_uses"] = 2
    guard, _ = _guard(plan)
    guard._registry_enforces = True
    _delegate(guard, "s0", "s1")
    for call_id in ("call_1", "call_2"):
        assert _push(guard, "s1", call_id) is None
        assert _push(guard, "s1", call_id, registry_check=True) is None
    assert _push(guard, "s1", "call_3") is not None


def test_a_registry_only_call_takes_a_use():
    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1", "call_1", registry_check=True) is None
    assert _push(guard, "s1", "call_2", registry_check=True) is not None


def test_a_repeated_call_id_cannot_add_uses():
    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1", "call_1") is None
    assert _push(guard, "s1", "call_1") is not None                       # the hook always takes a use
    assert _push(guard, "s1", "call_1", registry_check=True) is None      # the first call's own second check
    assert _push(guard, "s1", "call_1", registry_check=True) is not None  # and only that one


def test_without_a_registry_check_a_repeated_call_id_gets_no_pass():
    guard, _ = _guard(PLAN)
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1", "call_1") is None
    assert _push(guard, "s1", "call_1", registry_check=True) is not None


# Plan format.

@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1", None, []])
def test_max_uses_must_be_a_positive_integer(value):
    plan = copy.deepcopy(PLAN)
    plan["levels"][0]["tools"]["terminal"]["max_uses"] = value
    with pytest.raises(DelegationPlanError, match="max_uses must be a positive integer"):
        parse_plan(plan)


def test_max_uses_is_refused_on_the_root():
    plan = copy.deepcopy(PLAN)
    plan["root"]["tools"]["terminal"]["max_uses"] = 1
    with pytest.raises(DelegationPlanError, match="only supported in levels"):
        parse_plan(plan)


def test_a_level_cannot_raise_the_limit_of_the_level_above():
    plan = copy.deepcopy(NESTED)
    plan["levels"][1]["tools"]["terminal"]["max_uses"] = 3
    with pytest.raises(DelegationPlanError, match="larger than the level above"):
        parse_plan(plan)
    plan["levels"][1]["tools"]["terminal"]["max_uses"] = 2
    assert parse_plan(plan).levels[1].max_uses == {"terminal": 2}


def test_max_uses_is_never_read_as_an_argument_name():
    plan = copy.deepcopy(PLAN)
    plan["levels"][0]["tools"]["terminal"]["max_uses"] = {"range": [1, 1]}
    with pytest.raises(DelegationPlanError, match="max_uses must be a positive integer"):
        parse_plan(plan)


def test_plans_without_max_uses_are_unchanged():
    plan = copy.deepcopy(PLAN)
    del plan["levels"][0]["tools"]["terminal"]["max_uses"]
    guard, _ = _guard(plan)
    _delegate(guard, "s0", "s1")
    for _ in range(4):
        assert _push(guard, "s1") is None
    assert guard._session_uses == {}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("first_tool", ["terminal", "tool:terminal"])
def test_aliases_share_the_stricter_limit_regardless_of_entry_order(reverse, first_tool):
    plan = copy.deepcopy(PLAN)
    plan["root"]["tools"]["tool:terminal"] = {"command": PUSH}
    entries = [("terminal", {"max_uses": 1, "command": PUSH}),
               ("tool:terminal", {"max_uses": 3, "command": PUSH})]
    plan["levels"][0]["tools"] = dict(reversed(entries) if reverse else entries)
    guard, _ = _guard(plan)
    assert _delegate(guard, "s0", "s1") is None
    assert guard.pre_tool_call(first_tool, {"command": "git push origin fix/123"}, session_id="s1") is None
    for tool in ("terminal", "tool:terminal"):
        refused = guard.pre_tool_call(tool, {"command": "git push origin fix/123"}, session_id="s1")
        assert refused is not None and "terminal 1 time" in refused["message"]


def test_rejected_delegation_does_not_leave_a_refunded_registry_pass(monkeypatch):
    guard, _ = _guard(NESTED)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    args = {"goal": "first"}
    with monkeypatch.context() as patch:
        patch.setattr(guard, "_register_planned_children", lambda *a: {"action": "block", "message": "rejected"})
        assert guard.pre_tool_call("delegate_task", args, session_id="s1", tool_call_id="retry") is not None
    # A registry-only retry must spend the returned use, not redeem a free pass.
    assert guard.pre_tool_call(
        "delegate_task", args, session_id="s1", tool_call_id="retry", registry_check=True,
    ) is None
    guard.on_subagent_start(parent_session_id="s1", child_session_id="s2", child_goal="first")
    refused = _delegate(guard, "s1", "s3", goal="second", call_id="next")
    assert refused is not None and "delegate_task 1 time" in refused["message"]


@pytest.mark.parametrize("status", ["blocked", "cancelled", "error", "success"])
@pytest.mark.parametrize("call_id", ["", "call_1"])
def test_completed_invocations_cannot_leave_registry_passes(status, call_id):
    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    assert _push(guard, "s1", call_id) is None
    guard.post_tool_call("terminal", {"command": "git push origin fix/123"}, "done",
                        session_id="s1", tool_call_id=call_id, status=status)
    assert _push(guard, "s1", call_id, registry_check=True) is not None
    assert _push(guard, "s1", registry_check=True) is not None


def test_middleware_correlates_registry_without_tool_call_id():
    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    assert _push(guard, "s1", "call_1") is None
    # Hermes supplies the ID to middleware but omits it in registry.dispatch.
    result = guard.around_tool_call(
        tool_name="terminal", args={"command": "git push origin fix/123"},
        session_id="s1", tool_call_id="call_1",
        next_call=lambda args: guard.pre_tool_call("terminal", args, session_id="s1", registry_check=True),
    )
    assert result is None
    assert _push(guard, "s1", registry_check=True) is not None


@pytest.mark.parametrize("raises", [False, True])
def test_middleware_discards_pass_when_dispatch_does_not_run(raises):
    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    assert _push(guard, "s1", "call_1") is None

    def stopped(args):
        if raises:
            raise RuntimeError("cancelled")
        return "blocked by another middleware"

    def invoke():
        return guard.around_tool_call(
            tool_name="terminal", args={"command": "git push origin fix/123"},
            session_id="s1", tool_call_id="call_1", next_call=stopped,
        )

    if raises:
        with pytest.raises(RuntimeError, match="cancelled"):
            invoke()
    else:
        assert invoke() == "blocked by another middleware"
    assert _push(guard, "s1", "call_1", registry_check=True) is not None


def test_finishing_one_call_preserves_another_inflight_call():
    plan = copy.deepcopy(PLAN)
    plan["levels"][0]["tools"]["terminal"]["max_uses"] = 2
    guard, _ = _guard(plan)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    assert _push(guard, "s1", "blocked") is None
    assert _push(guard, "s1", "running") is None
    guard.post_tool_call("terminal", {"command": "git push origin fix/123"}, "blocked",
                        session_id="s1", tool_call_id="blocked", status="blocked")
    assert _push(guard, "s1", "running", registry_check=True) is None
    assert _push(guard, "s1", "blocked", registry_check=True) is not None


@pytest.mark.parametrize("hook_inside_middleware", [False, True])
def test_concurrent_unkeyed_calls_keep_separate_passes(hook_inside_middleware):
    plan = copy.deepcopy(PLAN)
    plan["levels"][0]["tools"]["terminal"]["max_uses"] = 2
    guard, _ = _guard(plan)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    hooks_finished = threading.Barrier(2)
    first_finished = threading.Event()
    results, errors = {}, []
    args = {"command": "git push origin fix/123"}

    def worker(index):
        try:
            payload = dict(args)
            if not hook_inside_middleware:
                assert guard.pre_tool_call("terminal", payload, session_id="s1") is None

            def dispatch(payload):
                if hook_inside_middleware:
                    assert _push(guard, "s1") is None
                hooks_finished.wait(timeout=5)
                if index:
                    assert first_finished.wait(timeout=5)
                return guard.pre_tool_call("terminal", payload, session_id="s1", registry_check=True)

            results[index] = guard.around_tool_call(
                tool_name="terminal", args=payload, session_id="s1", next_call=dispatch,
            )
            guard.post_tool_call("terminal", payload, "done", session_id="s1", status="success")
        except Exception as exc:
            errors.append(exc)
        finally:
            if not index:
                first_finished.set()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)
    assert not errors
    assert results == {0: None, 1: None}
    assert _push(guard, "s1", registry_check=True) is not None


def test_unkeyed_mcp_pass_cleanup_ignores_the_proof_carrier():
    from hermes_tenuo.mcp_proofs import CARRIER

    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    wrapper = "mcp__test__terminal"
    guard._mcp_resolver = lambda name: "terminal" if name == wrapper else None
    assert _delegate(guard, "s0", "s1") is None
    args = {"command": "git push origin fix/123"}
    proof_args = {**args, CARRIER: {"proof": "test"}}

    def stopped(payload):
        assert guard.pre_tool_call(wrapper, payload, session_id="s1") is None
        return "blocked"

    # The hook strips the proof, but cleanup receives the original arguments.
    assert guard.around_tool_call(
        tool_name=wrapper, args=proof_args, session_id="s1", next_call=stopped,
    ) == "blocked"
    assert guard.pre_tool_call(wrapper, proof_args, session_id="s1", registry_check=True) is not None


@pytest.mark.parametrize("blocked", [False, True])
def test_unkeyed_hook_worker_hands_off_to_caller_and_post_worker(blocked):
    from concurrent.futures import ThreadPoolExecutor

    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    args = {"command": "git push origin fix/123"}
    with ThreadPoolExecutor(max_workers=1) as worker:
        assert worker.submit(guard.pre_tool_call, "terminal", args, session_id="s1").result() is None
        if blocked:
            worker.submit(guard.post_tool_call, "terminal", args, "blocked",
                          session_id="s1", status="blocked").result()
        else:
            assert guard.around_tool_call(
                tool_name="terminal", args=args, session_id="s1",
                next_call=lambda payload: guard.pre_tool_call("terminal", payload, session_id="s1", registry_check=True),
            ) is None
    assert guard.pre_tool_call("terminal", args, session_id="s1", registry_check=True) is not None


@pytest.mark.parametrize("call_id", ["", "rewrite"])
@pytest.mark.parametrize("allowed", [False, True])
def test_argument_rewrites_reuse_only_this_invocations_reservation(monkeypatch, call_id, allowed):
    monkeypatch.setitem(PUSH, "patterns", [r"^git push origin fix/(123|456)$"])
    guard, _ = _guard(PLAN)
    guard._registry_enforces = True
    assert _delegate(guard, "s0", "s1") is None
    args = {"command": "git push origin fix/123"}
    assert guard.pre_tool_call("terminal", args, session_id="s1", tool_call_id=call_id) is None

    def rewrite_and_dispatch(payload):
        final_args = {"command": "git push origin fix/456" if allowed else "git push origin main"}
        return guard.pre_tool_call("terminal", final_args, session_id="s1", registry_check=True)

    result = guard.around_tool_call(
        tool_name="terminal", args=args, session_id="s1", tool_call_id=call_id,
        next_call=rewrite_and_dispatch,
    )
    assert (result is None) == allowed
    assert guard.pre_tool_call("terminal", args, session_id="s1", tool_call_id=call_id,
                               registry_check=True) is not None


def test_plugin_bridge_preserves_empty_unkeyed_arguments_across_workers():
    from concurrent.futures import ThreadPoolExecutor
    from hermes_tenuo._guard import PluginGuard

    plan = {"version": 1, "root": {"tools": {"delegate_task": {}, "ping": {}}},
            "levels": [{"ttl_seconds": 300, "tools": {"ping": {"max_uses": 1}}}]}
    guard, _ = _guard(plan)
    plugin = PluginGuard(guard)
    plugin.registry_enforces()
    assert _delegate(guard, "s0", "s1") is None
    args = {}
    with ThreadPoolExecutor(max_workers=1) as worker:
        assert worker.submit(plugin.pre_tool_call_hook, tool_name="ping", args=args, session_id="s1").result() is None
    assert plugin.around_tool_call(
        tool_name="ping", args=args, session_id="s1",
        next_call=lambda payload: plugin.pre_tool_call_hook(
            tool_name="ping", args=payload, session_id="s1", registry_check=True),
    ) is None
    assert plugin.pre_tool_call_hook(tool_name="ping", args=args, session_id="s1", registry_check=True) is not None


@pytest.mark.parametrize("reverse", [False, True])
def test_plan_validation_compares_effective_alias_limits(reverse):
    plan = copy.deepcopy(NESTED)
    plan["root"]["tools"]["tool:terminal"] = {"command": PUSH}
    parent = [("terminal", {"command": PUSH, "max_uses": 1}),
              ("tool:terminal", {"command": PUSH, "max_uses": 3}), ("delegate_task", {})]
    child = [("terminal", {"command": PUSH, "max_uses": 2}),
             ("tool:terminal", {"command": PUSH, "max_uses": 1})]
    plan["levels"][0]["tools"] = dict(reversed(parent) if reverse else parent)
    plan["levels"][1]["tools"] = dict(reversed(child) if reverse else child)
    guard, _ = _guard(plan)  # Both levels have an effective terminal limit of 1.
    assert _delegate(guard, "s0", "s1") is None
    assert _delegate(guard, "s1", "s2") is None
    assert _push(guard, "s2") is None
    assert _push(guard, "s2") is not None
    assert _push(guard, "s1") is not None


def test_plan_validation_preserves_limits_across_an_omitting_level():
    plan = copy.deepcopy(NESTED)
    plan["levels"][1]["tools"]["delegate_task"] = {}
    plan["levels"].append({"ttl_seconds": 60, "tools": {"terminal": {"command": PUSH, "max_uses": 3}}})
    with pytest.raises(DelegationPlanError, match="larger than the level above"):
        parse_plan(plan)


# What the audit log records.

def test_the_audit_record_carries_the_use_and_the_grant_it_counts_against():
    guard, events = _guard(NESTED)
    _delegate(guard, "s0", "s1")
    child_grant = str(guard._resolve_warrant("s1")[0].id)
    _push(guard, "s1")
    assert events[-1].decision == "ALLOW"
    assert events[-1].use == {"count": 1, "limit": 2, "grant": child_grant}
    _delegate(guard, "s1", "s2")
    assert events[-1].tool == "delegate_task" and events[-1].use == {"count": 1, "limit": 1, "grant": child_grant}
    _push(guard, "s2")  # the grandchild has no limit of its own: the use counts against the child's
    assert events[-1].use == {"count": 2, "limit": 2, "grant": child_grant}
    assert events[-1].warrant_id != child_grant
    refused = _push(guard, "s2")
    assert "the grant this one was delegated from allows terminal 2 times" in refused["message"]
    assert events[-1].decision == "DENY" and events[-1].use == {"count": 2, "limit": 2, "grant": child_grant}


def test_calls_without_a_limit_carry_no_use():
    guard, events = _guard(PLAN)
    _delegate(guard, "s0", "s1")
    _push(guard, "s0")
    assert events[0].use is None and events[-1].use is None
    assert guard.pre_tool_call("terminal", {"command": "git push origin main"}, session_id="s1") is not None
    assert events[-1].decision == "DENY" and events[-1].use is None  # refused by the warrant, not the limit


def test_a_rejected_delegation_is_recorded_without_a_use():
    guard, events = _guard(NESTED)
    _delegate(guard, "s0", "s1")
    guard.pre_tool_call("delegate_task", {"goal": "x", "toolsets": ["no-such-toolset"]}, session_id="s1")
    assert events[-1].decision == "DENY" and events[-1].use is None


def _logged(tmp_path, plan):
    from hermes_tenuo.audit import LocalAuditLog

    guard, _ = _guard(plan)
    guard._audit_callback = LocalAuditLog(tmp_path / "audit.jsonl")
    return guard, tmp_path / "audit.jsonl"


def test_the_log_file_shows_each_call_once_when_sessions_reuse_call_ids(tmp_path):
    """Two children whose model numbers its calls call_0, call_1 in every session."""
    import json

    from hermes_tenuo.audit import format_record, read_audit_log

    guard, path = _logged(tmp_path, PLAN)
    assert _delegate(guard, "s0", "a", goal="first", call_id="call_0") is None
    assert _delegate(guard, "s0", "b", goal="second", call_id="call_1") is None
    push = {"command": "git push origin fix/123"}
    for session in ("a", "b"):                       # both first calls are in flight together
        assert _push(guard, session, "call_0") is None
    for session in ("a", "b"):
        guard.post_tool_call("terminal", push, "ok", session_id=session, tool_call_id="call_0",
                             duration_ms=20, status="ok")
        assert _push(guard, session, "call_1") is not None
        guard.post_tool_call("terminal", push, "", session_id=session, tool_call_id="call_1", status="blocked")
    for call_id, goal in (("call_0", "first"), ("call_1", "second")):
        guard.post_tool_call("delegate_task", {"goal": goal}, "done", session_id="s0", tool_call_id=call_id,
                             duration_ms=90, status="ok")

    raw = [json.loads(line) for line in path.read_text().splitlines()]
    assert not [r for r in raw if r["reason"] == "post-dispatch"]  # every completion found its decision
    assert "use" not in raw[0] and raw[2]["use"]["count"] == 1     # only limited calls carry a use

    rows = read_audit_log(path)
    seen = [(r["session_id"], r["tool"], r["tool_call_id"], r["decision"]) for r in rows]
    assert sorted(seen) == sorted([
        ("s0", "delegate_task", "call_0", "ALLOW"), ("s0", "delegate_task", "call_1", "ALLOW"),
        ("a", "terminal", "call_0", "ALLOW"), ("a", "terminal", "call_1", "DENY"),
        ("b", "terminal", "call_0", "ALLOW"), ("b", "terminal", "call_1", "DENY"),
    ])
    allowed = [r for r in rows if r["tool"] == "terminal" and r["decision"] == "ALLOW"]
    assert all(r["duration_ms"] == 20 and r["outcome"] == "Hermes dispatch: ok" for r in allowed)
    assert all(r["use"] == {"count": 1, "limit": 1, "grant": r["warrant_id"]} for r in allowed)
    assert "(use 1 of 1)" in format_record(allowed[0])
    assert "use limit reached" in format_record(next(r for r in rows if r["decision"] == "DENY"))


def test_a_reused_call_id_in_a_later_turn_is_a_new_row(tmp_path):
    from hermes_tenuo.audit import read_audit_log

    plan = copy.deepcopy(PLAN)
    plan["levels"][0]["tools"]["terminal"]["max_uses"] = 2
    guard, path = _logged(tmp_path, plan)
    _delegate(guard, "s0", "s1")
    push = {"command": "git push origin fix/123"}
    for _turn in range(3):                            # the same id on every turn of one session
        blocked = _push(guard, "s1", "call_0")
        guard.post_tool_call("terminal", push, "", session_id="s1", tool_call_id="call_0",
                             duration_ms=0 if blocked else 5, status="blocked" if blocked else "ok")
    rows = [r for r in read_audit_log(path) if r["tool"] == "terminal"]
    assert [r["decision"] for r in rows] == ["ALLOW", "ALLOW", "DENY"]
    assert [r["use"]["count"] for r in rows] == [1, 2, 2]


# Plan entries that would leave a limit unclear.



def test_the_limit_applies_whichever_way_the_tool_is_named():
    plan = copy.deepcopy(PLAN)
    for level in (plan["root"], plan["levels"][0]):
        level["tools"]["tool:terminal"] = level["tools"].pop("terminal")
    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    constraint = All([tenuo_core.Shlex(allow=PUSH["binaries"]), AnyOf([Regex(p) for p in PUSH["patterns"]])])
    warrant = (Warrant.mint_builder().holder(agent_key.public_key)
               .capability("tool:terminal", command=constraint).capability("delegate_task").ttl(3600).mint(root_key))
    guard = HermesGuard(warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key],
                        delegation_plan=parse_plan(plan))
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1") is None
    assert _push(guard, "s1") is not None
    assert guard.pre_tool_call("tool:terminal", {"command": "git push origin fix/123"}, session_id="s1") is not None


def test_a_deeper_level_cannot_raise_a_limit_by_renaming_the_tool():
    plan = copy.deepcopy(NESTED)
    plan["root"]["tools"]["tool:terminal"] = plan["root"]["tools"].pop("terminal")
    plan["levels"][0]["tools"]["tool:terminal"] = plan["levels"][0]["tools"].pop("terminal")
    del plan["levels"][1]["tools"]["terminal"]
    plan["levels"][1]["tools"]["tool:terminal"] = {"max_uses": 9, "command": PUSH}
    with pytest.raises(DelegationPlanError, match="larger than the level above"):
        parse_plan(plan)


# A session the guard has no grant for gets nothing, limit or not.

def test_a_child_under_a_new_session_id_holds_no_authority():
    guard, _ = _guard(PLAN)
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1") is None
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1-again", child_goal="push the fix")
    assert _push(guard, "s1-again") is not None
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1", child_goal="push the fix")  # replayed
    assert _push(guard, "s1") is not None


# hermes-tenuo mint --plan

def test_mint_with_a_plan_makes_a_warrant_that_delegates_under_it(tmp_path, capsys, monkeypatch):
    import argparse
    import base64
    import json

    from hermes_tenuo.cli import cmd_mint
    from hermes_tenuo.delegation import load_plan

    monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(PLAN))
    path.chmod(0o600)
    assert cmd_mint(argparse.Namespace(ttl="1h", allow=["web_search"], output="env", plan=str(path))) == 0
    env = dict(line.removeprefix("export ").split("=", 1) for line in capsys.readouterr().out.splitlines())
    assert env["TENUO_DELEGATION_PLAN"] == str(path.resolve())
    guard = HermesGuard(
        warrant=Warrant.from_bytes(base64.b64decode(env["TENUO_WARRANT"])),
        signing_key=SigningKey.from_bytes(base64.b64decode(env["TENUO_SIGNING_KEY"])),
        trusted_roots=[tenuo_core.PublicKey.from_bytes(base64.b64decode(env["TENUO_TRUSTED_ROOT"]))],
        delegation_plan=load_plan(env["TENUO_DELEGATION_PLAN"]),
    )
    assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="s0") is None
    assert _delegate(guard, "s0", "s1") is None
    assert _push(guard, "s1") is None
    assert _push(guard, "s1") is not None

    assert cmd_mint(argparse.Namespace(ttl="1h", allow=None, output="full", plan=str(path))) == 0
    out = capsys.readouterr().out
    assert f"delegation_plan: {path.resolve()}" in out and "depth 1: terminal (at most 1 use)" in out


def test_mint_refuses_a_tool_the_plan_already_grants(tmp_path, capsys):
    import argparse
    import json

    from hermes_tenuo.cli import cmd_mint

    path = tmp_path / "plan.json"
    path.write_text(json.dumps(PLAN))
    path.chmod(0o600)
    assert cmd_mint(argparse.Namespace(ttl="1h", allow=["terminal"], output="env", plan=str(path))) == 1
    assert "already granted by the plan's root" in capsys.readouterr().err
    path.chmod(0o666)
    assert cmd_mint(argparse.Namespace(ttl="1h", allow=None, output="env", plan=str(path))) == 1
    assert "must not be writable" in capsys.readouterr().err


def test_a_control_action_takes_a_use_of_delegate_task():
    guard, events = _guard(NESTED)
    _delegate(guard, "s0", "s1")
    assert guard.pre_tool_call("delegate_task", {"action": "list"}, session_id="s1") is None
    assert events[-1].use["count"] == 1
    refused = _delegate(guard, "s1", "s2")
    assert refused is not None and "use limit reached" in refused["message"]


# Findings from adversarial testing.

def test_a_child_keeps_its_grant_and_count_when_its_session_id_changes():
    """Hermes can continue a child under a new session id; the task id stays."""
    guard, events = _guard(PLAN)
    assert guard.pre_tool_call("delegate_task", {"goal": "push the fix"}, session_id="s0", task_id="s0") is None
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1", child_goal="push the fix",
                            child_subagent_id="sa-0-abc")
    push = {"command": "git push origin fix/123"}
    assert guard.pre_tool_call("terminal", push, session_id="s1", task_id="sa-0-abc") is None
    child_grant = events[-1].warrant_id

    # same task, new session id, never announced
    refused = guard.pre_tool_call("terminal", push, session_id="s1-b", task_id="sa-0-abc")
    assert refused is not None and "use limit reached" in refused["message"]
    assert events[-1].warrant_id == child_grant and events[-1].session_id == "s1-b"
    other = guard.pre_tool_call("terminal", {"command": "git push origin main"}, session_id="s1-b", task_id="sa-0-abc")
    assert other is not None  # still the child's narrow grant, not the parent's
    assert guard.pre_tool_call("terminal", push, session_id="s1", task_id="sa-0-abc") is not None  # old id retired
    assert guard.pre_tool_call("terminal", push, session_id="s0", task_id="s0") is None  # the parent is untouched


def test_a_child_that_changes_session_id_before_its_first_call_keeps_its_grant():
    guard, events = _guard(PLAN)
    guard.pre_tool_call("delegate_task", {"goal": "push the fix"}, session_id="s0", task_id="s0")
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1", child_goal="push the fix",
                            child_subagent_id="sa-0-abc")
    push = {"command": "git push origin fix/123"}
    assert guard.pre_tool_call("terminal", push, session_id="s1-b", task_id="sa-0-abc") is None
    assert events[-1].use["count"] == 1 and events[-1].parent_warrant_ids
    assert guard.pre_tool_call("terminal", push, session_id="s1-b", task_id="sa-0-abc") is not None


def test_a_child_with_no_grant_gains_nothing_from_a_new_session_id():
    guard, _ = _guard(PLAN)
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1", child_subagent_id="sa-0-abc")
    push = {"command": "git push origin fix/123"}
    assert "holds no authority" in guard.pre_tool_call("terminal", push, session_id="s1", task_id="sa-0-abc")["message"]
    assert "holds no authority" in guard.pre_tool_call("terminal", push, session_id="s1-b", task_id="sa-0-abc")["message"]


def test_a_child_whose_grant_was_cleared_stays_without_authority_under_a_new_session_id():
    guard, _ = _guard(PLAN)
    guard.pre_tool_call("delegate_task", {"goal": "push the fix"}, session_id="s0", task_id="s0")
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1", child_goal="push the fix",
                            child_subagent_id="sa-0-abc")
    guard.clear_session_warrant("s1")
    push = {"command": "git push origin fix/123"}
    assert guard.pre_tool_call("terminal", push, session_id="s1-b", task_id="sa-0-abc") is not None


def test_a_script_run_by_a_moved_child_is_still_attributed_to_it():
    """execute_code calls carry the task id and no session id."""
    guard, events = _guard(PLAN)
    guard.pre_tool_call("delegate_task", {"goal": "push the fix"}, session_id="s0", task_id="s0")
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1", child_goal="push the fix",
                            child_subagent_id="sa-0-abc")
    push = {"command": "git push origin fix/123"}
    assert guard.pre_tool_call("terminal", {"command": "git status"}, session_id="s1", task_id="sa-0-abc") is not None
    assert guard.pre_tool_call("terminal", {"command": "git status"}, session_id="s1-b", task_id="sa-0-abc") is not None
    assert guard.pre_tool_call("terminal", push, session_id="", task_id="sa-0-abc") is None
    assert events[-1].session_id == "s1-b" and events[-1].use["count"] == 1
    assert guard.pre_tool_call("terminal", push, session_id="", task_id="sa-0-abc") is not None


def test_a_rejected_delegation_leaves_no_pass_for_a_second_check():
    guard, _ = _guard(NESTED)
    guard._registry_enforces = True
    _delegate(guard, "s0", "s1")
    bad = {"goal": "x", "toolsets": ["no-such-toolset"]}
    assert guard.pre_tool_call("delegate_task", bad, session_id="s1", tool_call_id="call_9") is not None
    assert _delegate(guard, "s1", "s2", call_id="call_1") is None       # the one use, taken properly
    # a registry-only check of the rejected call must not ride on a leftover pass
    again = guard.pre_tool_call("delegate_task", bad, session_id="s1", tool_call_id="call_9", registry_check=True)
    assert again is not None and "use limit reached" in again["message"]


def test_a_call_hermes_rejected_for_its_arguments_is_not_recorded_as_allowed():
    guard, events = _guard(PLAN)
    _delegate(guard, "s0", "s1")
    assert _push(guard, "s1", "call_0") is None
    guard.post_tool_call("terminal", {}, "", session_id="s1", tool_call_id="call_1",
                         status="error", error_type="invalid_tool_arguments")
    assert events[-1].decision == "DENY" and "not run" in events[-1].reason
    assert [e.decision for e in events if e.tool == "terminal"].count("ALLOW") == 1


def test_a_plan_file_with_a_repeated_key_is_refused(tmp_path):
    from hermes_tenuo.delegation import load_plan

    for text in (
        # the limit is in the first of two entries for the tool
        '''{"version": 1, "root": {"tools": {"terminal": {}, "delegate_task": {}}}, "levels": [{"ttl_seconds": 60,
           "tools": {"terminal": {"max_uses": 1}, "terminal": {}}}]}''',
        # two limits
        '''{"version": 1, "root": {"tools": {"terminal": {}, "delegate_task": {}}}, "levels": [{"ttl_seconds": 60,
           "tools": {"terminal": {"max_uses": 1, "max_uses": 50}}}]}''',
        # two "levels"
        '''{"version": 1, "root": {"tools": {"terminal": {}, "delegate_task": {}}},
           "levels": [{"ttl_seconds": 60, "tools": {"terminal": {"max_uses": 1}}}],
           "levels": [{"ttl_seconds": 60, "tools": {"terminal": {}}}]}''',
    ):
        path = tmp_path / "plan.json"
        path.write_text(text)
        path.chmod(0o600)
        with pytest.raises(DelegationPlanError, match="twice"):
            load_plan(path)


def test_doctor_notes_a_limit_next_to_an_open_tool_that_runs_code():
    from hermes_tenuo.delegation import unbounded_routes

    plan = copy.deepcopy(PLAN)
    assert unbounded_routes(parse_plan(plan)) == []
    plan["root"]["tools"]["execute_code"] = {}
    plan["levels"][0]["tools"]["execute_code"] = {}
    notes = unbounded_routes(parse_plan(plan))
    assert len(notes) == 1 and "execute_code" in notes[0] and "terminal has a use limit" in notes[0]


def test_a_limit_cannot_be_raised_two_levels_down():
    plan = copy.deepcopy(NESTED)
    plan["levels"][1]["tools"]["delegate_task"] = {}
    plan["levels"].append({"ttl_seconds": 60, "tools": {"terminal": {"max_uses": 50, "command": PUSH}}})
    with pytest.raises(DelegationPlanError, match="larger than the level above"):
        parse_plan(plan)
