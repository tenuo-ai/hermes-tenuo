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


def test_an_argument_named_max_uses_is_still_an_argument():
    plan = copy.deepcopy(PLAN)
    plan["root"]["tools"]["retry"] = {"max_uses": {"range": [1, 5]}}
    plan["levels"][0]["tools"]["retry"] = {"max_uses": {"range": [1, 3]}}
    level = parse_plan(plan).levels[0]
    assert level.max_uses == {"terminal": 1}
    assert "max_uses" in level.tools["retry"] and "max_uses" not in level.tools["terminal"]


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
