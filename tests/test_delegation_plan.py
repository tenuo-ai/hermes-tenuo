"""Delegation plans: per-depth argument grants across a delegate_task tree."""

import copy

import pytest
from tenuo import AnyOf, All, Regex, SigningKey, Warrant
import tenuo_core

from hermes_tenuo.delegation import DelegationPlanError, parse_plan
from hermes_tenuo.hermes_guard import HermesGuard

ROOT_CMD = {
    "binaries": ["kubectl", "proddb"],
    "patterns": [
        r"^kubectl get pods -n shop$",
        r"^kubectl logs deploy/(checkout|payments) -n shop$",
        r"^kubectl rollout restart deploy/checkout -n shop$",
        r"^proddb select [a-z_]+ --schema checkout$",
    ],
}
LEVEL1_CMD = {
    "binaries": ["kubectl", "proddb"],
    "patterns": [
        r"^kubectl get pods -n shop$",
        r"^kubectl logs deploy/(checkout|payments) -n shop$",
        r"^proddb select [a-z_]+ --schema checkout$",
    ],
}
LEVEL2_CMD = {"binaries": ["kubectl"], "patterns": [r"^kubectl logs deploy/payments -n shop$"]}

PLAN = {
    "version": 1,
    "root": {"tools": {"terminal": {"command": ROOT_CMD}, "delegate_task": {}}},
    "levels": [
        {"role": "investigator", "ttl_seconds": 1800,
         "tools": {"terminal": {"command": LEVEL1_CMD}, "delegate_task": {}}},
        {"role": "inspector", "ttl_seconds": 600, "tools": {"terminal": {"command": LEVEL2_CMD}}},
    ],
}


def _root_constraint():
    return All([tenuo_core.Shlex(allow=ROOT_CMD["binaries"]),
                AnyOf([Regex(p) for p in ROOT_CMD["patterns"]])])


@pytest.fixture
def tree():
    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder().holder(agent_key.public_key)
        .capability("terminal", command=_root_constraint())
        .capability("delegate_task")
        .ttl(3600).mint(root_key)
    )
    guard = HermesGuard(
        warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key],
        delegation_plan=parse_plan(PLAN),
    )
    return guard


def _run(guard, session, command):
    return guard.pre_tool_call("terminal", {"command": command}, session_id=session)


def _delegate(guard, parent, child, tasks=1):
    blocked = guard.pre_tool_call(
        "delegate_task", {"goal": "investigate", "tasks": [{"goal": "x"}] * tasks}, session_id=parent
    )
    if blocked is None:
        guard.on_subagent_start(parent_session_id=parent, child_session_id=child)
    return blocked


def test_three_level_tree_narrows_at_each_level(tree):
    g = tree
    assert _run(g, "s0", "kubectl rollout restart deploy/checkout -n shop") is None

    assert _delegate(g, "s0", "s1") is None
    assert _run(g, "s1", "kubectl logs deploy/checkout -n shop") is None
    assert _run(g, "s1", "proddb select orders --schema checkout") is None
    assert _run(g, "s1", "kubectl rollout restart deploy/checkout -n shop") is not None  # commander only

    assert _delegate(g, "s1", "s2") is None
    assert _run(g, "s2", "kubectl logs deploy/payments -n shop") is None
    for cmd in (
        "kubectl logs deploy/checkout -n shop",
        "proddb select orders --schema checkout",
        "kubectl get pods -n shop",
        "kubectl rollout restart deploy/checkout -n shop",
    ):
        assert _run(g, "s2", cmd) is not None, cmd


def test_children_carry_full_chains_and_nested_expiry(tree):
    g = tree
    _delegate(g, "s0", "s1")
    _delegate(g, "s1", "s2")
    root_w, _ = g._resolve_warrant("s0")
    w1, _ = g._resolve_warrant("s1")
    w2, _ = g._resolve_warrant("s2")
    assert g._chain_for("s1") == [root_w]
    assert g._chain_for("s2") == [root_w, w1]
    assert w2.expires_at() <= w1.expires_at() <= root_w.expires_at()


def test_each_child_holds_its_own_key(tree):
    g = tree
    _delegate(g, "s0", "s1")
    _delegate(g, "s1", "s2")
    keys = [g._resolve_warrant(s)[1] for s in ("s0", "s1", "s2")]
    assert len({bytes(k.public_key.to_bytes()) for k in keys}) == 3
    w2, _ = g._resolve_warrant("s2")
    # The parent's key cannot act as the child: proof-of-possession fails.
    with g._session_lock:
        g._session_warrants["s2"] = (w2, keys[1])
    assert _run(g, "s2", "kubectl logs deploy/payments -n shop") is not None


def test_depth_beyond_plan_blocks_the_delegation(tree):
    g = tree
    _delegate(g, "s0", "s1")
    _delegate(g, "s1", "s2")
    # The inspector holds no delegate_task, so the warrant itself refuses.
    assert g.pre_tool_call("delegate_task", {"goal": "x"}, session_id="s2") is not None


def test_plan_depth_limit_blocks_even_when_warrant_allows_delegation():
    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    warrant = (Warrant.mint_builder().holder(agent_key.public_key)
               .capability("terminal", command=_root_constraint()).capability("delegate_task")
               .ttl(600).mint(root_key))
    plan = copy.deepcopy(PLAN)
    plan["levels"] = plan["levels"][:1]
    g = HermesGuard(warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key],
                    delegation_plan=parse_plan(plan))
    assert _delegate(g, "s0", "s1") is None
    blocked = g.pre_tool_call("delegate_task", {"goal": "x"}, session_id="s1")
    assert blocked and "beyond the delegation plan" in blocked["message"]


def test_unplanned_child_holds_no_authority(tree):
    g = tree
    g.on_subagent_start(parent_session_id="s0", child_session_id="stray")
    blocked = _run(g, "stray", "kubectl get pods -n shop")
    assert blocked and "holds no authority" in blocked["message"]


def _guard_with_plan(plan):
    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    warrant = (Warrant.mint_builder().holder(agent_key.public_key)
               .capability("terminal", command=_root_constraint()).capability("delegate_task")
               .ttl(600).mint(root_key))
    return HermesGuard(warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key],
                       delegation_plan=parse_plan(plan))


def test_tampered_plan_cannot_widen_a_child():
    """Extra patterns in the plan never let anyone run them: the grant is refused or narrowed."""
    plan = copy.deepcopy(PLAN)
    plan["root"]["tools"]["terminal"]["command"]["patterns"].append(r"^kubectl delete ns shop$")
    plan["levels"][0]["tools"]["terminal"]["command"]["patterns"].append(r"^kubectl delete ns shop$")
    g = _guard_with_plan(plan)
    blocked = _delegate(g, "s0", "s1")
    if blocked is None:
        assert _run(g, "s1", "kubectl delete ns shop") is not None
    else:
        assert "rejected" in blocked["message"]
    assert _run(g, "s0", "kubectl delete ns shop") is not None


def test_plan_with_a_substituted_root_is_refused():
    """A plan whose root does not match the signed warrant cannot produce a valid grant."""
    plan = copy.deepcopy(PLAN)
    plan["root"]["tools"]["terminal"]["command"] = {"binaries": ["bash"], "patterns": [r"^.*$"]}
    plan["levels"][0]["tools"]["terminal"]["command"] = {"binaries": ["bash"], "patterns": [r"^.*$"]}
    plan["levels"][1]["tools"]["terminal"]["command"] = {"binaries": ["bash"], "patterns": [r"^.*$"]}
    g = _guard_with_plan(plan)
    blocked = _delegate(g, "s0", "s1")
    assert blocked and "rejected" in blocked["message"]
    assert _run(g, "s1", "bash -c id") is not None


def test_multiple_children_from_one_call_each_get_a_grant(tree):
    g = tree
    assert g.pre_tool_call("delegate_task", {"goal": "x", "tasks": [{"goal": "a"}, {"goal": "b"}]},
                           session_id="s0") is None
    g.on_subagent_start(parent_session_id="s0", child_session_id="c1")
    g.on_subagent_start(parent_session_id="s0", child_session_id="c2")
    for child in ("c1", "c2"):
        assert _run(g, child, "kubectl get pods -n shop") is None
    g.on_subagent_start(parent_session_id="s0", child_session_id="c3")
    assert _run(g, "c3", "kubectl get pods -n shop") is not None


def test_session_end_clears_depth_and_pending(tree):
    g = tree
    g.pre_tool_call("delegate_task", {"goal": "x"}, session_id="s0")
    g.on_session_end("s0")
    assert "s0" not in g._planned_children
    g.on_subagent_start(parent_session_id="s0", child_session_id="late")
    assert _run(g, "late", "kubectl get pods -n shop") is not None


@pytest.mark.parametrize("mutate, message", [
    (lambda p: p.update(version=2), "unsupported plan version"),
    (lambda p: p.update(levels=[]), "at least one level"),
    (lambda p: p["levels"][0].pop("ttl_seconds"), "ttl_seconds"),
    (lambda p: p["levels"][1]["tools"]["terminal"]["command"]["patterns"].append("kubectl.*"), "anchored"),
    (lambda p: p["root"]["tools"].pop("terminal"), "not held by every ancestor"),
])
def test_malformed_plans_are_rejected(mutate, message):
    plan = copy.deepcopy(PLAN)
    mutate(plan)
    with pytest.raises(DelegationPlanError, match=message):
        parse_plan(plan)
