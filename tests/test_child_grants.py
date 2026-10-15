"""delegate_task grants: child_warrant scope, per-task toolsets, sessionless calls."""

import pytest
from tenuo import SigningKey, Subpath, Warrant, Wildcard

from hermes_tenuo.hermes_guard import HermesGuard, _allows_unknown_args, _delegated_tasks


@pytest.fixture
def keys():
    return SigningKey.generate(), SigningKey.generate()


def _parent(root, agent, ttl=3600):
    return (
        Warrant.mint_builder().holder(agent.public_key)
        .capability("read_file", path=Subpath("/data"), _allow_unknown=True)
        .capability("web_search", query=Wildcard())
        .capability("delegate_task")
        .ttl(ttl).mint(root)
    )


def _guard(keys, child_warrant=None, parent=None):
    root, agent = keys
    return HermesGuard(
        warrant=parent or _parent(root, agent), signing_key=agent,
        child_warrant=child_warrant, trusted_roots=[root.public_key],
    )


def _delegate(guard, args, children, parent="p"):
    assert guard.pre_tool_call("delegate_task", args, session_id=parent) is None
    for child, goal in children:
        guard.on_subagent_start(parent, child, child_goal=goal)


def _allowed(guard, tool, args, session):
    return guard.pre_tool_call(tool, args, session_id=session) is None


# ---------------------------------------------------------------------------
# Parsing delegate_task arguments
# ---------------------------------------------------------------------------


def test_single_goal_is_one_task_and_missing_toolsets_is_none():
    assert _delegated_tasks({"goal": "g"}) == [("g", None)]
    assert _delegated_tasks({"goal": "g", "tasks": []}) == [("g", None)]


def test_explicit_empty_toolsets_is_not_missing():
    assert _delegated_tasks({"goal": "g", "toolsets": []}) == [("g", [])]


def test_per_task_toolsets_override_the_top_level():
    args = {"toolsets": ["web"], "tasks": [{"goal": "a", "toolsets": ["file"]}, {"goal": "b"}]}
    assert _delegated_tasks(args) == [("a", ["file"]), ("b", ["web"])]


def test_tasks_as_a_json_string():
    assert _delegated_tasks({"tasks": '[{"goal": "a"}, {"goal": "b"}]'}) == [("a", None), ("b", None)]


# ---------------------------------------------------------------------------
# child_warrant
# ---------------------------------------------------------------------------


def test_child_warrant_scope_reaches_a_single_goal_child(keys):
    root, agent = keys
    cw = Warrant.mint_builder().holder(agent.public_key).capability("web_search", query=Wildcard()).ttl(600).mint(root)
    g = _guard(keys, cw)
    _delegate(g, {"goal": "research"}, [("c", "research")])
    assert not _allowed(g, "read_file", {"path": "/data/x"}, "c")
    assert _allowed(g, "web_search", {"query": "q"}, "c")
    assert _allowed(g, "read_file", {"path": "/data/x"}, "p")


def test_child_grant_is_chained_and_holds_its_own_key(keys):
    root, agent = keys
    cw = Warrant.mint_builder().holder(agent.public_key).capability("web_search", query=Wildcard()).ttl(600).mint(root)
    g = _guard(keys, cw)
    _delegate(g, {"goal": "r"}, [("c", "r")])
    child, key = g._resolve_warrant("c")
    assert child.depth == 1 and len(g._chain_for("c")) == 1
    assert key.public_key.to_bytes() != agent.public_key.to_bytes()
    assert child.ttl_remaining.total_seconds() <= 600


def test_child_warrant_constraints_narrow_the_parent(keys):
    root, agent = keys
    cw = (Warrant.mint_builder().holder(agent.public_key)
          .capability("read_file", path=Subpath("/data/pub"), _allow_unknown=True).ttl(600).mint(root))
    g = _guard(keys, cw)
    _delegate(g, {"goal": "r"}, [("c", "r")])
    assert _allowed(g, "read_file", {"path": "/data/pub/a", "offset": 1}, "c")
    assert not _allowed(g, "read_file", {"path": "/data/private"}, "c")


def test_child_warrant_wider_than_the_parent_blocks_the_delegation(keys):
    root, agent = keys
    cw = Warrant.mint_builder().holder(agent.public_key).capability("read_file", path=Subpath("/")).ttl(600).mint(root)
    g = _guard(keys, cw)
    blocked = g.pre_tool_call("delegate_task", {"goal": "r"}, session_id="p")
    assert blocked and blocked["action"] == "block" and "delegation rejected" in blocked["message"]
    assert not g._planned_children.get("p")


def test_child_warrant_tools_the_parent_lacks_are_dropped(keys):
    root, agent = keys
    cw = (Warrant.mint_builder().holder(agent.public_key)
          .capability("web_search", query=Wildcard()).capability("terminal").ttl(600).mint(root))
    g = _guard(keys, cw)
    _delegate(g, {"goal": "r"}, [("c", "r")])
    assert sorted(g._resolve_warrant("c")[0].tools) == ["web_search"]


def test_allow_unknown_probe_reads_the_core_flag(keys):
    root, agent = keys
    open_ = Warrant.mint_builder().holder(agent.public_key).capability(
        "read_file", path=Subpath("/d"), _allow_unknown=True).ttl(60).mint(root)
    closed = Warrant.mint_builder().holder(agent.public_key).capability(
        "read_file", path=Subpath("/d")).ttl(60).mint(root)
    assert _allows_unknown_args(open_, "read_file") is True
    assert _allows_unknown_args(closed, "read_file") is False


# ---------------------------------------------------------------------------
# Toolsets and matching children to tasks
# ---------------------------------------------------------------------------


def test_toolsets_narrow_without_child_warrant(keys):
    g = _guard(keys)
    _delegate(g, {"tasks": [{"goal": "w", "toolsets": ["web"]}, {"goal": "all"}]}, [("c0", "w"), ("c1", "all")])
    assert not _allowed(g, "read_file", {"path": "/data/x"}, "c0")
    assert _allowed(g, "web_search", {"query": "q"}, "c0")
    assert _allowed(g, "read_file", {"path": "/data/x"}, "c1")


def test_children_are_matched_by_goal_not_arrival_order(keys):
    g = _guard(keys)
    _delegate(g, {"tasks": [{"goal": "w", "toolsets": ["web"]}, {"goal": "all"}]}, [("c1", "all"), ("c0", "w")])
    assert not _allowed(g, "read_file", {"path": "/data/x"}, "c0")
    assert _allowed(g, "read_file", {"path": "/data/x"}, "c1")


def test_a_child_with_an_unknown_goal_holds_nothing(keys):
    g = _guard(keys)
    _delegate(g, {"goal": "planned"}, [("c", "something else")])
    assert not _allowed(g, "web_search", {"query": "q"}, "c")


def test_more_children_than_tasks_hold_nothing(keys):
    g = _guard(keys)
    _delegate(g, {"goal": "one"}, [("c0", None), ("c1", None)])
    assert _allowed(g, "web_search", {"query": "q"}, "c0")
    assert not _allowed(g, "web_search", {"query": "q"}, "c1")


# ---------------------------------------------------------------------------
# Calls with a task id and no session id (execute_code)
# ---------------------------------------------------------------------------


def test_sessionless_call_follows_the_child_task(keys):
    root, agent = keys
    cw = Warrant.mint_builder().holder(agent.public_key).capability("web_search", query=Wildcard()).ttl(600).mint(root)
    g = _guard(keys, cw)
    g.pre_tool_call("delegate_task", {"goal": "r"}, session_id="p", task_id="tp")
    g.on_subagent_start("p", "c", child_goal="r", child_task_id="sa-0")
    assert g.pre_tool_call("read_file", {"path": "/data/x"}, task_id="sa-0") is not None
    assert g.pre_tool_call("web_search", {"query": "q"}, task_id="sa-0") is None
    assert g.pre_tool_call("read_file", {"path": "/data/x"}, task_id="tp") is None


def test_sessionless_call_with_unknown_task_is_blocked_once_children_exist(keys):
    g = _guard(keys)
    assert g.pre_tool_call("read_file", {"path": "/data/x"}, task_id="t?") is None  # single agent: config warrant
    _delegate(g, {"goal": "r"}, [("c", "r")])
    blocked = g.pre_tool_call("read_file", {"path": "/data/x"}, task_id="t?")
    assert blocked and "no session id" in blocked["message"]


def test_task_shared_by_two_live_sessions_is_ambiguous(keys):
    g = _guard(keys)
    _delegate(g, {"goal": "r"}, [("c", "r")])
    g.pre_tool_call("web_search", {"query": "q"}, session_id="p", task_id="shared")
    g.pre_tool_call("web_search", {"query": "q"}, session_id="c", task_id="shared")
    assert g.pre_tool_call("web_search", {"query": "q"}, task_id="shared") is not None
    g.on_session_end("c")
    assert g.pre_tool_call("web_search", {"query": "q"}, task_id="shared") is None
