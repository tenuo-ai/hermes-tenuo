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


def test_duplicate_goals_with_different_authority_are_rejected(keys):
    g = _guard(keys)
    blocked = g.pre_tool_call(
        "delegate_task",
        {"tasks": [{"goal": "same", "toolsets": ["web"]}, {"goal": "same", "toolsets": ["read_file"]}]},
        session_id="p",
    )
    assert blocked and "duplicate child goals" in blocked["message"]
    assert not g._planned_children.get("p")


def test_child_ttl_is_atomically_capped_to_shorter_parent(keys):
    root, agent = keys
    parent = _parent(root, agent, ttl=60)
    child_scope = (
        Warrant.mint_builder()
        .holder(agent.public_key)
        .capability("web_search", query=Wildcard())
        .ttl(600)
        .mint(root)
    )
    g = _guard(keys, child_scope, parent=parent)
    _delegate(g, {"goal": "r"}, [("c", "r")])
    child, _ = g._resolve_warrant("c")
    assert child.expires_at() <= parent.expires_at()


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


def _web_only(keys, ttl=600):
    root, agent = keys
    return Warrant.mint_builder().holder(agent.public_key).capability("web_search", query=Wildcard()).ttl(ttl).mint(root)


def test_child_keeps_its_grant_when_it_runs_another_turn(keys):
    # Hermes fires on_session_end after every turn and may run a child again
    # under the same session id (its output-schema correction turn).
    g = _guard(keys, _web_only(keys))
    _delegate(g, {"goal": "research"}, [("c", "research")])
    assert _allowed(g, "web_search", {"query": "q"}, "c")
    assert not _allowed(g, "read_file", {"path": "/data/x"}, "c")
    g.on_session_end("c")
    g.on_session_start("c")
    assert _allowed(g, "web_search", {"query": "q"}, "c")
    assert not _allowed(g, "read_file", {"path": "/data/x"}, "c")
    assert _allowed(g, "read_file", {"path": "/data/x"}, "p")  # the parent still holds it


def test_grandchild_chain_survives_the_child_turn_end(keys):
    g = _guard(keys)
    _delegate(g, {"goal": "a"}, [("c", "a")])
    depth = len(g._chain_for("c"))
    assert depth == 1
    g.on_session_end("c")
    assert len(g._chain_for("c")) == depth


def test_expired_child_grant_is_denied_not_widened(keys):
    import time

    g = _guard(keys, _web_only(keys, ttl=1))
    _delegate(g, {"goal": "a"}, [("old", "a")])
    time.sleep(1.2)
    g._child_warrant = _web_only(keys)  # a fresh template for the next delegation
    # Attaching the next child retires children whose grant has expired.
    assert g.pre_tool_call("delegate_task", {"goal": "b"}, session_id="p", tool_call_id="second") is None
    g.on_subagent_start("p", "new", child_goal="b")
    blocked = g.pre_tool_call("read_file", {"path": "/data/x"}, session_id="old")
    assert blocked and "holds no authority" in blocked["message"]
    assert "old" not in g._child_sessions and "old" not in g._session_warrant_chains


def test_expired_child_sweep_is_bounded_per_attach(keys):
    class Stub:
        checks = 0

        def __init__(self, expired):
            self.expired = expired

        def is_expired(self):
            Stub.checks += 1
            return self.expired

    g = _guard(keys)
    g._CHILD_SWEEP = 4
    with g._session_lock:
        for n in range(10):
            g._session_warrants[f"old-{n}"] = (Stub(expired=n % 2 == 0), None)
            g._child_sessions[f"old-{n}"] = None
    _delegate(g, {"goal": "g0"}, [("c0", "g0")])
    assert Stub.checks == 4  # not all ten
    for n in range(1, 4):
        _delegate(g, {"goal": f"g{n}"}, [(f"c{n}", f"g{n}")])
    # Four attaches, four checks each at most; the rotation has reached every old child.
    assert 10 <= Stub.checks <= 16
    for n in range(10):
        retired = f"old-{n}" not in g._child_sessions
        assert retired == (n % 2 == 0)
        assert (not _allowed(g, "web_search", {"query": "q"}, f"old-{n}"))
    for n in range(4):
        assert _allowed(g, "web_search", {"query": "q"}, f"c{n}")


def test_denied_session_markers_are_bounded_and_overflow_fails_closed(keys):
    root, agent = keys
    g = _guard(keys)
    g._MAX_DENIED_SESSIONS = 3
    g.set_session_warrant("own", _web_only(keys), agent)
    for n in range(3):
        g.on_subagent_start("p", f"stray-{n}")
    assert _allowed(g, "web_search", {"query": "q"}, "p")  # not yet overflowed
    for n in range(3, 5):
        g.on_subagent_start("p", f"stray-{n}")
    assert len(g._denied_sessions) == 3
    assert sum(1 for s in g._session_warrants if s.startswith("stray-")) == 3
    # The oldest markers were evicted; those sessions must stay denied.
    for n in range(5):
        assert not _allowed(g, "web_search", {"query": "q"}, f"stray-{n}")
    # So is any other session with no warrant of its own, sessionless calls included.
    blocked = g.pre_tool_call("web_search", {"query": "q"}, session_id="p")
    assert blocked and "until Hermes restarts" in blocked["message"]
    assert g.pre_tool_call("web_search", {"query": "q"}) is not None
    assert g.pre_tool_call("delegate_task", {"goal": "x"}, session_id="p") is not None
    # A session that holds its own warrant is unaffected.
    assert _allowed(g, "web_search", {"query": "q"}, "own")
    assert not _allowed(g, "read_file", {"path": "/data/x"}, "own")


def test_marker_overflow_fails_closed_without_a_config_warrant(keys):
    # A gateway with no config warrant that lets unknown sessions pass through.
    root, agent = keys
    g = HermesGuard(trusted_roots=[root.public_key], require_session_warrant=False)
    g._MAX_DENIED_SESSIONS = 2
    for n in range(2):
        g.set_session_warrant(f"user-{n}", _web_only(keys), agent)
        g.clear_session_warrant(f"user-{n}")
    assert _allowed(g, "terminal", {"command": "ls"}, "unknown")  # not yet overflowed
    assert not _allowed(g, "terminal", {"command": "ls"}, "user-0")
    g.set_session_warrant("user-2", _web_only(keys), agent)
    g.clear_session_warrant("user-2")  # evicts user-0's marker
    assert "user-0" not in g._session_warrants
    for session in ("user-0", "user-1", "user-2", "unknown"):
        blocked = g.pre_tool_call("terminal", {"command": "ls"}, session_id=session)
        assert blocked and "holds no authority" in blocked["message"]
    g.set_session_warrant("user-3", _web_only(keys), agent)
    assert _allowed(g, "web_search", {"query": "q"}, "user-3")


def test_marker_overflow_blocks_the_staged_grant_fallback(keys):
    # A Hermes build that never fires subagent_start: a new session id claims
    # the next staged grant. After overflow, an untracked session must not.
    root, agent = keys
    g = _guard(keys)
    g._MAX_DENIED_SESSIONS = 2
    g.set_session_warrant("own", _parent(root, agent), agent)
    assert _allowed(g, "web_search", {"query": "q"}, "own")  # becomes the primary session
    assert g.pre_tool_call("delegate_task", {"goal": "g"}, session_id="own", tool_call_id="d") is None
    for n in range(3):
        g.set_session_warrant(f"user-{n}", _web_only(keys), agent)
        g.clear_session_warrant(f"user-{n}")
    assert g._denied_sessions_saturated and "user-0" not in g._session_warrants
    assert not g._saw_subagent_start and len(g._planned_children["own"]) == 1
    blocked = g.pre_tool_call("web_search", {"query": "q"}, session_id="user-0")
    assert blocked and "holds no authority" in blocked["message"]
    assert len(g._planned_children["own"]) == 1  # the grant was not consumed
    assert "user-0" not in g._session_warrants


def test_marker_overflow_blocks_a_replayed_child_start(keys):
    # A denied child whose marker was evicted replays subagent_start. It must
    # not take a grant staged for another child, with or without a goal match.
    root, agent = keys
    g = _guard(keys)
    g._MAX_DENIED_SESSIONS = 2
    g.set_session_warrant("own", _parent(root, agent), agent)
    assert g.pre_tool_call("delegate_task", {"goal": "g"}, session_id="own", tool_call_id="d") is None
    for n in range(3):
        g.on_subagent_start("own", f"stray-{n}", child_goal="other")
    assert g._denied_sessions_saturated and "stray-0" not in g._session_warrants
    for goal in ("g", None):
        g.on_subagent_start("own", "stray-0", child_goal=goal)
        assert len(g._planned_children["own"]) == 1
        assert not _allowed(g, "web_search", {"query": "q"}, "stray-0")
    # New delegation is refused outright until restart, instead of spawning a child with nothing.
    refused = g.pre_tool_call("delegate_task", {"goal": "h"}, session_id="own", tool_call_id="e")
    assert refused and "restart Hermes" in refused["message"]
    assert _allowed(g, "web_search", {"query": "q"}, "own")


def test_marker_overflow_leaves_an_unconfigured_guard_a_no_op():
    g = HermesGuard()
    g._denied_sessions_saturated = True
    assert g.pre_tool_call("terminal", {"command": "ls"}, session_id="s1") is None


@pytest.mark.parametrize('result', ['{"error":"spawn failed"}', '{"results":[]}'])
def test_completed_invocation_cannot_supply_a_retry_grant(keys, result):
    g = _guard(keys)
    assert g.pre_tool_call('delegate_task', {'goal': 'same'}, session_id='p', tool_call_id='first') is None
    g.post_tool_call('delegate_task', {'goal': 'same'}, result, session_id='p', tool_call_id='first')
    assert g.pre_tool_call('delegate_task', {'goal': 'same', 'toolsets': ['web']},
                           session_id='p', tool_call_id='retry') is None
    g.on_subagent_start('p', 'c', child_goal='same')
    assert not _allowed(g, 'read_file', {'path': '/data/secret'}, 'c')
    assert _allowed(g, 'web_search', {'query': 'q'}, 'c')


def test_overlapping_invocations_with_same_goal_are_rejected(keys):
    g = _guard(keys)
    assert g.pre_tool_call('delegate_task', {'goal': 'same'}, session_id='p', tool_call_id='first') is None
    denied = g.pre_tool_call('delegate_task', {'goal': 'same', 'toolsets': ['web']},
                             session_id='p', tool_call_id='second')
    assert denied and 'ambiguous' in denied['message']
    # A post hook for the rejected invocation must not clear the first one's grant.
    g.post_tool_call('delegate_task', {}, '{}', session_id='p', tool_call_id='second')
    g.on_subagent_start('p', 'c', child_goal='same')
    assert _allowed(g, 'read_file', {'path': '/data/file'}, 'c')


def test_finishing_one_invocation_preserves_other_pending_grants(keys):
    g = _guard(keys)
    for call_id in ('first', 'second'):
        assert g.pre_tool_call('delegate_task', {'goal': call_id}, session_id='p', tool_call_id=call_id) is None
    g.post_tool_call('delegate_task', {}, '{}', session_id='p', tool_call_id='first')
    g.on_subagent_start('p', 'c1', child_goal='first')
    g.on_subagent_start('p', 'c2', child_goal='second')
    assert not _allowed(g, 'read_file', {'path': '/data/file'}, 'c1')
    assert _allowed(g, 'read_file', {'path': '/data/file'}, 'c2')


@pytest.mark.parametrize('action', ['list', 'steer', 'stop'])
def test_control_actions_do_not_stage_child_authority(keys, action):
    g = _guard(keys)
    assert g.pre_tool_call('delegate_task', {'action': action}, session_id='p') is None
    assert not g._planned_children


def test_log_only_denial_does_not_create_delegation_authority(keys):
    root, agent = keys
    parent = (Warrant.mint_builder().holder(agent.public_key)
              .capability('read_file', path=Subpath('/data')).ttl(600).mint(root))
    g = HermesGuard(warrant=parent, signing_key=agent, trusted_roots=[root.public_key], on_denial='log')
    denied = g.pre_tool_call('delegate_task', {'goal': 'r'}, session_id='p')
    assert denied and denied['action'] == 'block'
    assert not g._planned_children
    g.on_subagent_start('p', 'c', child_goal='r')
    assert not _allowed(g, 'read_file', {'path': '/data/file'}, 'c')
