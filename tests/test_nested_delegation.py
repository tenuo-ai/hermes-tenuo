"""Nested delegate_task: each sub-agent presents its full ancestor chain."""

from tenuo import SigningKey, Subpath, Warrant

from hermes_tenuo.hermes_guard import HermesGuard


def _guard():
    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder().holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/data"))
        .capability("delegate_task")
        .ttl(3600).mint(root_key)
    )
    return HermesGuard(warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key]), warrant


def _delegate(guard, parent, child):
    assert guard.pre_tool_call("delegate_task", {"goal": "go deeper"}, session_id=parent) is None
    guard.on_subagent_start(parent_session_id=parent, child_session_id=child)


def test_every_level_of_a_four_deep_tree_can_act():
    guard, root_warrant = _guard()
    sessions = ["s0", "s1", "s2", "s3", "s4"]
    for parent, child in zip(sessions, sessions[1:]):
        _delegate(guard, parent, child)
    for depth, session in enumerate(sessions):
        assert guard.pre_tool_call("read_file", {"path": "/data/q3.csv"}, session_id=session) is None, session
        assert len(guard._chain_for(session)) == depth
    assert guard._chain_for("s4")[0] is root_warrant


def test_nested_children_keep_the_root_constraints():
    guard, _ = _guard()
    _delegate(guard, "s0", "s1")
    _delegate(guard, "s1", "s2")
    denied = guard.pre_tool_call("read_file", {"path": "/etc/passwd"}, session_id="s2")
    assert denied and denied["action"] == "block"


def test_a_grandchild_without_its_full_chain_is_denied():
    guard, _ = _guard()
    _delegate(guard, "s0", "s1")
    _delegate(guard, "s1", "s2")
    with guard._session_lock:
        guard._session_warrant_chains["s2"] = guard._session_warrant_chains["s2"][-1:]
    denied = guard.pre_tool_call("read_file", {"path": "/data/q3.csv"}, session_id="s2")
    assert denied and denied["action"] == "block"
