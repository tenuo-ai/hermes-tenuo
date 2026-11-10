"""A call the plugin blocks is never recorded as allowed."""

from __future__ import annotations

import threading

import pytest
from tenuo import SigningKey, Subpath, Warrant, Wildcard

from hermes_tenuo._guard import PluginGuard
from hermes_tenuo.hermes_guard import HermesGuard


@pytest.fixture
def setup():
    root, agent = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder().holder(agent.public_key)
        .capability("read_file", path=Subpath("/data"))
        .capability("web_search", query=Wildcard())
        .ttl(600).mint(root)
    )
    return root, agent, warrant


def _guard(events, **kwargs):
    return HermesGuard(audit_callback=events.append, **kwargs)


def _decisions(events):
    return [(e.decision, e.reason) for e in events]


def _concurrently(count, fn):
    """Run *fn* on *count* threads that are all alive at once, so their ids differ."""
    barrier = threading.Barrier(count)

    def run():
        fn()
        barrier.wait(timeout=10)

    workers = [threading.Thread(target=run) for _ in range(count)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()


@pytest.mark.parametrize("tool_call_id", ["call-1", ""])
def test_missing_signing_key_is_recorded_as_denied(setup, tool_call_id):
    root, _agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=None, trusted_roots=[root.public_key])
    blocked = g.pre_tool_call("read_file", {"path": "/data/x"}, session_id="s", tool_call_id=tool_call_id)
    assert blocked and "TENUO_SIGNING_KEY" in blocked["message"]
    # Hermes fires post_tool_call for a blocked call too.
    g.post_tool_call("read_file", {"path": "/data/x"}, "{}", session_id="s", tool_call_id=tool_call_id)
    assert len(events) == 2
    assert all(d == "DENY" and "TENUO_SIGNING_KEY" in r for d, r in _decisions(events))


@pytest.mark.parametrize("tool_call_id", ["call-1", ""])
def test_session_without_a_warrant_is_recorded_as_denied(setup, tool_call_id):
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, trusted_roots=[root.public_key])
    g.set_session_warrant("alice", warrant, agent)
    blocked = g.pre_tool_call("web_search", {"query": "x"}, session_id="eve", tool_call_id=tool_call_id)
    assert blocked and "no warrant for this session" in blocked["message"]
    g.post_tool_call("web_search", {"query": "x"}, "{}", session_id="eve", tool_call_id=tool_call_id)
    assert len(events) == 2
    assert all(d == "DENY" and "no warrant for this session" in r for d, r in _decisions(events))


@pytest.mark.parametrize("tool_call_id", ["c", ""])
def test_enforcement_error_is_recorded_as_denied(setup, monkeypatch, tool_call_id):
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])

    def boom(**_kwargs):
        raise RuntimeError("backend down")

    monkeypatch.setattr("tenuo._enforcement.enforce_tool_call", boom)
    blocked = g.pre_tool_call("read_file", {"path": "/data/x"}, session_id="s", tool_call_id=tool_call_id)
    assert blocked and blocked["action"] == "block"
    assert _decisions(events) == [("DENY", "Authorization error: backend down")]
    g.post_tool_call("read_file", {"path": "/data/x"}, "{}", session_id="s", tool_call_id=tool_call_id)
    assert _decisions(events) == [("DENY", "Authorization error: backend down")] * 2


@pytest.mark.parametrize("tool_call_id", ["c", ""])
@pytest.mark.parametrize("session_id, task_id", [("s", ""), ("", "t")])
def test_escaped_hook_error_is_recorded_as_denied(setup, monkeypatch, tool_call_id, session_id, task_id):
    root, agent, warrant = setup
    events: list = []
    inner = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    pg = PluginGuard(inner)

    def boom(**_kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(inner, "pre_tool_call", boom)
    call = dict(tool_name="read_file", args={"path": "/data/x"}, session_id=session_id, task_id=task_id,
                tool_call_id=tool_call_id)
    blocked = pg.pre_tool_call_hook(**call)
    assert blocked and blocked["action"] == "block"
    pg.post_tool_call_hook(**call)
    assert [d for d, _ in _decisions(events)] == ["DENY", "DENY"]
    assert events[0].reason == events[1].reason
    assert "unexpected" not in events[0].reason  # the error text stays out of the record


def test_allowed_and_unobserved_calls_are_unchanged(setup):
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    assert g.pre_tool_call("read_file", {"path": "/data/x"}, session_id="s", tool_call_id="c") is None
    g.post_tool_call("read_file", {"path": "/data/x"}, "{}", session_id="s", tool_call_id="c")
    g.post_tool_call("read_file", {"path": "/data/y"}, "{}", session_id="s")  # no pre hook seen
    assert _decisions(events) == [("ALLOW", ""), ("ALLOW", ""), ("ALLOW", "post-dispatch")]


def test_policy_denial_without_an_id_stays_denied(setup):
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    call = ("terminal", {"command": "id"})
    # Two identical calls in flight on two threads, then their post hooks.
    _concurrently(2, lambda: g.pre_tool_call(*call, session_id="s"))
    assert len(g._unkeyed_decisions) == 1 and len(next(iter(g._unkeyed_decisions.values()))) == 2
    g.post_tool_call(*call, "{}", session_id="s")
    g.post_tool_call(*call, "{}", session_id="s")
    assert [d for d, _ in _decisions(events)] == ["DENY"] * 4
    assert not g._unkeyed_decisions
    # A different call by the same session is still an unobserved post event.
    g.post_tool_call("read_file", {"path": "/data/y"}, "{}", session_id="s")
    assert _decisions(events)[-1] == ("ALLOW", "post-dispatch")


def test_a_call_checked_twice_leaves_no_decision_behind(setup):
    # With a registry enforcement hook, Hermes checks one invocation twice:
    # once from pre_tool_call and once inside dispatch.
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    call = ("read_file", {"path": "/data/x"})
    assert g.pre_tool_call(*call, session_id="s") is None
    assert g.pre_tool_call(*call, session_id="s") is None
    g.post_tool_call(*call, "{}", session_id="s")
    assert not g._unkeyed_decisions
    # The identical call is later denied (here: a warrant without the tool).
    g._static_warrant = (
        Warrant.mint_builder().holder(agent.public_key)
        .capability("web_search", query=Wildcard()).ttl(600).mint(root)
    )
    events.clear()
    assert g.pre_tool_call(*call, session_id="s")
    assert g.pre_tool_call(*call, session_id="s")
    g.post_tool_call(*call, "{}", session_id="s", status="blocked")
    assert [d for d, _ in _decisions(events)] == ["DENY"] * 3
    assert not g._unkeyed_decisions


def test_stale_allow_from_another_thread_does_not_mask_a_denial(setup):
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    call = ("read_file", {"path": "/data/x"})
    # An allowed call on another thread whose post hook never arrives.
    worker = threading.Thread(target=lambda: g.pre_tool_call(*call, session_id="s"))
    worker.start()
    worker.join()
    g._static_warrant = (
        Warrant.mint_builder().holder(agent.public_key)
        .capability("web_search", query=Wildcard()).ttl(600).mint(root)
    )
    events.clear()
    assert g.pre_tool_call(*call, session_id="s")
    g.post_tool_call(*call, "{}", session_id="s", status="blocked")
    assert [d for d, _ in _decisions(events)] == ["DENY", "DENY"]
    # And when the post hook runs on a thread other than the one that decided.
    worker = threading.Thread(target=lambda: g.pre_tool_call(*call, session_id="s"))
    worker.start()
    worker.join()
    events.clear()
    poster = threading.Thread(target=lambda: g.post_tool_call(*call, "{}", session_id="s", status="blocked"))
    poster.start()
    poster.join()
    assert [d for d, _ in _decisions(events)] == ["DENY"]


def test_blocked_post_on_a_thread_holding_a_stale_allow_takes_the_denial(setup):
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    call = ("read_file", {"path": "/data/x"})
    # This thread allowed the call earlier and its post hook never arrived.
    assert g.pre_tool_call(*call, session_id="s") is None
    g._static_warrant = (
        Warrant.mint_builder().holder(agent.public_key)
        .capability("web_search", query=Wildcard()).ttl(600).mint(root)
    )
    # Another thread now denies the identical call; its post runs back here.
    denied = []
    worker = threading.Thread(target=lambda: denied.append(g.pre_tool_call(*call, session_id="s")))
    worker.start()
    worker.join()
    assert denied[0] and denied[0]["action"] == "block"
    events.clear()
    g.post_tool_call(*call, "{}", session_id="s", status="blocked")
    assert _decisions(events) == [("DENY", denied[0]["message"])]  # the denial's own reason


def test_blocked_post_with_only_an_allow_pending_is_recorded_as_denied(setup):
    # The warrant allowed it and something else blocked it: the call did not run.
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    call = ("read_file", {"path": "/data/x"})
    assert g.pre_tool_call(*call, session_id="s") is None
    events.clear()
    g.post_tool_call(*call, "{}", session_id="s", status="blocked")
    assert [d for d, _ in _decisions(events)] == ["DENY"]
    assert not g._unkeyed_decisions


def test_post_reported_as_blocked_is_never_recorded_as_allowed(setup):
    root, agent, warrant = setup
    events: list = []
    g = _guard(events, warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    g.post_tool_call("read_file", {"path": "/data/x"}, "{}", session_id="s", status="blocked")
    assert [d for d, _ in _decisions(events)] == ["DENY"]


def test_decisions_without_an_id_are_bounded(setup):
    root, agent, warrant = setup
    g = _guard([], warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    for n in range(g._MAX_PENDING_DECISIONS + 50):
        g.pre_tool_call("terminal", {"command": f"x{n}"}, session_id="s")
    assert len(g._unkeyed_decisions) == g._MAX_PENDING_DECISIONS
    # Repeats on one thread keep one entry; concurrent ones are capped per call.
    for _ in range(200):
        g.pre_tool_call("terminal", {"command": "same"}, session_id="s")
    assert max(len(d) for d in g._unkeyed_decisions.values()) == 1
    assert all(d.maxlen == 64 for d in g._unkeyed_decisions.values())
