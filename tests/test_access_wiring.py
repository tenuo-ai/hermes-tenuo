"""The guard resolves each gateway turn to its sender's role warrant (PR 2 wiring)."""
from __future__ import annotations

import pytest

from hermes_tenuo import access
from hermes_tenuo.access import build_access_policy
from hermes_tenuo.hermes_guard import HermesGuard

tenuo = pytest.importorskip("tenuo")


BLOCK_ROLES = {
    "roles": {
        "owner": {"match": {"user": ["telegram:1"]}, "allow": {
            "terminal": {"command": {"binaries": ["git"]}},
            "read_file": {"path": "/data/**"},
        }},
        "analyst": {"match": {"platform": ["telegram"]}, "allow": {"read_file": {"path": "/data/reports/**"}}},
        "guest": {"default": True, "allow": {"web_search": {}}},
    },
}


@pytest.fixture
def guard():
    """A guard in access mode, keyed like the plugin wires it: one self-issued key."""
    key = tenuo.SigningKey.generate()
    policy = build_access_policy(BLOCK_ROLES, control_key=key, holder=key.public_key, signing_key=key)
    return HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy, on_denial="block")


def sender(monkeypatch, **ident):
    monkeypatch.setattr(access, "current_sender", lambda: ident if ident else None)


def blocked(guard, tool, args, session="s1"):
    return bool(guard.pre_tool_call(tool, args, session_id=session))


def test_the_sender_gets_their_own_roles_authority(guard, monkeypatch):
    sender(monkeypatch, user="telegram:1", platform="telegram", chat="telegram:room")
    assert not blocked(guard, "terminal", {"command": "git status"})
    assert blocked(guard, "terminal", {"command": "rm -rf /"})       # binaries allowlist
    assert not blocked(guard, "read_file", {"path": "/data/x", "limit": 5})  # unnamed arg kept
    assert blocked(guard, "read_file", {"path": "/etc/passwd"})


def test_a_self_issued_role_warrant_verifies_through_the_guard(guard, monkeypatch):
    """The plugin mints role warrants with one key as issuer and holder; they must verify."""
    sender(monkeypatch, user="telegram:1", platform="telegram")
    assert not blocked(guard, "read_file", {"path": "/data/ok"})     # would fail if PoP/trust broke


def test_a_different_role_gets_narrower_authority(guard, monkeypatch):
    sender(monkeypatch, user="telegram:99", platform="telegram")     # not owner -> analyst (platform match)
    assert not blocked(guard, "read_file", {"path": "/data/reports/q3"})
    assert blocked(guard, "read_file", {"path": "/data/secret"})     # analyst is narrower than owner
    assert blocked(guard, "terminal", {"command": "git status"})     # analyst has no terminal


def test_a_shared_chat_authorises_per_sender_not_per_session(guard, monkeypatch):
    """#112119: the same session carries different senders; each is authorised as itself,
    so the owner's authority never leaks to another participant in the same conversation."""
    sender(monkeypatch, user="telegram:1", platform="telegram")       # owner speaks
    assert not blocked(guard, "terminal", {"command": "git status"}, session="group")
    sender(monkeypatch, user="telegram:77", platform="telegram")      # someone else, SAME session
    assert blocked(guard, "terminal", {"command": "git status"}, session="group")   # not the owner
    assert not blocked(guard, "read_file", {"path": "/data/reports/x"}, session="group")  # their own role


def test_an_unmatched_sender_under_deny_is_blocked(monkeypatch):
    key = tenuo.SigningKey.generate()
    rules = {"roles": {"owner": {"match": {"user": ["telegram:1"]}, "allow": {"web_search": {}}}}}  # no default
    policy = build_access_policy(rules, control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy)
    sender(monkeypatch, user="telegram:stranger", platform="telegram")
    r = guard.pre_tool_call("web_search", {"query": "x"}, session_id="s")
    assert r and "no access role" in r["message"]


def test_a_no_sender_message_matches_nobody(guard, monkeypatch):
    sender(monkeypatch, user=access.NOBODY, platform="telegram")      # shared feed, no one sender
    assert not blocked(guard, "web_search", {"query": "x"})           # falls to guest (default)
    assert blocked(guard, "terminal", {"command": "git status"})      # guest has no terminal


def test_a_local_turn_without_a_sender_falls_through_to_the_static_warrant(monkeypatch):
    """A CLI/local turn (no gateway identity) is not governed by access; it uses the
    static warrant when one is configured."""
    key = tenuo.SigningKey.generate()
    from hermes_tenuo.issuance import mint_for_holder
    static = mint_for_holder(key, key.public_key, {"web_search": {"_allow_unknown": True}}, 3600)
    policy = build_access_policy({"roles": {"owner": {"match": {"user": ["telegram:1"]}, "allow": {"terminal": {}}}}},
                                 control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(warrant=static, signing_key=key, trusted_roots=[key.public_key], access_policy=policy)
    monkeypatch.setattr(access, "current_sender", lambda: None)       # CLI: no identity
    assert not blocked(guard, "web_search", {"query": "x"})           # static warrant applies
    assert blocked(guard, "terminal", {"command": "git status"})      # not granted by the static warrant


def test_an_explicit_session_warrant_still_wins_over_access(guard, monkeypatch):
    """A delegated child (subagent_start sets a session warrant) keeps its own grant even
    in access mode — the explicit binding is resolved before the access policy."""
    key = tenuo.SigningKey.generate()
    from hermes_tenuo.issuance import mint_for_holder
    child = mint_for_holder(key, key.public_key, {"web_search": {"_allow_unknown": True}}, 3600)
    guard.set_trusted_roots([key.public_key] + list(getattr(guard, "_trusted_roots", []) or []))
    guard.set_session_warrant("child-1", child, key)
    sender(monkeypatch, user="telegram:1", platform="telegram")       # owner identity present
    assert not blocked(guard, "web_search", {"query": "x"}, session="child-1")   # child's own grant
    assert blocked(guard, "terminal", {"command": "git status"}, session="child-1")  # not the owner's


def test_current_sender_reads_real_hermes_session_context():
    ctx = pytest.importorskip("gateway.session_context")
    t = ctx.set_session_vars(platform="telegram", user_id="42", actor_id="7", chat_id="r", session_key="k")
    try:
        # The message's sender (actor 7) wins over the routing user (42).
        assert access.current_sender() == {"user": "telegram:7", "chat": "telegram:r", "platform": "telegram"}
    finally:
        ctx.clear_session_vars(t)
    for local in ("cli", "desktop", "tui"):
        t = ctx.set_session_vars(platform=local, session_key="k")
        try:
            assert access.current_sender() is None, local   # the operator: access does not govern
        finally:
            ctx.clear_session_vars(t)


def test_turns_with_no_chat_sender_are_identified_by_platform_only():
    ctx = pytest.importorskip("gateway.session_context")
    for surface in ("api_server", "webhook", "msgraph_webhook"):
        # Whatever identity the caller supplies is not used.
        t = ctx.set_session_vars(platform=surface, user_id="1", actor_id="1", chat_id="c", session_key="k")
        try:
            assert access.current_sender() == {"user": "", "chat": "", "platform": surface}
        finally:
            ctx.clear_session_vars(t)
    # A scheduled run clears the platform and marks the context instead.
    if "HERMES_CRON_SESSION" not in getattr(ctx, "_VAR_MAP", {}):
        pytest.skip("this Hermes does not mark scheduled runs in the session context")
    t = ctx.set_session_vars(platform="", session_key="")
    token = ctx._VAR_MAP["HERMES_CRON_SESSION"].set("1")
    try:
        assert access.current_sender() == {"user": "", "chat": "", "platform": "cron"}
    finally:
        ctx._VAR_MAP["HERMES_CRON_SESSION"].reset(token)
        ctx.clear_session_vars(t)


def test_a_turn_with_no_chat_sender_gets_the_default_role_never_a_person(guard, monkeypatch):
    for surface in ("api_server", "webhook", "cron"):
        sender(monkeypatch, user="", chat="", platform=surface)
        assert not blocked(guard, "web_search", {"query": "x"}), surface          # guest (default)
        assert blocked(guard, "terminal", {"command": "git status"}), surface     # not the owner
        assert blocked(guard, "read_file", {"path": "/data/reports/q3"}), surface  # not the analyst


def test_a_turn_with_no_chat_sender_is_denied_without_a_default_role(monkeypatch):
    key = tenuo.SigningKey.generate()
    roles = {"roles": {"owner": {"match": {"user": ["telegram:1"]}, "allow": ["terminal"]}}}
    policy = build_access_policy(roles, control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy)
    sender(monkeypatch, user="", chat="", platform="api_server")
    verdict = guard.pre_tool_call("terminal", {"command": "id"}, session_id="s")
    assert verdict and "no access role" in verdict["message"]


def test_a_role_can_name_a_platform_with_no_chat_sender(monkeypatch):
    key = tenuo.SigningKey.generate()
    roles = {"roles": {
        "jobs": {"match": {"platform": ["cron"]}, "allow": {"terminal": {"command": {"binaries": ["git"]}}}},
        "guest": {"default": True, "allow": ["web_search"]},
    }}
    policy = build_access_policy(roles, control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy)
    sender(monkeypatch, user="", chat="", platform="cron")
    assert not blocked(guard, "terminal", {"command": "git pull"})
    sender(monkeypatch, user="", chat="", platform="api_server")
    assert blocked(guard, "terminal", {"command": "git pull"})


def test_a_child_gets_a_full_lifetime_whenever_it_is_delegated(monkeypatch):
    """A child's grant is capped to its parent's expiry, so the role warrant is minted afresh."""
    import time
    from hermes_tenuo.access import AccessPolicy, parse_access
    key = tenuo.SigningKey.generate()
    config = parse_access({"roles": {"owner": {"match": {"user": ["telegram:1"]},
                                               "allow": ["terminal", "delegate_task"]}}})
    policy = AccessPolicy(config, control_key=key, holder=key.public_key, signing_key=key, ttl_seconds=60)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy)
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: (lambda task_id: None))
    sender(monkeypatch, user="telegram:1", chat="", platform="telegram")
    assert not blocked(guard, "terminal", {"command": "id"}, session="p")
    first, _ = policy.warrant_for(user="telegram:1", platform="telegram")
    time.sleep(2.2)                                                   # the role warrant ages
    assert not blocked(guard, "delegate_task", {"goal": "x"}, session="p")
    guard.on_subagent_start("p", "child", child_goal="x")
    child, _ = guard._session_warrants["child"]
    assert child.ttl_remaining.total_seconds() > first.ttl_remaining.total_seconds() + 1
    assert not blocked(guard, "terminal", {"command": "id"}, session="child")


def test_access_enforces_through_real_session_context():
    ctx = pytest.importorskip("gateway.session_context")
    key = tenuo.SigningKey.generate()
    pol = build_access_policy({"roles": {
        "owner": {"match": {"user": ["telegram:7"]}, "allow": {"terminal": {"command": {"binaries": ["git"]}}}},
        "guest": {"default": True, "allow": {"web_search": {}}}}},
        control_key=key, holder=key.public_key, signing_key=key)
    g = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=pol)

    def under(vars, tool, args):
        t = ctx.set_session_vars(session_key="k", **vars)
        try:
            return bool(g.pre_tool_call(tool, args, session_id="s"))
        finally:
            ctx.clear_session_vars(t)

    assert not under(dict(platform="telegram", actor_id="7"), "terminal", {"command": "git log"})       # owner
    assert under(dict(platform="telegram", user_id="42", actor_id="999"), "terminal", {"command": "git log"})  # not owner
    assert not under(dict(platform="telegram", actor_id="999"), "web_search", {"query": "x"})           # guest default


def test_access_mode_does_not_warn_audit_only_on_a_local_fallthrough(monkeypatch, caplog):
    import logging
    key = tenuo.SigningKey.generate()
    pol = build_access_policy({"roles": {"owner": {"match": {"user": ["telegram:1"]}, "allow": {"web_search": {}}}}},
                              control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=pol)
    monkeypatch.setattr(access, "current_sender", lambda: None)   # CLI/local: not a gateway turn
    with caplog.at_level(logging.WARNING):
        assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="s") is None   # passes through
    assert "AUDIT-ONLY" not in caplog.text and guard._audit_only_warned is False


def test_unbound_child_cannot_inherit_a_role_when_start_hook_is_missing(monkeypatch):
    key = tenuo.SigningKey.generate()
    rules = {"roles": {"owner": {"default": True, "allow": ["delegate_task", "web_search", "read_file"]}}}
    policy = build_access_policy(rules, control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy)
    sender(monkeypatch, user="telegram:1", platform="telegram")
    children = {}
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: children.get)
    assert guard.pre_tool_call("delegate_task", {"goal": "research", "toolsets": ["web_search"]},
                               session_id="parent", task_id="parent-task") is None
    children["child-task"] = {"subagent_id": "child-task", "goal": "research"}
    denied = guard.pre_tool_call("read_file", {"path": "/secret"}, session_id="child", task_id="child-task")
    assert denied and "no bound delegation warrant" in denied["message"]
    # Neither another user nor another conversation may claim the staged grant.
    sender(monkeypatch, user="telegram:2", platform="telegram")
    assert guard.pre_tool_call("read_file", {"path": "/public"}, session_id="other", task_id="other-task") is None
    assert len(guard._planned_children["parent"]) == 1
    guard.on_subagent_start("parent", "child", child_goal="research", child_task_id="child-task")
    assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="child", task_id="child-task") is None
    assert guard.pre_tool_call("read_file", {"path": "/secret"}, session_id="child", task_id="child-task")


def test_access_delegation_is_denied_without_runtime_child_attribution(monkeypatch):
    key = tenuo.SigningKey.generate()
    policy = build_access_policy({"roles": {"owner": {"default": True, "allow": ["delegate_task", "web_search"]}}},
                                 control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy, on_denial="log")
    sender(monkeypatch, user="telegram:1", platform="telegram")
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: None)
    denied = guard.pre_tool_call("delegate_task", {"goal": "research"}, session_id="parent")
    assert denied and "requires Hermes subagent attribution" in denied["message"]
    assert not guard._planned_children
    assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="parent") is None


@pytest.mark.parametrize("attribution_available", [False, True])
def test_access_only_local_delegation_remains_unrestricted(monkeypatch, attribution_available):
    key = tenuo.SigningKey.generate()
    policy = build_access_policy({"roles": {"guest": {"default": True, "allow": ["web_search"]}}},
                                 control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(access_policy=policy)
    sender(monkeypatch)  # CLI/Desktop/API: no messaging identity
    def lookup(task):
        return {"subagent_id": task, "parent_session_id": "parent"} if task == "child-task" else None

    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: lookup if attribution_available else None)
    assert guard.pre_tool_call("delegate_task", {"goal": "local work"}, session_id="parent", task_id="parent-task") is None
    guard.on_subagent_start("parent", "child", child_goal="local work", child_task_id="child-task")
    assert guard.pre_tool_call("read_file", {"path": "/local/file"}, session_id="child", task_id="child-task") is None
    # The same unbound child is never allowed to fall back to a messaging role.
    sender(monkeypatch, user="telegram:1", platform="telegram")
    if attribution_available:
        assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="child", task_id="child-task")


@pytest.mark.parametrize("attach_gateway_child", [False, True])
def test_local_calls_never_claim_gateway_grants_or_require_their_warrants(monkeypatch, attach_gateway_child):
    key = tenuo.SigningKey.generate()
    policy = build_access_policy({"roles": {"owner": {"default": True, "allow": ["delegate_task", "web_search"]}}},
                                 control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(access_policy=policy, trusted_roots=[key.public_key])
    sender(monkeypatch, user="telegram:1", platform="telegram")
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: lambda task: None)
    assert guard.pre_tool_call("delegate_task", {"goal": "research"}, session_id="gateway") is None
    if attach_gateway_child:
        guard.on_subagent_start("gateway", "gateway-child", child_goal="research")
    sender(monkeypatch)
    assert guard.pre_tool_call("read_file", {"path": "/local"}, session_id="local") is None
    assert "local" not in guard._session_warrants
    if not attach_gateway_child:
        assert len(guard._planned_children["gateway"]) == 1
    # Local audit-only exemption never overrides an explicit operator requirement.
    guard._require_session_warrant = True
    assert guard.pre_tool_call("read_file", {"path": "/local"}, session_id="local")


@pytest.mark.parametrize("explicit_parent", [False, True])
def test_local_warranted_child_cannot_inherit_authority_when_hook_is_missed(monkeypatch, explicit_parent):
    key = tenuo.SigningKey.generate()
    policy = build_access_policy({"roles": {"owner": {"default": True, "allow": ["delegate_task", "web_search", "read_file"]}}},
                                 control_key=key, holder=key.public_key, signing_key=key)
    parent, _ = policy.warrant_for()
    guard = HermesGuard(warrant=None if explicit_parent else parent, signing_key=key,
                        access_policy=policy, trusted_roots=[key.public_key])
    if explicit_parent:
        guard.set_session_warrant("parent", parent, key)
    sender(monkeypatch)
    children = {}
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: children.get)
    assert guard.pre_tool_call("delegate_task", {"goal": "research", "toolsets": ["web_search"]}, session_id="parent") is None
    children["child-task"] = {"subagent_id": "child-task", "parent_session_id": "parent"}
    denied = guard.pre_tool_call("read_file", {"path": "/secret"}, session_id="child", task_id="child-task")
    assert denied and "no bound delegation warrant" in denied["message"]
    guard.on_subagent_start("parent", "child", child_goal="research")
    assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="child", task_id="child-task") is None
    assert guard.pre_tool_call("read_file", {"path": "/secret"}, session_id="child", task_id="child-task")
