"""Trust comes only from a configured trusted_root, never from the warrant under test."""

import pytest
from tenuo import SigningKey, Subpath, Warrant

from hermes_tenuo.hermes_guard import HermesGuard


def _guard(trusted, on_denial="block", issuer=None):
    root, agent = issuer or SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder().holder(agent.public_key)
        .capability("read_file", path=Subpath("/data")).capability("delegate_task")
        .ttl(600).mint(root)
    )
    roots = [root.public_key] if trusted == "own" else trusted
    guard = HermesGuard(warrant=warrant, signing_key=agent, trusted_roots=roots, on_denial=on_denial)
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1")
    return guard


def _read(guard, session):
    return guard.pre_tool_call("read_file", {"path": "/data/q3.csv"}, session_id=session)


@pytest.mark.parametrize("session", ["s0", "s1"])
def test_no_trusted_root_fails_closed_for_root_and_child(session):
    blocked = _read(_guard(trusted=None), session)
    assert blocked and blocked["action"] == "block"


def test_child_chain_is_not_trusted_on_its_own_issuer():
    """A chain signed by an unknown key must not verify just because it is a chain."""
    attacker = SigningKey.generate()
    guard = _guard(trusted=[SigningKey.generate().public_key], issuer=attacker)
    assert _read(guard, "s1") is not None


@pytest.mark.parametrize("session", ["s0", "s1"])
def test_configured_trusted_root_verifies_root_and_child(session):
    assert _read(_guard(trusted="own"), session) is None


@pytest.mark.parametrize("session", ["s0", "s1"])
def test_audit_mode_logs_instead_of_blocking(session):
    assert _read(_guard(trusted=None, on_denial="log"), session) is None
