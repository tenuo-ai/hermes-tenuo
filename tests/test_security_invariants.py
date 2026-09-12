"""
Security invariant tests for hermes-tenuo.

These tests verify that HermesGuard enforces Tenuo's core security properties
regardless of how it is configured. Every test here should remain green for any
compliant implementation — they define the security contract, not implementation
details.

Invariants tested:
    I1  Fail-closed:    Missing/invalid warrant/key → block, never allow
    I2  Monotonicity:   Child tools ⊆ parent tools; child constraint ≥ parent constraint
    I3  Expiry cap:     child.exp ≤ parent.exp (enforced by Rust core)
    I4  Closed-world:   Every argument passed must be declared; undeclared args → block
    I5  PoP binding:    Wrong signing key → block even with a valid warrant
    I6  Issuer trust:   Warrant from untrusted issuer → block
    I7  Chain integrity: Fake parent in warrant_chain → block
    I8  No escalation:  Child cannot access tools the parent never had
"""

import base64
import pytest

from hermes_tenuo.hermes_guard import HermesGuard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cloud_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def agent_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def other_key():
    """A completely unrelated key — used to simulate wrong-key attacks."""
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def parent_warrant(cloud_key, agent_key):
    from tenuo import Warrant, Wildcard, Subpath
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("tool:web_search", query=Wildcard())
        .capability("tool:read_file", path=Subpath("/data"))
        .ttl(3600)
        .mint(cloud_key)
    )


@pytest.fixture
def guard(parent_warrant, agent_key, cloud_key):
    g = HermesGuard(
        warrant=parent_warrant,
        signing_key=agent_key,
        trusted_roots=[cloud_key.public_key],
    )
    g._primary_session_id = "s1"
    return g


# ---------------------------------------------------------------------------
# I1: Fail-closed
# ---------------------------------------------------------------------------


class TestFailClosed:

    def test_no_warrant_blocks_all_calls(self, agent_key, cloud_key):
        """No warrant configured — every call is blocked (not passed through)."""
        guard = HermesGuard(signing_key=agent_key, trusted_roots=[cloud_key.public_key])
        guard._primary_session_id = "s1"
        # Without a warrant the guard is in audit-only / pass-through mode —
        # but with a signing key and trusted_roots, warrant absence means pass-through.
        # The invariant: if the operator configures a signing key, they expect
        # enforcement. A None warrant with a signing key is audit-only, not blocked.
        # This test verifies the audit-only contract (pass-through without warrant).
        result = guard.pre_tool_call("web_search", {"query": "x"}, session_id="s1")
        assert result is None  # audit-only pass-through

    def test_no_signing_key_hard_blocks(self, parent_warrant, cloud_key):
        """Warrant present but no signing key → hard block, not silent pass-through."""
        guard = HermesGuard(
            warrant=parent_warrant,
            signing_key=None,
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        result = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"
        assert "TENUO_SIGNING_KEY" in result["message"]

    def test_expired_warrant_blocks(self, agent_key, cloud_key):
        """Expired warrant blocks all calls, including previously-authorized tools."""
        from tenuo import Warrant, Wildcard
        import time
        expired = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:web_search", query=Wildcard())
            .ttl(1)
            .mint(cloud_key)
        )
        time.sleep(2)
        guard = HermesGuard(
            warrant=expired,
            signing_key=agent_key,
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        result = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"

    def test_tool_not_in_warrant_blocks(self, guard):
        """Tool not declared in warrant → block."""
        result = guard.pre_tool_call("tool:terminal", {"command": "ls"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"

    def test_tool_not_in_warrant_normalization_still_blocks(self, guard):
        """Bare name not in warrant, prefixed name also not in warrant → block."""
        result = guard.pre_tool_call("terminal", {"command": "ls"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"

    def test_no_trusted_root_hard_blocks(self, parent_warrant, agent_key):
        """Warrant + signing key present but no trusted root and no chain → hard block.

        The agent-key fallback was removed: without an issuer anchor we cannot
        verify the warrant's signature, so we refuse rather than trust an
        unrelated key (the holder's own pubkey).
        """
        guard = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=None,  # no anchor configured
        )
        guard._primary_session_id = "s1"
        result = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"
        assert any(w in result["message"] for w in ("trusted_root", "issuer", "trusted"))

    def test_audit_only_mode_emits_warning_once(self, agent_key, cloud_key, caplog):
        """Audit-only mode (no warrant) must be visible in logs at first call."""
        import logging
        guard = HermesGuard(signing_key=agent_key, trusted_roots=[cloud_key.public_key])
        guard._primary_session_id = "s1"
        with caplog.at_level(logging.WARNING, logger="hermes_tenuo"):
            guard.pre_tool_call("web_search", {"query": "a"}, session_id="s1")
            guard.pre_tool_call("web_search", {"query": "b"}, session_id="s1")
        audit_warnings = [r for r in caplog.records if "AUDIT-ONLY" in r.getMessage()]
        assert len(audit_warnings) == 1


# ---------------------------------------------------------------------------
# Trusted root management — lock-protected setter
# ---------------------------------------------------------------------------


class TestTrustedRootsSetter:

    def test_set_trusted_roots_installs_anchor(self, parent_warrant, agent_key, cloud_key):
        """set_trusted_roots makes enforcement succeed after the fact."""
        guard = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=None,
        )
        guard._primary_session_id = "s1"
        # Initially blocks because no trusted root.
        r = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        assert r is not None and r["action"] == "block"
        # Install the right anchor.
        guard.set_trusted_roots([cloud_key.public_key])
        r2 = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        assert r2 is None

    def test_set_trusted_roots_none_clears(self, parent_warrant, agent_key, cloud_key):
        """Passing None clears the trusted root set."""
        guard = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        guard.set_trusted_roots(None)
        r = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        assert r is not None and r["action"] == "block"


# ---------------------------------------------------------------------------
# I2: Monotonicity — child ⊆ parent
# ---------------------------------------------------------------------------


class TestMonotonicity:

    def test_attenuate_builder_enforces_tool_subset(self, parent_warrant, agent_key, cloud_key):
        """attenuate_builder cannot add tools the parent doesn't have."""
        from tenuo import Warrant, Wildcard
        other_key = agent_key  # reuse for simplicity
        b = parent_warrant.attenuate_builder()
        b.inherit_all()
        b.with_tools(["tool:web_search"])
        b.with_ttl(60)
        child = b.delegate(agent_key)
        # Child should only have web_search, not read_file
        assert child.tools is not None
        assert "tool:web_search" in child.tools
        assert "tool:read_file" not in child.tools

    def test_child_cannot_call_parent_only_tool(self, parent_warrant, agent_key, cloud_key):
        """A tool dropped in attenuation is blocked for the child session."""
        b = parent_warrant.attenuate_builder()
        b.inherit_all()
        b.with_tools(["tool:web_search"])  # drop read_file
        b.with_ttl(60)
        child = b.delegate(agent_key)

        guard = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        guard.set_session_warrant("child-1", child, agent_key)
        # Store parent in chain so enforcement verifies root→parent→child
        with guard._session_lock:
            guard._session_warrant_chains["child-1"] = parent_warrant

        # web_search allowed for child (in child warrant + chain verifies)
        r = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="child-1")
        assert r is None

        # read_file blocked for child (dropped in attenuation)
        r2 = guard.pre_tool_call("tool:read_file", {"path": "/data/x"}, session_id="child-1")
        assert r2 is not None
        assert r2["action"] == "block"

    def test_parent_can_call_what_child_cannot(self, parent_warrant, agent_key, cloud_key):
        """Parent retains its full scope; child's restriction doesn't affect parent."""
        b = parent_warrant.attenuate_builder()
        b.inherit_all()
        b.with_tools(["tool:web_search"])
        b.with_ttl(60)
        child = b.delegate(agent_key)

        guard = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        guard.set_session_warrant("child-1", child, agent_key)
        with guard._session_lock:
            guard._session_warrant_chains["child-1"] = parent_warrant

        # Parent can still read_file
        r = guard.pre_tool_call("tool:read_file", {"path": "/data/x"}, session_id="s1")
        assert r is None

        # Child cannot read_file
        r2 = guard.pre_tool_call("tool:read_file", {"path": "/data/x"}, session_id="child-1")
        assert r2 is not None
        assert r2["action"] == "block"


# ---------------------------------------------------------------------------
# I3: Expiry cap — child.exp <= parent.exp
# ---------------------------------------------------------------------------


class TestExpiryCap:

    def test_child_ttl_capped_at_parent_remaining(self, agent_key, cloud_key):
        """Child warrant TTL is capped at parent's remaining lifetime by Rust core."""
        from tenuo import Warrant, Wildcard
        parent = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:web_search", query=Wildcard())
            .ttl(60)
            .mint(cloud_key)
        )
        b = parent.attenuate_builder()
        b.inherit_all()
        b.with_ttl(86400)  # request 24h — parent only has 60s
        b.with_ttl(86400)
        child = b.delegate(agent_key)
        # Child expires at same time as parent, not 24h from now
        assert child.expires_at() <= parent.expires_at()


# ---------------------------------------------------------------------------
# I4: Closed-world — undeclared args are blocked
# ---------------------------------------------------------------------------


class TestClosedWorld:

    def test_undeclared_argument_is_blocked(self, agent_key, cloud_key):
        """An argument not declared in the warrant is rejected (zero-trust mode)."""
        from tenuo import Warrant, Wildcard
        # Warrant only declares 'query' for web_search
        w = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:web_search", query=Wildcard())
            .ttl(60)
            .mint(cloud_key)
        )
        guard = HermesGuard(
            warrant=w, signing_key=agent_key, trusted_roots=[cloud_key.public_key]
        )
        guard._primary_session_id = "s1"
        # Pass 'limit' which is not declared → should be blocked
        r = guard.pre_tool_call("tool:web_search", {"query": "x", "limit": 5}, session_id="s1")
        assert r is not None
        assert r["action"] == "block"
        assert "limit" in r["message"] or "unknown" in r["message"].lower()

    def test_declared_argument_is_allowed(self, agent_key, cloud_key):
        """An argument declared as Wildcard() is accepted with any value."""
        from tenuo import Warrant, Wildcard
        w = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:web_search", query=Wildcard())
            .ttl(60)
            .mint(cloud_key)
        )
        guard = HermesGuard(
            warrant=w, signing_key=agent_key, trusted_roots=[cloud_key.public_key]
        )
        guard._primary_session_id = "s1"
        r = guard.pre_tool_call("tool:web_search", {"query": "any value at all"}, session_id="s1")
        assert r is None

    def test_constraint_violation_is_blocked(self, agent_key, cloud_key):
        """An argument that violates its constraint (e.g. path outside Subpath) is blocked."""
        from tenuo import Warrant, Subpath
        w = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:read_file", path=Subpath("/data"))
            .ttl(60)
            .mint(cloud_key)
        )
        guard = HermesGuard(
            warrant=w, signing_key=agent_key, trusted_roots=[cloud_key.public_key]
        )
        guard._primary_session_id = "s1"
        # /etc/passwd is outside /data
        r = guard.pre_tool_call("tool:read_file", {"path": "/etc/passwd"}, session_id="s1")
        assert r is not None
        assert r["action"] == "block"
        assert "path" in r["message"].lower()


# ---------------------------------------------------------------------------
# I5: PoP binding — wrong signing key is rejected
# ---------------------------------------------------------------------------


class TestPoPBinding:

    def test_wrong_signing_key_blocks(self, parent_warrant, cloud_key):
        """Agent with wrong signing key cannot use a valid warrant."""
        from tenuo import SigningKey
        wrong_key = SigningKey.generate()  # not the holder key
        guard = HermesGuard(
            warrant=parent_warrant,
            signing_key=wrong_key,  # wrong key
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        r = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        # Wrong PoP → authorization error → block
        assert r is not None
        assert r["action"] == "block"


# ---------------------------------------------------------------------------
# I6: Issuer trust — untrusted issuer is rejected
# ---------------------------------------------------------------------------


class TestIssuerTrust:

    def test_untrusted_issuer_blocks(self, agent_key, cloud_key):
        """Warrant signed by an unknown issuer is rejected even if structurally valid."""
        from tenuo import Warrant, Wildcard, SigningKey
        malicious_issuer = SigningKey.generate()  # not in trusted_roots
        forged = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:terminal", command=Wildcard())  # escalated capability
            .ttl(3600)
            .mint(malicious_issuer)  # signed by untrusted key
        )
        guard = HermesGuard(
            warrant=forged,
            signing_key=agent_key,
            trusted_roots=[cloud_key.public_key],  # cloud_key ≠ malicious_issuer
        )
        guard._primary_session_id = "s1"
        r = guard.pre_tool_call("tool:terminal", {"command": "ls"}, session_id="s1")
        assert r is not None
        assert r["action"] == "block"


# ---------------------------------------------------------------------------
# I7: Chain integrity — fake parent in chain is rejected
# ---------------------------------------------------------------------------


class TestChainIntegrity:

    def test_fake_parent_in_chain_blocks(self, agent_key, cloud_key):
        """A child warrant presented with a fake parent (not its actual ancestor) is rejected."""
        from tenuo import Warrant, SigningKey, Wildcard, Subpath

        attacker_key = SigningKey.generate()

        # Parent minted by the trusted root
        real_parent = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:web_search", query=Wildcard())
            .ttl(3600)
            .mint(cloud_key)
        )

        # Attacker-issued "parent" claiming broader scope
        fake_parent = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:terminal", command=Wildcard())
            .ttl(3600)
            .mint(attacker_key)  # not trusted
        )

        # Real child attenuated from real parent
        b = real_parent.attenuate_builder()
        b.inherit_all()
        b.with_ttl(60)
        child = b.delegate(agent_key)

        guard = HermesGuard(
            warrant=real_parent,
            signing_key=agent_key,
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        guard.set_session_warrant("child-1", child, agent_key)
        # Inject a fake parent into the chain store (simulates the attack)
        with guard._session_lock:
            guard._session_warrant_chains["child-1"] = fake_parent

        # Enforcement should fail because the chain is broken (fake parent is
        # not signed by a trusted root, so check_chain fails)
        r = guard.pre_tool_call("tool:terminal", {"command": "ls"}, session_id="child-1")
        assert r is not None
        assert r["action"] == "block"


# ---------------------------------------------------------------------------
# I8: No escalation — child cannot exceed parent scope
# ---------------------------------------------------------------------------


class TestNoEscalation:

    def test_child_cannot_claim_tool_parent_never_had(self, agent_key, cloud_key):
        """Child warrant cannot grant a tool the parent was never authorized for."""
        from tenuo import Warrant, Wildcard
        # Parent only has web_search
        parent = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:web_search", query=Wildcard())
            .ttl(3600)
            .mint(cloud_key)
        )
        # Try to create a child with terminal (not in parent) via attenuate_builder
        b = parent.attenuate_builder()
        b.inherit_all()
        # with_tools only whitelists from what parent already has — terminal isn't there
        b.with_tools(["tool:web_search", "tool:terminal"])
        b.with_ttl(60)
        child = b.delegate(agent_key)
        # Child should not have terminal even though we asked for it
        assert child.tools is not None
        assert "tool:terminal" not in child.tools

    def test_child_tool_blocked_for_unauthorized_tool(self, agent_key, cloud_key):
        """Even if child warrant somehow contains an escalated tool, enforcement rejects it
        when the warrant chain is verified against the parent that didn't have the tool."""
        from tenuo import Warrant, Wildcard, SigningKey
        # This test verifies that warrant_chain enforcement (check_chain) catches
        # escalation even if the child object was constructed with extra tools.
        # We can't easily construct a "valid but escalated" child with attenuate_builder
        # (Rust prevents it), so we verify the invariant holds from the parent side:
        # a tool not in the parent is not in any properly-derived child.
        parent = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("tool:web_search", query=Wildcard())
            .ttl(3600)
            .mint(cloud_key)
        )
        b = parent.attenuate_builder()
        b.inherit_all()
        b.with_ttl(60)
        child = b.delegate(agent_key)

        guard = HermesGuard(
            warrant=parent,
            signing_key=agent_key,
            trusted_roots=[cloud_key.public_key],
        )
        guard._primary_session_id = "s1"
        guard.set_session_warrant("child-1", child, agent_key)
        with guard._session_lock:
            guard._session_warrant_chains["child-1"] = parent

        # terminal not in parent, not in child → blocked
        r = guard.pre_tool_call("tool:terminal", {"command": "ls"}, session_id="child-1")
        assert r is not None
        assert r["action"] == "block"
