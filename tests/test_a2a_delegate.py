"""Scoped A2A sender (D2): an agent delegates only what its own session holds."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from tenuo import Exact, SigningKey, Warrant, Wildcard

from hermes_tenuo.a2a_delegate import (
    DelegationError,
    Peer,
    SenderConfig,
    constraint_for,
    delegate,
    grant_spec,
)
from hermes_tenuo.a2a_ingress import A2AIngress, public_key_b64
from hermes_tenuo.hermes_guard import HermesGuard

LIGHT = {"ha_call_service": {"domain": {"equals": "light"}, "service": {"one_of": ["turn_on", "turn_off"]},
                             "entity_id": {"equals": "light.porch"}}}


@pytest.fixture()
def k():
    return SimpleNamespace(**{n: SigningKey.generate() for n in ("root", "a", "b", "c")})


@pytest.fixture()
def w_a(k):
    """A's own warrant: Home Assistant service calls on lights, and delegation."""
    return (Warrant.mint_builder().holder(k.a.public_key)
            .capability("ha_call_service", {"domain": Exact("light"), "service": Wildcard(),
                                            "entity_id": Wildcard(), "_allow_unknown": True})
            .capability("ha_get_state", {"entity_id": Wildcard()})
            .capability("tenuo_delegate", {"peer": Wildcard(), "task": Wildcard(), "tools": Wildcard(),
                                            "ttl_seconds": Wildcard()})
            .ttl(3600).mint(k.root))


def _config(k, **extra):
    peers = {"home": Peer("home", "http://home:9900/", public_key_b64(k.b), "TOKEN_HOME")}
    return SenderConfig(peers=peers, **extra)


def _event_text(request, peer):
    """What Hermes hands to plugins for a native A2A SendMessage (extract_text + framing)."""
    chunks = []
    for part in request["params"]["message"]["parts"]:
        if "text" in part:
            chunks.append(part["text"])
        else:
            chunks.append(f"[data ({part['mediaType']})]\n" + json.dumps(part["data"], ensure_ascii=False))
    return f"[A2A inbound — message from a remote agent peer named {peer!r}.]\n\n" + "\n".join(chunks).strip()


class Peer2:
    """A receiving agent: its ingress and guard, reached by ``post``."""

    def __init__(self, own_key, peers, root, name="agent-a"):
        self.ingress = A2AIngress(own_key=own_key, peers=peers, trusted_roots=[root.public_key])
        self.guard = HermesGuard(require_session_warrant=False, ingress=self.ingress)
        self.sender_name = name
        self.requests = []

    def post(self, url, token, body, timeout):
        self.requests.append(body)
        message = body["params"]["message"]
        source = SimpleNamespace(platform=SimpleNamespace(value="a2a"), user_id=self.sender_name,
                                 chat_id=message["contextId"])
        decision = self.ingress.pre_gateway_dispatch(SimpleNamespace(source=source, text=_event_text(body, self.sender_name)))
        if decision["action"] == "skip":
            return {"result": {"task": {"status": {"state": "TASK_STATE_COMPLETED", "message": {"parts": []}}}}}
        self.turn = (self.sender_name, message["contextId"])
        return {"result": {"task": {"status": {"state": "TASK_STATE_COMPLETED",
                                               "message": {"parts": [{"text": "done"}]}}}}}

    def call(self, tool, args, session="sess-b"):
        self.ingress.current_turn = lambda: self.turn
        return self.guard.pre_tool_call(tool, args, session_id=session, tool_call_id=f"{tool}{args}")


@pytest.fixture()
def home(k):
    return Peer2(k.b, {"agent-a": public_key_b64(k.a)}, k.root)


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("TOKEN_HOME", "secret-token")


# --- rules ---------------------------------------------------------------------


def test_rules_use_the_guests_vocabulary():
    spec = grant_spec({"t": {"a": {"equals": 1}, "b": {"one_of": [1, 2]}, "c": {"range": [0, 5]},
                             "d": {"pattern": "x*"}, "e": {"regex": "^x$"}, "f": {"any": True},
                             "*": {"any": True}}})
    assert set(spec["t"]) == {"a", "b", "c", "d", "e", "f", "_allow_unknown"}
    with pytest.raises(DelegationError):
        constraint_for({"maybe": 1})
    with pytest.raises(DelegationError):
        grant_spec({"t": {"*": {"equals": 1}}})
    with pytest.raises(DelegationError):
        grant_spec({})


# --- sending ---------------------------------------------------------------------


def test_a_delegated_task_runs_on_the_peer_within_the_grant_only(k, w_a, home):
    result = delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Turn on the porch light.",
                      tools=LIGHT, ttl_seconds=120, post=home.post)
    assert result["state"] == "TASK_STATE_COMPLETED" and result["grant"]["tools"] == ["ha_call_service"]
    ok = {"domain": "light", "service": "turn_on", "entity_id": "light.porch"}
    assert home.call("ha_call_service", ok) is None
    assert home.call("ha_call_service", {**ok, "entity_id": "light.office"})["action"] == "block"
    assert home.call("ha_call_service", {**ok, "data": "{}"})["action"] == "block"  # not listed
    assert home.call("ha_get_state", {"entity_id": "light.porch"})["action"] == "block"  # not granted
    assert home.requests[0]["params"]["message"]["contextId"] == result["context_id"]


def test_optional_arguments_can_be_left_open_when_the_sender_may(k, w_a, home):
    tools = {"ha_call_service": {**LIGHT["ha_call_service"], "*": {"any": True}}}
    delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Porch light on, dimmed.",
             tools=tools, post=home.post)
    args = {"domain": "light", "service": "turn_on", "entity_id": "light.porch", "data": '{"brightness": 80}'}
    assert home.call("ha_call_service", args) is None


def test_an_agent_cannot_delegate_more_than_its_session_holds(k, w_a, home):
    with pytest.raises(DelegationError, match="not within this session's own authority"):
        delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Unlock.",
                 tools={"lock_unlock": {"entity_id": {"equals": "lock.front"}}}, post=home.post)
    with pytest.raises(DelegationError, match="not within"):  # domain outside A's own constraint
        delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Open the garage.",
                 tools={"ha_call_service": {"domain": {"equals": "cover"}, "service": {"any": True},
                                            "entity_id": {"any": True}}}, post=home.post)
    assert home.requests == []


def test_unnamed_arguments_cannot_be_opened_when_the_sender_cannot(k, home):
    strict = (Warrant.mint_builder().holder(k.a.public_key)
              .capability("ha_get_state", {"entity_id": Wildcard()}).ttl(600).mint(k.root))
    with pytest.raises(DelegationError, match="not within"):
        delegate(config=_config(k), chain=[strict], key=k.a, peer="home", task="Read it.",
                 tools={"ha_get_state": {"entity_id": {"equals": "light.porch"}, "*": {"any": True}}},
                 post=home.post)


@pytest.mark.parametrize("change, reason", [
    (dict(peer="office"), "no paired peer"),
    (dict(task=""), "1 to"),
    (dict(ttl_seconds=5), "between 10"),
    (dict(ttl_seconds=100000), "between 10"),
    (dict(chain=[], key=None), "holds no warrant"),
])
def test_requests_that_cannot_be_sent_are_refused_before_anything_leaves(k, w_a, home, change, reason):
    args = dict(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Porch on.", tools=LIGHT,
                ttl_seconds=60, post=home.post)
    args.update(change)
    with pytest.raises(DelegationError, match=reason):
        delegate(**args)
    assert home.requests == []


def test_a_missing_peer_token_is_reported(k, w_a, home, monkeypatch):
    monkeypatch.delenv("TOKEN_HOME")
    with pytest.raises(DelegationError, match="TOKEN_HOME"):
        delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Porch on.", tools=LIGHT,
                 post=home.post)


def test_a_transport_failure_is_reported_and_not_retried(k, w_a):
    calls = []

    def broken(*a):
        calls.append(a)
        raise TimeoutError("slow")

    result = delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Porch on.",
                      tools=LIGHT, post=broken)
    assert result["state"] == "unknown" and "may or may not have run" in result["reply"] and len(calls) == 1


def test_a_peer_that_drops_the_task_is_not_reported_as_success(k, w_a):
    other = Peer2(k.b, {"agent-a": public_key_b64(k.c)}, k.root)  # pins a different key for agent-a
    result = delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Porch on.",
                      tools=LIGHT, post=other.post)
    assert result["state"] == "refused_or_empty"


# --- the guard supplies this session's authority -----------------------------------


def test_the_guard_hands_over_the_sessions_own_warrant_and_key(k, w_a):
    guard = HermesGuard(warrant=w_a, signing_key=k.a, trusted_roots=[k.root.public_key])
    chain, key = guard.delegation_authority("s1")
    assert [w.id for w in chain] == [w_a.id] and key is k.a
    assert HermesGuard().delegation_authority("s1") == ([], None)


def test_a_delegated_turn_can_delegate_onward_only_within_its_grant(k, w_a, home):
    """A → B → C: B's onward grant is a child of the grant A gave B, and C verifies all three."""
    tools = {"ha_call_service": {"domain": {"equals": "light"}, "service": {"one_of": ["turn_on", "turn_off"]},
                                 "entity_id": {"one_of": ["light.porch", "light.hall"]}}}
    delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Handle porch and hall.",
             tools=tools, post=home.post)
    home.ingress.current_turn = lambda: home.turn
    chain_b, key_b = home.guard.delegation_authority("sess-b")
    assert len(chain_b) == 2 and key_b is k.b

    carol = Peer2(k.c, {"agent-b": public_key_b64(k.b)}, k.root, name="agent-b")
    to_carol = SenderConfig(peers={"carol": Peer("carol", "http://c:9900/", public_key_b64(k.c), "TOKEN_HOME")})
    hall = {"ha_call_service": {"domain": {"equals": "light"}, "service": {"equals": "turn_on"},
                                "entity_id": {"equals": "light.hall"}}}
    delegate(config=to_carol, chain=chain_b, key=key_b, peer="carol", task="Hall light on.", tools=hall,
             post=carol.post)
    ok = {"domain": "light", "service": "turn_on", "entity_id": "light.hall"}
    assert carol.call("ha_call_service", ok, session="sess-c") is None
    assert carol.call("ha_call_service", {**ok, "entity_id": "light.porch"}, session="sess-c")["action"] == "block"
    # B cannot widen what A gave it.
    with pytest.raises(DelegationError, match="not within"):
        delegate(config=to_carol, chain=chain_b, key=key_b, peer="carol", task="Office.",
                 tools={"ha_call_service": {"domain": {"equals": "light"}, "service": {"equals": "turn_on"},
                                            "entity_id": {"equals": "light.office"}}}, post=carol.post)


# --- registration ---------------------------------------------------------------------


class _Ctx:
    def __init__(self):
        self.tools, self.hooks = {}, {}

    def register_hook(self, name, fn):
        self.hooks.setdefault(name, []).append(fn)

    def register_tool(self, name, toolset, schema, handler, check_fn=None, **kw):
        self.tools[name] = SimpleNamespace(handler=handler, check=check_fn, schema=schema)


def _register(monkeypatch, entry):
    import hermes_tenuo

    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry", lambda _ctx: entry)
    ctx = _Ctx()
    hermes_tenuo.register(ctx)
    return ctx


def test_the_tool_is_registered_but_hidden_when_not_configured(monkeypatch):
    ctx = _register(monkeypatch, {})
    tool = ctx.tools["tenuo_delegate"]
    assert tool.check() is False
    assert json.loads(tool.handler({"peer": "x", "task": "y", "tools": {}}))["ok"] is False


def test_the_tool_is_offered_when_peers_and_enforcement_are_configured(monkeypatch, k, w_a):
    entry = {"warrant": w_a.to_base64(),
             "a2a_delegation": {"peers": {"home": {"url": "http://home:9900/", "public_key": public_key_b64(k.b),
                                                   "token_env": "TOKEN_HOME"}}}}
    monkeypatch.setenv("TENUO_SIGNING_KEY", __import__("base64").b64encode(k.a.secret_key_bytes()).decode())
    monkeypatch.setenv("TENUO_TRUSTED_ROOT", public_key_b64(k.root))
    ctx = _register(monkeypatch, entry)
    assert ctx.tools["tenuo_delegate"].check() is True


# --- meeting the MCP track: a delegated turn proves its grant to a Tenuo MCP verifier ---


def test_a_delegated_turn_presents_its_grant_to_an_mcp_verifier(k, w_a, home):
    """operator → A → B, then B calls a wrapped MCP tool: the verifier the MCP wrapper uses checks
    the whole chain and B's proof, and refuses anything outside the grant."""
    from tenuo import Authorizer
    from tenuo.mcp import MCPVerifier

    delegate(config=_config(k), chain=[w_a], key=k.a, peer="home", task="Porch light on.",
             tools=LIGHT, post=home.post)
    home.ingress.current_turn = lambda: home.turn
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[k.root.public_key]))
    ok = {"domain": "light", "service": "turn_on", "entity_id": "light.porch"}
    meta = home.guard.call_meta("sess-b", "ha_call_service", ok)
    allowed = verifier.verify("ha_call_service", ok, meta=meta)
    assert allowed.allowed, allowed
    assert [w.id for w in allowed.presented_chain][:1] == [w_a.id]
    office = {**ok, "entity_id": "light.office"}
    assert not verifier.verify("ha_call_service", office, meta=home.guard.call_meta("sess-b", "ha_call_service", office)).allowed
    assert not verifier.verify("ha_call_service", office, meta=meta).allowed  # a proof is bound to its arguments
    # A's own session presents A's warrant, not B's grant.
    a_guard = HermesGuard(warrant=w_a, signing_key=k.a, trusted_roots=[k.root.public_key])
    a_meta = a_guard.call_meta("s-a", "ha_get_state", {"entity_id": "light.porch"})
    assert verifier.verify("ha_get_state", {"entity_id": "light.porch"}, meta=a_meta).allowed
    assert HermesGuard().call_meta("s", "x", {}) is None
