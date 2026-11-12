"""Scoped A2A sender: delegate one bounded task to a paired Hermes, from this session's own authority.

The agent calls ``tenuo_delegate(peer, task, tools, ttl_seconds)``. The grant is a child of the warrant
this session already holds (as the guard resolves it), held by the peer's pinned public key, so an
agent can only delegate what it holds and only the peer can use it. The request is signed with this
session's key and sent as a native A2A ``SendMessage``; the peer verifies and enforces it itself
(``hermes_tenuo.a2a_ingress``).

Peers come only from the operator's config, never from the model::

    a2a_delegation:
      peers:
        home:
          url: http://home-hermes:9900/
          public_key: "<the peer's A2A key, base64>"
          token_env: A2A_TOKEN_HOME        # bearer token for that peer's A2A endpoint
      max_ttl_seconds: 900
      reply_timeout_seconds: 300

Rules for each tool argument use this vocabulary::

    {"equals": v} · {"one_of": [..]} · {"range": [lo, hi]} · {"pattern": "glob*"} ·
    {"regex": "^...$"} · {"any": true}

An argument the grant does not name is refused by the peer, unless the tool lists ``"*": {"any": true}``
(only possible when this session's own warrant allows unnamed arguments for that tool).
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes_tenuo.a2a")

TOOL_NAME = "tenuo_delegate"
DEFAULT_TTL = 300
MAX_TASK_CHARS = 8000


class DelegationError(ValueError):
    """A delegation was not sent. The message says why, for the model and the operator."""


@dataclass(frozen=True)
class Peer:
    name: str
    url: str
    public_key: str
    token_env: str


@dataclass(frozen=True)
class SenderConfig:
    peers: Dict[str, Peer]
    max_ttl_seconds: int = 900
    reply_timeout_seconds: int = 300


def load_sender_config(ctx: Any) -> Optional[SenderConfig]:
    """``a2a_delegation`` from the plugin config, or None when it is not configured."""
    from hermes_tenuo._config import _get_plugin_entry
    from tenuo import PublicKey

    block = _get_plugin_entry(ctx).get("a2a_delegation")
    if not isinstance(block, dict) or not block.get("peers"):
        return None
    peers: Dict[str, Peer] = {}
    for name, raw in dict(block["peers"]).items():
        if not isinstance(raw, dict):
            raise ValueError(f"a2a_delegation peer {name!r} must be a mapping")
        url, key, token_env = str(raw.get("url") or ""), str(raw.get("public_key") or ""), str(raw.get("token_env") or "")
        if not url.startswith(("http://", "https://")) or not key or not token_env:
            raise ValueError(f"a2a_delegation peer {name!r} needs url, public_key and token_env")
        PublicKey.from_bytes(base64.b64decode(key))  # raises on a bad key
        peers[str(name)] = Peer(str(name), url, key, token_env)
    return SenderConfig(peers=peers, max_ttl_seconds=int(block.get("max_ttl_seconds", 900)),
                        reply_timeout_seconds=int(block.get("reply_timeout_seconds", 300)))


# ---------------------------------------------------------------------------
# Rules → Tenuo constraints
# ---------------------------------------------------------------------------


def constraint_for(rule: Any) -> Any:
    """One Tenuo constraint from a JSON rule."""
    from tenuo import AnyOf, Exact, OneOf, Pattern, Range, Regex, Wildcard

    if not isinstance(rule, dict) or len(rule) != 1:
        raise DelegationError(f"a rule must have exactly one kind, got {rule!r}")
    kind, value = next(iter(rule.items()))
    if kind == "equals":
        if isinstance(value, str):
            return Exact(value)
        if type(value) in (int, float) and abs(value) <= 2**53 - 1:
            return Range(value, value)
        raise DelegationError("equals needs a string or a finite number in the safe numeric range")
    if kind == "one_of" and isinstance(value, list) and value:
        if all(isinstance(item, str) for item in value):
            return OneOf(value)
        return AnyOf([constraint_for({"equals": item}) for item in value])
    if kind == "range" and isinstance(value, list) and len(value) == 2:
        return Range(value[0], value[1])
    if kind == "pattern" and isinstance(value, str):
        return Pattern(value)
    if kind == "regex" and isinstance(value, str):
        return Regex(value)
    if kind == "any" and value is True:
        return Wildcard()
    raise DelegationError(f"unknown rule {rule!r}; use equals, one_of, range, pattern, regex or any")


def grant_spec(tools: Any) -> Dict[str, Dict[str, Any]]:
    """{tool: {arg: constraint, "_allow_unknown": True?}} from the model's ``tools`` argument."""
    if not isinstance(tools, dict) or not tools:
        raise DelegationError("name at least one tool the peer may use, with a rule for each argument")
    spec: Dict[str, Dict[str, Any]] = {}
    for tool, rules in tools.items():
        if not isinstance(tool, str) or not tool or not isinstance(rules, dict):
            raise DelegationError(f"tool {tool!r} needs a mapping of argument rules")
        constraints: Dict[str, Any] = {}
        for arg, rule in rules.items():
            if arg == "*":
                if rule != {"any": True}:
                    raise DelegationError('"*" may only be {"any": true}: unnamed arguments allowed')
                constraints["_allow_unknown"] = True
            else:
                constraints[str(arg)] = constraint_for(rule)
        spec[tool] = constraints
    return spec


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------


def _secret(name: str) -> str:
    from hermes_tenuo._config import _env_secret

    return _env_secret(name) or ""


def _egress_text(text: str) -> str:
    try:
        from agent.redact import redact_for_egress
        return redact_for_egress(text)
    except Exception:
        return text


def _post(url: str, token: str, body: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {token}", "A2A-Version": "1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured peer URL
        return json.loads(resp.read().decode("utf-8"))


def _outcome(response: Dict[str, Any]) -> Tuple[str, str]:
    """(state, reply text) from a SendMessage response."""
    if "error" in response:
        return "rejected", str((response.get("error") or {}).get("message") or "the peer refused the task")
    result = response.get("result") or {}
    task = result.get("task") or result
    status = task.get("status") or {}
    parts = (status.get("message") or {}).get("parts") or []
    text = " ".join(str(p.get("text", "")) for p in parts if isinstance(p, dict)).strip()
    state = str(status.get("state") or "unknown")
    if state == "TASK_STATE_COMPLETED" and not text:
        # A peer that dropped the task at ingress currently reports an empty completion.
        return "refused_or_empty", "The peer returned no result. It may have refused the delegation."
    return state, text


def delegate(*, config: SenderConfig, chain: List[Any], key: Any, peer: str, task: str,
             tools: Any, ttl_seconds: Any = DEFAULT_TTL, post=_post) -> Dict[str, Any]:
    """Grant, sign and send one task. ``chain`` is root-first and ends with this session's warrant."""
    from tenuo import PublicKey

    from hermes_tenuo.a2a_ingress import build_envelope, grant_to, send_message_request

    target = config.peers.get(str(peer))
    if target is None:
        raise DelegationError(f"no paired peer called {peer!r}; paired: {', '.join(sorted(config.peers)) or 'none'}")
    task = str(task or "").strip()
    if not task or len(task) > MAX_TASK_CHARS:
        raise DelegationError(f"the task must be 1 to {MAX_TASK_CHARS} characters")
    try:
        ttl = int(ttl_seconds)
    except (TypeError, ValueError):
        raise DelegationError("ttl_seconds must be a whole number of seconds") from None
    if not 10 <= ttl <= config.max_ttl_seconds:
        raise DelegationError(f"ttl_seconds must be between 10 and {config.max_ttl_seconds}")
    if not chain or key is None:
        raise DelegationError("this session holds no warrant, so it has nothing to delegate")
    spec = grant_spec(tools)
    recipient = PublicKey.from_bytes(base64.b64decode(target.public_key))
    try:
        grant = grant_to(key, chain, recipient, spec, ttl)
    except Exception as exc:  # Tenuo refuses anything broader than this session holds
        raise DelegationError(f"that grant is not within this session's own authority ({exc})") from exc
    token = _secret(target.token_env)
    if not token:
        raise DelegationError(f"the token for peer {peer!r} ({target.token_env}) is not set")
    task = _egress_text(task)
    context_id = "tenuo-" + uuid.uuid4().hex
    envelope = build_envelope(sender_key=key, sender_chain=chain, grant=grant, audience=target.public_key,
                              context_id=context_id, task_text=task)
    started = time.time()
    try:
        response = post(target.url, token, send_message_request(envelope, task, context_id),
                        config.reply_timeout_seconds)
    except urllib.error.HTTPError as exc:
        state, reply = "rejected", f"the peer answered HTTP {exc.code}"
    except Exception as exc:
        # Not retried: the task may have run. Report what is known.
        state, reply = "unknown", f"no answer from the peer ({type(exc).__name__}); the task may or may not have run"
    else:
        state, reply = _outcome(response)
    return {
        "peer": target.name, "context_id": context_id, "state": state, "reply": reply,
        "seconds": round(time.time() - started, 1),
        "grant": {"id": str(grant.id), "tools": sorted(spec), "ttl_seconds": ttl},
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

DESCRIPTION = (
    "Delegate one bounded task to a paired Hermes agent. The peer receives a signed, expiring grant "
    "covering only the tools and argument values you list, derived from your own permissions, and "
    "enforces it itself before running anything. Use when another agent should do part of a job, e.g. "
    "control a device it manages. List every argument the peer's tool needs with a rule: "
    '{"equals": v}, {"one_of": [..]}, {"range": [lo, hi]}, {"pattern": "glob*"}, {"regex": "..."} or '
    '{"any": true}. Arguments you do not list are refused by the peer. Not retried automatically.'
)

SCHEMA = {
    "name": TOOL_NAME,
    "description": DESCRIPTION,
    "parameters": {
        "type": "object",
        "properties": {
            "peer": {"type": "string", "description": "A paired peer's name."},
            "task": {"type": "string", "description": "What the peer should do, in plain words."},
            "tools": {
                "type": "object",
                "description": 'Per tool, a rule for each argument, e.g. {"ha_call_service": {"domain": '
                               '{"equals": "light"}, "service": {"one_of": ["turn_on", "turn_off"]}, '
                               '"entity_id": {"equals": "light.porch"}}}',
                "additionalProperties": {"type": "object"},
            },
            "ttl_seconds": {"type": "integer", "minimum": 10, "description": "How long the grant lasts."},
        },
        "required": ["peer", "task", "tools"],
        "additionalProperties": False,
    },
}


def register(ctx: Any, get_guard: Any) -> bool:
    """Register ``tenuo_delegate``. It is offered only when peers are configured and an enforcing
    guard holds this session's authority (``get_guard()``). Returns whether peers are configured."""
    try:
        config = load_sender_config(ctx)
    except Exception as exc:
        logger.error("hermes-tenuo: a2a_delegation is configured but unusable (%s); delegation is off", exc)
        config = None

    def available() -> bool:
        return config is not None and get_guard() is not None

    def handler(args: Dict[str, Any], **_kw: Any) -> str:
        try:
            if not available():
                raise DelegationError("delegation is not configured on this agent")
            guard = get_guard()
            session_id = str(_kw.get("session_id") or _current_session_id())
            task_id = str(_kw.get("task_id") or "")
            session_id = guard.delegation_session(session_id, task_id)
            chain, key = guard.delegation_authority(session_id)
            result = delegate(config=config, chain=chain, key=key, peer=args.get("peer", ""),
                              task=args.get("task", ""), tools=args.get("tools"),
                              ttl_seconds=args.get("ttl_seconds", DEFAULT_TTL))
            guard.record_delegation(session_id, chain, result)
            logger.info("hermes-tenuo: delegated to %s (%s): %s", result["peer"], result["context_id"], result["state"])
            return json.dumps({"ok": True, **result})
        except DelegationError as exc:
            return json.dumps({"ok": False, "error": str(exc)})
        except Exception as exc:  # never crash the agent loop
            logger.error("hermes-tenuo: delegation failed: %s", exc, exc_info=True)
            return json.dumps({"ok": False, "error": f"delegation failed ({type(exc).__name__})"})

    if not hasattr(ctx, "register_tool"):
        return config is not None
    try:
        ctx.register_tool(TOOL_NAME, "tenuo", SCHEMA, handler, check_fn=available, description=DESCRIPTION)
    except TypeError:
        ctx.register_tool(TOOL_NAME, "tenuo", SCHEMA, handler)
    return config is not None


def _current_session_id() -> str:
    try:
        from gateway.session_context import get_session_env
        return str(get_session_env("HERMES_SESSION_ID", "") or "")
    except Exception:
        return ""


__all__ = ["DelegationError", "SenderConfig", "constraint_for", "delegate", "grant_spec",
           "load_sender_config", "register"]
