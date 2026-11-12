"""Protected A2A ingress as a standalone plugin, for testing against an existing Hermes instance.

Leaves the installed hermes_tenuo untouched. Inbound A2A turns run only on the grant verified at
ingress, enforced with this agent's own key over the full chain; every other turn returns None."""

import base64
import json
import logging
import os
import time
from pathlib import Path

from . import a2a_ingress as ai

HERE = Path(__file__).parent
logger = logging.getLogger("tenuo_a2a_d0")


def _audit(row):
    with (HERE / "audit.jsonl").open("a") as fh:
        fh.write(json.dumps(row, default=str) + "\n")


def _own_key():
    from tenuo import SigningKey

    path = HERE / "a2a.key"
    if path.exists():
        return SigningKey.from_bytes(base64.b64decode(path.read_text().strip()))
    key = SigningKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(key.secret_key_bytes()).decode())
    return key


def register(ctx):
    from tenuo import PublicKey
    from tenuo._enforcement import enforce_tool_call

    cfg = json.loads((HERE / "config.json").read_text())
    key = _own_key()
    ingress = ai.A2AIngress(
        own_key=key, peers=dict(cfg["peers"]),
        trusted_roots=[PublicKey.from_bytes(base64.b64decode(r)) for r in cfg["trusted_roots"]],
        audit=_audit)
    (HERE / "a2a.pub").write_text(ai.public_key_b64(key))
    ctx.register_hook("pre_gateway_dispatch", ingress.pre_gateway_dispatch)

    def pre_tool_call(tool_name="", args=None, **_kw):
        turn = ingress.current_turn()
        if turn is None:
            return None  # not an inbound A2A turn: untouched
        grant = ingress.grant_for(*turn)
        reason = None
        if grant is None:
            reason = "tenuo: this A2A task carries no verified grant; tool call blocked"
        else:
            try:
                result = enforce_tool_call(tool_name, args or {}, grant.warrant.bind(key),
                                           trusted_roots=list(ingress.trusted_roots),
                                           warrant_chain=list(grant.chain))
                if not result.allowed:
                    reason = f"tenuo: {result.denial_reason or 'not authorized'}"
            except Exception as exc:  # never allow on an error
                reason = f"tenuo: authorization error: {exc}"
        _audit({"event": "tool", "ts": time.time(), "peer": turn[0], "context": turn[1],
                "tool": tool_name, "args": args, "decision": "DENY" if reason else "ALLOW",
                "reason": reason or ""})
        return {"action": "block", "message": reason} if reason else None

    ctx.register_hook("pre_tool_call", pre_tool_call)
    logger.info("tenuo-a2a-d0: protected A2A ingress on; key %s", ai.public_key_b64(key))
