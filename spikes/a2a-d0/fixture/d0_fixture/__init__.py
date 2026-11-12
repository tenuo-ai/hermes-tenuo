"""Synthetic devices for the A2A delegation lab. Each call that runs appends one line to d0_effects.jsonl."""

import json
import os
import time
from pathlib import Path


def _record(tool, args):
    from gateway.session_context import get_session_env

    row = {"ts": time.time(), "tool": tool, "args": args,
           "platform": get_session_env("HERMES_SESSION_PLATFORM", ""),
           "user": get_session_env("HERMES_SESSION_USER_ID", ""),
           "chat": get_session_env("HERMES_SESSION_CHAT_ID", "")}
    path = Path(os.environ.get("HERMES_HOME", ".")) / "d0_effects.jsonl"
    with path.open("a") as fh:
        fh.write(json.dumps(row) + "\n")


def _schema(name, description, props, required):
    return {"name": name, "description": description,
            "parameters": {"type": "object", "properties": props, "required": required}}


ENTITY = {"entity_id": {"type": "string", "description": "e.g. light.guest_room"}}


def register(ctx):
    def light_get(args, **_kw):
        _record("light_get", args)
        return json.dumps({"entity_id": args.get("entity_id"), "state": "off"})

    def light_set(args, **_kw):
        _record("light_set", args)
        return json.dumps({"entity_id": args.get("entity_id"), "state": args.get("state", "on")})

    def door_unlock(args, **_kw):
        _record("door_unlock", args)
        return json.dumps({"door": args.get("door"), "state": "unlocked"})

    ctx.register_tool("light_get", "d0_home", _schema("light_get", "Read a light.", ENTITY, ["entity_id"]), light_get)
    ctx.register_tool("light_set", "d0_home", _schema(
        "light_set", "Turn a light on or off.",
        {**ENTITY, "state": {"type": "string", "enum": ["on", "off"]}}, ["entity_id"]), light_set)
    ctx.register_tool("door_unlock", "d0_home", _schema(
        "door_unlock", "Unlock a door.", {"door": {"type": "string"}}, ["door"]), door_unlock)
