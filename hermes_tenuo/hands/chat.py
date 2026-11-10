"""The `/hands` chat command, and switching one conversation over to a device."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional

from hermes_tenuo.hands.hub import HandsUnavailable, get_hub

logger = logging.getLogger("hermes_tenuo.hands")

_lock = threading.Lock()
_wanted: Dict[str, str] = {}   # conversation -> device name ("" = the only one up), set by /hands on
_applied: Dict[str, str] = {}  # Hermes task id -> conversation it was switched for
_devices: Dict[str, str] = {}  # Hermes task id -> device name

HELP = """Hands runs this conversation's commands on your own machine.
  /hands invite        print the line to run on your machine
  /hands on [name]     run this conversation's commands on that machine
  /hands off           run them on the server again
  /hands status        which machines are up
  /hands revoke <name> forget a machine"""


def _conversation() -> str:
    """The conversation the current message belongs to; "" in a single-session CLI."""
    try:
        from gateway.session_context import get_session_env
        return get_session_env("HERMES_SESSION_KEY", "") or ""
    except Exception:
        return ""


def device_for(task_id: str) -> str:
    with _lock:
        return _devices.get(task_id, "")


def command(raw_args: str = "") -> str:
    hub = get_hub()
    words = (raw_args or "").split()
    verb = words[0].lower() if words else "status"
    if verb in ("help", "-h", "--help"):
        return HELP
    if hub is None:
        return ("Hands is off in this Hermes process. Add `hands: {listen: \"0.0.0.0:8765\", "
                "url: \"http://<this-server>:8765\"}` under plugins.entries.hermes-tenuo and restart.")
    try:
        if verb == "invite":
            line = hub.invite()
            return ("On your machine, in the folder you want to work in, run:\n\n"
                    f"  hermes-tenuo hands up '{line}' --dir . --for 4h\n\n"
                    "The line works once and for 10 minutes. Then type /hands on here.")
        if verb == "on":
            name = words[1] if len(words) > 1 else ""
            session = hub.pick(name)
            with _lock:
                _wanted[_conversation()] = session.name
            left = max(0, int((session.expires - time.time()) / 60))
            return (f"This conversation now runs commands on '{session.name}' in {session.folder} "
                    f"({left} min left). /hands off switches back to the server.")
        if verb == "off":
            with _lock:
                _wanted.pop(_conversation(), None)
            _release(_conversation())
            return "This conversation runs commands on the server again."
        if verb == "revoke":
            if len(words) < 2:
                return "Which machine? /hands revoke <name>"
            return (f"'{words[1]}' is forgotten; it needs a new invite to come back." if hub.revoke(words[1])
                    else f"No machine called '{words[1]}'.")
        if verb == "status":
            rows = [f"  {s.name}: {'up' if s.online else 'not answering'}, {s.folder}, "
                    f"{max(0, int((s.expires - time.time()) / 60))} min left" for s in hub.sessions()]
            here = _wanted.get(_conversation())
            return "\n".join(["Machines:"] + (rows or ["  none are up (/hands invite to add one)"]) +
                             [f"This conversation runs on: {here if here is not None else 'the server'}"])
    except HandsUnavailable as e:
        return str(e)
    return HELP


def _release(conversation: str) -> None:
    try:
        from tools.terminal_tool import clear_task_env_overrides
    except Exception:
        return
    with _lock:
        tasks = [t for t, c in _applied.items() if c == conversation]
        for task in tasks:
            _applied.pop(task, None)
            _devices.pop(task, None)
    for task in tasks:
        clear_task_env_overrides(task)


def before_tool(tool_name: str = "", task_id: str = "", **_: Any) -> Optional[dict]:
    """pre_tool_call: point this conversation's task at the device before its first command."""
    conversation = _conversation()
    with _lock:
        wanted = _wanted.get(conversation)
        task = str(task_id or "default")
        if wanted is None or _applied.get(task) == conversation:
            return None
        _applied[task] = conversation
        _devices[task] = wanted
    try:
        from hermes_tenuo.hands.backend import NAME
        from tools.terminal_tool import register_task_env_overrides
        register_task_env_overrides(task, {"env_type": NAME})
    except Exception as e:
        logger.warning("hermes-tenuo hands: could not switch this conversation to the device (%s)", e)
        with _lock:
            _applied.pop(task, None)
            _devices.pop(task, None)
        return {"action": "block", "message": "hands: this Hermes version can't switch a conversation to a device. "
                                              "Use /hands off, or set terminal.backend: hands for a profile."}
    return None
