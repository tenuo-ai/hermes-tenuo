"""The `/hands` chat command, and switching one conversation over to a device."""

from __future__ import annotations

import contextvars
import json
import logging
import threading
import time
from typing import Any, Dict

from hermes_tenuo.hands import wire
from hermes_tenuo.hands.hub import HandsUnavailable, get_hub

logger = logging.getLogger("hermes_tenuo.hands")

_lock = threading.Lock()
# One Hermes process can serve several profiles, and neither conversation keys nor task ids
# are unique across them. Everything below is keyed by `_scoped(...)`, which adds the profile.
_wanted: Dict[str, str] = {}   # conversation -> device name ("" = the only one up), set by /hands on
_applied: Dict[str, tuple] = {}  # task -> (conversation it was switched for, the task id as Hermes knows it)
_devices: Dict[str, str] = {}  # task -> device name
_saved: Dict[str, Dict[str, Any]] = {}  # task -> the overrides it had before /hands on
_route: "contextvars.ContextVar[Any]" = contextvars.ContextVar("hands_device", default=None)
can_switch = False  # set when this Hermes version lets a plugin wrap tool calls

HELP = """Hands runs this conversation's commands on your own machine.
  /hands invite        print the line to run on your machine
  /hands on [name]     run this conversation's commands on that machine
  /hands off           run them on the server again
  /hands status        which machines are up
  /hands revoke <name> forget a machine"""


def _scoped(key: str) -> str:
    """`key` with the profile this call was routed to, where Hermes serves several."""
    try:
        from tools.terminal_tool import _qualify_task_key
        return _qualify_task_key(key)
    except Exception:
        return key


def _conversation() -> str:
    """The conversation the current message belongs to; the same for a whole single-session CLI."""
    try:
        from gateway.session_context import get_session_env
        return _scoped(get_session_env("HERMES_SESSION_KEY", "") or "")
    except Exception:
        return _scoped("")


NOBODY = "?"  # a message on a chat platform with no one sender; never the owner of a machine


def _owner() -> str:
    """Who is asking, where Hermes knows: the chat platform and the person who sent this
    message. Hermes names the sender of a message apart from the user a conversation is
    routed by, which is empty in a shared chat; a Hermes from before it did has only the
    latter. Empty on a single-user Hermes (the CLI, the desktop app), where every machine
    is the user's. NOBODY for a message on a chat platform that has no one sender."""
    try:
        from gateway import session_context as context
    except Exception:
        return ""
    try:
        import inspect
        read = context.get_session_env
        platform = str(read("HERMES_SESSION_PLATFORM", "") or "")
        names_sender = "actor_id" in inspect.signature(context.set_session_vars).parameters
        person = str(read("HERMES_SESSION_ACTOR_ID" if names_sender else "HERMES_SESSION_USER_ID", "") or "")
        if person:
            return f"{platform}:{person}"
        messaging = getattr(context, "session_is_messaging_surface", None)
        return NOBODY if (messaging() if callable(messaging) else platform not in ("", "cli", "desktop")) else ""
    except Exception:
        return NOBODY


def joined(conversation: str, name: str) -> None:
    """A machine came up on the invite this conversation asked for: use it from now on."""
    if can_switch:
        with _lock:
            _wanted[conversation] = name


def _whole_profile() -> bool:
    """True if this profile's terminal backend is Hands itself, for every conversation."""
    try:
        from hermes_tenuo.hands.backend import NAME
        from tools.terminal_scope import terminal_env
        return terminal_env("TERMINAL_ENV", "local") == NAME
    except Exception:
        return False


def device_for(task_id: str) -> str:
    with _lock:
        return _devices.get(task_id) or _devices.get(_scoped(task_id), "")


def current_device() -> Any:
    """The device the tool call in progress was routed to, or None outside one."""
    return _route.get()


def command(raw_args: str = "") -> str:
    hub = get_hub()
    words = (raw_args or "").split()
    verb = words[0].lower() if words else "status"
    if verb in ("help", "-h", "--help"):
        return HELP
    if hub is None:
        return ("Hands is off in this Hermes process. Add `hands: {listen: \"0.0.0.0:8765\", "
                "url: \"http://<this-server>:8765\"}` under plugins.entries.hermes-tenuo and restart.")
    asking = _owner()
    if asking == NOBODY and verb in ("invite", "on", "revoke"):
        return ("Hands cannot tell who sent this message, so nothing was changed. "
                "Send the command again as a message of its own.")
    try:
        if verb == "invite":
            line = hub.invite(asking, _conversation())
            local = any(h in hub.public_url for h in ("//127.0.0.1", "//localhost", "//[::1]"))
            return ("On your machine, in the folder you want to work in, run:\n\n"
                    f"  hermes-tenuo hands up '{line}' --dir . --for 4h\n\n"
                    "The line works once and for 10 minutes. "
                    + ("This conversation starts using the machine as soon as it is up; /hands off switches back."
                       if can_switch else "Then type /hands on here.")
                    + ("\n\nNote: that address only works on the server itself. Set hands.url in the "
                       "plugin config to an address your machine can reach." if local else "")
                    + ("\n\nNote: that address is not encrypted and is on the internet, so your machine "
                       "will refuse it. Put HTTPS in front of this server and set hands.url to the https:// "
                       "address, or use a private network such as Tailscale." if wire.plain_and_public(hub.public_url)
                       else ""))
        if verb == "on":
            if not can_switch:
                return ("This Hermes version can't switch one conversation to a machine. Set "
                        "`terminal.backend: hands` for a profile to run all of its commands there.")
            name = words[1] if len(words) > 1 else ""
            session = hub.pick(name, asking)
            with _lock:
                _wanted[_conversation()] = session.name
            left = max(0, int((session.expires - time.time()) / 60))
            return (f"This conversation now runs commands on '{session.name}' in {session.folder} "
                    f"({left} min left). /hands off switches back to the server.")
        if verb == "off":
            with _lock:
                _wanted.pop(_conversation(), None)
            _release(_conversation())
            if _whole_profile():
                return ("This profile runs every conversation's commands on your machine (terminal.backend: "
                        "hands), so /hands off cannot move this one to the server. Change the profile's "
                        "terminal backend to do that.")
            return "This conversation runs commands on the server again."
        if verb == "revoke":
            if len(words) < 2:
                return "Which machine? /hands revoke <name>"
            return (f"'{words[1]}' is forgotten; it needs a new invite to come back."
                    if hub.revoke(words[1], asking) else f"No machine of yours is called '{words[1]}'.")
        if verb == "status":
            how = {"read-only": ", read-only", "none": ", no sandbox"}
            net = {"on": ", internet on", "off": ", no internet"}
            rows = [f"  {s.name}: {'up' if s.online else 'not answering'}, {s.folder}{how.get(s.mode, '')}"
                    f"{net.get(s.network, '') if s.mode != 'none' else ''}, "
                    f"{max(0, int((s.expires - time.time()) / 60))} min left" for s in hub.sessions(asking)]
            here = _wanted.get(_conversation())
            if here is None:
                here = "your machine (this profile's terminal backend is hands)" if _whole_profile() else "the server"
            return "\n".join(["Machines:"] + (rows or ["  none are up (/hands invite to add one)"]) +
                             [f"This conversation runs on: {here}"])
    except HandsUnavailable as e:
        return str(e)
    return HELP


def _release(conversation: str) -> None:
    try:
        from tools.terminal_tool import clear_task_env_overrides
    except Exception:
        return
    with _lock:
        mine = [(key, entry[1]) for key, entry in _applied.items() if entry[0] == conversation]
        for key, _ in mine:
            _applied.pop(key, None)
            _devices.pop(key, None)
    for key, task in mine:
        _drop_shell(task)  # while the task still has its own slot, so the server's shell is untouched
        with _lock:
            before = _saved.pop(key, None)
        clear_task_env_overrides(task)  # also forgets the device folder as this task's directory
        if before:
            try:
                from tools.terminal_tool import register_task_env_overrides
                register_task_env_overrides(task, before)  # what the task had before /hands on
            except Exception as e:
                logger.warning("hermes-tenuo hands: could not restore the task's settings (%s)", e)


def _own_overrides(task: str) -> Dict[str, Any]:
    """The overrides Hermes holds for this task itself (registering replaces them all)."""
    try:
        from tools import terminal_tool
        return dict(terminal_tool._task_env_overrides.get(terminal_tool._qualify_task_key(task)) or {})
    except Exception:
        return {}


def _other_shell(task: str) -> bool:
    """True if this task already has a shell of its own that is not on a device. Hermes
    would keep using it, so the call must not go ahead as if it ran on the device."""
    try:
        from hermes_tenuo.hands.backend import HandsEnvironment
        from tools import terminal_tool
        cached = terminal_tool._active_environments
        env = cached.get(terminal_tool._qualify_task_key(task)) or cached.get(task)
        return env is not None and not isinstance(env, HandsEnvironment)
    except Exception:
        return False


def _drop_shell(task: str) -> None:
    """Forget the shell a task had on a device, so its next command starts fresh where the
    conversation now points: another machine, or the server."""
    try:
        from hermes_tenuo.hands.backend import HandsEnvironment
        from tools import terminal_tool
        from tools.terminal_tool_lifecycle import cleanup_vm
        # Hermes removes exactly the key it is given, and the key it caches under carries
        # the routed profile. Try the ways it may have keyed this task, and only ever
        # remove a shell that is on a device.
        keys = []
        for find in (lambda: terminal_tool._resolve_container_task_id(task), lambda: _scoped(task), lambda: task):
            try:
                key = find()
            except Exception:
                continue
            if key and key not in keys:
                keys.append(key)
        for key in keys:
            if isinstance(terminal_tool._active_environments.get(key), HandsEnvironment):
                cleanup_vm(key)
    except Exception as e:
        logger.debug("hermes-tenuo hands: could not drop the device shell for %s (%s)", task, e)


def _policy_with_hands() -> Dict[str, str]:
    """This context's complete terminal policy, with the backend set to the device."""
    import os

    from hermes_tenuo.hands.backend import NAME
    from tools.terminal_scope import get_terminal_scope
    current = get_terminal_scope()
    policy = dict(current) if current is not None else {
        k: v for k, v in os.environ.items() if k.startswith("TERMINAL_")}
    policy["TERMINAL_ENV"] = NAME
    policy.pop("TERMINAL_CWD", None)  # a server path means nothing on the device
    return policy


def _inside(path: Any, folder: str) -> bool:
    return isinstance(path, str) and (path == folder or path.startswith(folder.rstrip("/") + "/"))


# The tools whose work happens on the device once a conversation is switched. Others
# (search, memory, delegation) still run on the server and are not marked. Neither is the
# process tool: it reports on a process started earlier, which may have been started on the
# server or on another machine, and naming the current one would be a guess.
ON_DEVICE = {"terminal", "read_file", "write_file", "patch", "search_files"}


# How a sandbox's refusal reads in a command's output: macOS denies the call, Linux shows
# everything outside the folder as a read-only file system.
REFUSALS = ("Operation not permitted", "Permission denied", "Read-only file system")
# How having no internet reads: a name that cannot be looked up, or no route out.
NO_NETWORK = ("Could not resolve host", "Temporary failure in name resolution", "Temporary failure resolving",
              "Name or service not known", "nodename nor servname provided", "failed to lookup address information",
              "Network is unreachable", "network is unreachable", "ENOTFOUND", "EAI_AGAIN")


def _marked(result: Any, tool_name: str, session: Any) -> Any:
    """The tool's result, saying which machine it ran on. A refusal by that machine's
    sandbox also says what the machine shares, since the bare system message does not."""
    if session is None or tool_name not in ON_DEVICE or not isinstance(result, str):
        return result
    try:
        data = json.loads(result)
    except ValueError:
        return result
    if not isinstance(data, dict) or "ran_on" in data:
        return result
    data["ran_on"] = f"{session.name} (the user's own machine, in {session.folder})"
    text = " ".join(str(data.get(key) or "") for key in ("output", "error"))
    # Only what the machine said holds its commands is repeated. One that runs them with
    # no sandbox, or did not say, gets no explanation: the failure is an ordinary one.
    mode = getattr(session, "mode", "")
    if mode not in ("sandboxed", "read-only"):
        return json.dumps(data, ensure_ascii=False)
    offline = getattr(session, "network", "") == "off"
    if offline:  # said with every result: a failed install does not always say why
        data["ran_on"] = f"{session.name} (the user's own machine, in {session.folder}, no internet)"
    notes = []
    refused = any(refusal in text for refusal in REFUSALS)
    if refused:
        shares = (f"shares {session.folder} to read, not to change: commands there cannot change it or anything else"
                  if mode == "read-only" else
                  f"shares only {session.folder}: commands there cannot change anything outside it")
        notes.append(f"'{session.name}' {shares}, and the user's keys, credentials and browser data cannot be read.")
    # Where commands have no internet, an install or download fails on a name that cannot be
    # looked up, or (macOS, a numeric address) as a refusal. Say what it is and who can change it.
    if offline:
        if any(sign in text for sign in NO_NETWORK):
            notes.append(f"Commands on '{session.name}' have no internet access, so installs and downloads fail. "
                         "The user can allow it by starting Hands on that machine with --network.")
        elif refused:
            notes.append("Commands there also have no internet access unless the user starts Hands with --network.")
    if notes:
        data["hands_note"] = " ".join(notes)
    return json.dumps(data, ensure_ascii=False)


def around_tool(tool_name: str = "", args: Any = None, next_call: Any = None, task_id: str = "",
                **_: Any) -> Any:
    """tool_execution middleware: run this tool call on the device when the conversation is
    switched on (or the whole profile uses the `hands` backend).

    Hermes picks the terminal backend from a per-context policy, so the switch wraps this
    call only. The task also gets its own environment slot, so the server's shell for the
    same conversation is left untouched.

    File tools resolve a relative path against the session's recorded directory before any
    command has run, so that record is pointed at the device's folder first. Otherwise a
    session whose first call is `write_file` would aim at a server path.
    """
    conversation = _conversation()
    task = str(task_id or "default")
    with _lock:
        wanted = _wanted.get(conversation)
    try:
        from hermes_tenuo.hands.backend import NAME
        from tools.terminal_scope import (
            TerminalPolicyRefusal, get_terminal_scope, reset_terminal_scope, set_terminal_scope, terminal_env)
        from tools.terminal_tool import get_session_cwd, record_session_cwd, register_task_env_overrides
        if isinstance(get_terminal_scope(), TerminalPolicyRefusal):
            return next_call()  # Hermes is refusing terminal use for this profile; leave that alone
        whole_profile = wanted is None and terminal_env("TERMINAL_ENV", "local") == NAME
    except Exception as e:
        if wanted is not None:
            logger.warning("hermes-tenuo hands: could not route tool call to the device (%s)", e)
            raise HandsUnavailable("hands: could not route this tool call to the device; it was not run") from e
        logger.debug("hermes-tenuo hands: tool call left on the server (%s)", e)
        return next_call()
    if wanted is None and not whole_profile:
        return next_call()

    hub = get_hub()
    try:
        session = hub.pick(wanted or "", None if wanted else _owner()) if hub is not None else None
    except HandsUnavailable:
        session = None  # the backend reports the missing device when the call runs
    folder = session.folder if session is not None else ""
    if session is not None and session.owner and session.owner != _owner() and tool_name in ON_DEVICE:
        # The conversation is switched to a machine, but this message is from someone else
        # (a shared chat). It is not run there, and never falls back to the server either.
        # A tool that only ever runs on the server goes on as usual; anything else that
        # reaches for the machine is refused where the command would leave the server.
        raise HandsUnavailable(f"hands: '{session.name}' belongs to the person who paired it; this call was not "
                               "run. They can type /hands off to return this conversation to the server")
    if not whole_profile:
        key = _scoped(task)
        with _lock:
            entry = _applied.get(key)
            fresh = entry is None or entry[0] != conversation
            switched = not fresh and _devices.get(key) != wanted
            _applied[key] = (conversation, task)
            _devices[key] = wanted
        if fresh:
            before = _own_overrides(task)
            if before.get("env_type") == NAME:
                before.pop("env_type")  # never save our own switch as the thing to go back to
            with _lock:
                _saved[key] = before
            register_task_env_overrides(task, {**before, "env_type": NAME})
        elif switched:
            _drop_shell(task)  # /hands on <another machine>: never keep running on the first one
        if _other_shell(task):
            raise HandsUnavailable("hands: this conversation already has its own sandbox on the server, so its "
                                   "commands cannot move to your machine. Start a new conversation and type "
                                   "/hands on there; this call was not run")
    if folder and not _inside(get_session_cwd(task), folder):
        record_session_cwd(task, folder)
    if whole_profile:
        return _marked(next_call(), tool_name, session)
    token = set_terminal_scope(_policy_with_hands())
    chosen = _route.set(wanted)
    try:
        return _marked(next_call(), tool_name, session)
    finally:
        _route.reset(chosen)
        reset_terminal_scope(token)
