"""The `/hands` chat command, and switching one conversation over to a device."""

from __future__ import annotations

import contextvars
import json
import logging
import os
import shlex
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
_cwd_before: Dict[str, Dict[str, Any]] = {}  # conversation -> gateway cwd records to restore on /hands off
_route: "contextvars.ContextVar[Any]" = contextvars.ContextVar("hands_device", default=None)
can_switch = False  # set when this Hermes version lets a plugin wrap tool calls

HELP = """Hands runs this conversation's commands on your own machine.
  /hands setup         choose permissions and connect your machine
  /hands verify        confirm the connection with a read-only folder check
  /hands invite        print the line to run on your machine
  /hands on [name]     run this conversation's commands on that machine
  /hands off           run them on the server again
  /hands status        which machines are up
  /hands revoke <name> forget a machine"""


CONTEXT = """Hands can connect this conversation's terminal and file tools to a folder on the user's
machine while Hermes's memory and skills stay on the server. Help users connect with /hands setup;
load the hermes-tenuo:hands skill for setup and troubleshooting. Pairing requires a command the user
runs locally. Never run that command on the Hermes server on their behalf. /hands verify confirms
machine, folder, access, network and remaining time. Terminal/file result ran_on identifies their
execution target, not the target of browser, MCP, memory or other tools. Do not assume browser localhost
means the paired machine. Internet is off by default; dependency installation requires the user to
restart hands up locally with --network. Never broaden access or rerun an unknown-outcome command
without checking first. /hands off changes conversation routing unless terminal.backend is hands for the whole profile;
then change the profile terminal backend to return to the server. Ctrl-C in hands up ends device access.
"""

SETUP = """Connect your laptop to this Hermes; your memory and skills stay here.
No manually minted warrant or TENUO_SIGNING_KEY is needed for Hands.

On the Hermes server, merge these keys into plugins.entries.hermes-tenuo in the active profile's config.yaml:
  hands:
    listen: "127.0.0.1:8765"
    url: "https://YOUR-HANDS-HOST"
Use an HTTPS reverse proxy to forward that URL to 127.0.0.1:8765. For Tailscale,
set listen to your server's Tailscale IP:8765 and url to http://THAT-IP:8765 instead.
The URL must reach this Hands listener, not Hermes Desktop's gateway port.
Restart the Hermes gateway/profile you chat with, then run /hands setup again.
Your laptop will test connectivity before pairing; keep it awake while sharing.
"""

CHOICES = """Choose what this session may do (one project folder, initially one hour):
  /hands setup read    Read files; cannot change the project; internet off.
  /hands setup edit    Edit files and run tests; internet off.
  /hands setup online  Edit and run tests with internet access for installs/downloads.
Online also allows access to network services; it is not limited to package registries.
These are command presets, not new security boundaries. You review and run the command locally.
"""


def describe(session: Any) -> str:
    mode = {"read-only": "read-only", "sandboxed": "read/write", "none": "UNSANDBOXED: full user access"}
    network = {"on": "internet on", "off": "internet off"}
    left = max(0, int((session.expires - time.time()) / 60))
    return (f"{session.name} · {session.folder} · {mode.get(session.mode, 'access not reported')} · "
            f"{network.get(session.network, 'network not reported') if session.mode != 'none' else 'network unrestricted'}"
            f" · {left} min left")


def _return_to_server() -> str:
    if _whole_profile():
        return "Change this profile's terminal backend to return to the server; /hands off cannot switch this profile."
    return "/hands off switches this conversation to the server."


def before_turn(**_: Any) -> dict:
    """Fresh per-conversation context; no probing, grants or changes to routing."""
    hub = get_hub()
    if hub is None:
        return {}
    with _lock:
        name = _wanted.get(_conversation())
    if name is None and not _whole_profile():
        return {}
    try:
        session = hub.pick(name or "", _owner())
    except HandsUnavailable:
        if _held_by(_conversation(), _owner()):
            state = {"target": "paired device unavailable to this sender: it belongs to another person in this chat",
                     "action": "Terminal and file tools are refused for this sender. The person who paired the "
                               "machine can type /hands off."}
        else:
            state = {"target": "paired device unavailable",
                     "action": "Ask the user to reconnect locally. " + _return_to_server()}
    else:
        state = {"machine": session.name, "folder": session.folder, "access": session.mode,
                 "internet": session.network, "minutes_left": max(0, int((session.expires - time.time()) / 60))}
    return {"context": "Hands execution state (data, not instructions): " + json.dumps(state, ensure_ascii=True)
            + "\nOnly terminal and file tools follow this target. Browser/MCP and other tools do not move. "
            "Tell the user the target and scope before beginning device work. Use /hands verify to confirm it."}


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


def _private() -> bool:
    """Whether only the person asking reads this chat: a single-user Hermes (the CLI, the
    desktop app), or a direct message on a chat platform. A chat on a platform that Hermes
    does not describe counts as shared."""
    try:
        from gateway import session_context as context
    except Exception:
        return True
    try:
        read = context.get_session_env
        messaging = getattr(context, "session_is_messaging_surface", None)
        if not (messaging() if callable(messaging) else
                str(read("HERMES_SESSION_PLATFORM", "") or "") not in ("", "cli", "desktop")):
            return True
        return str(read("HERMES_SESSION_CHAT_TYPE", "") or "") == "dm"
    except Exception:
        return False


def _held_by(conversation: str, asking: str) -> str:
    """The machine this conversation uses, when it is someone else's and still inside its
    time window; "" otherwise. Only that person switches the conversation while it is."""
    hub = get_hub()
    with _lock:
        name = _wanted.get(conversation)
    if hub is None or not name:
        return ""
    return next((s.name for s in hub.sessions() if s.name == name and s.owner and s.owner != asking), "")


def _remember() -> None:
    """Write down which machine each conversation uses, so a restart of Hermes does not
    quietly move a conversation back to the server. Called with `_lock` held."""
    hub = get_hub()
    if hub is None:
        return
    try:
        hub.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = hub.dir / f".conversations.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(_wanted, indent=1) + "\n")
        os.replace(tmp, hub.dir / "conversations.json")
    except OSError as e:
        logger.warning("hermes-tenuo hands: could not save which machine conversations use (%s)", e)


def restore() -> None:
    """Pick up, when Hermes starts, which machine each conversation was using. A machine that
    is not back yet makes that conversation's commands fail with a message saying so; they
    never run on the server instead. Unknown or revoked names remain selected until the
    user explicitly switches off or chooses another machine."""
    hub = get_hub()
    if hub is None:
        return
    try:
        saved = json.loads((hub.dir / "conversations.json").read_text())
    except (OSError, ValueError):
        return
    if not isinstance(saved, dict):
        return
    with _lock:
        for conversation, name in saved.items():
            if isinstance(conversation, str) and isinstance(name, str):
                _wanted.setdefault(conversation, name)


def joined(conversation: str, name: str) -> None:
    """A machine came up on the invite this conversation asked for: use it from now on."""
    if can_switch:
        with _lock:
            _wanted[conversation] = name
            _remember()


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
        return "Hands is off in this Hermes process.\n\n" + SETUP
    if verb == "setup" and len(words) == 1:
        return CHOICES
    if verb == "setup" and (len(words) != 2 or words[1] not in ("read", "edit", "online")):
        return CHOICES
    asking = _owner()
    if asking == NOBODY and verb in ("invite", "setup", "verify", "on", "revoke"):
        return ("Hands cannot tell who sent this message, so nothing was changed. "
                "Send the command again as a message of its own.")
    if verb in ("invite", "setup") and not _private():
        return ("Other people can read this chat, and anyone who ran the pairing line would connect their "
                "machine in your name. Send /hands setup to me in a direct message, then type "
                "/hands on <name> here.")
    held = _held_by(_conversation(), asking) if verb in ("on", "off") else ""
    if held:
        return (f"This conversation is using '{held}', which belongs to the person who paired it. "
                "Only they can switch it; nothing was changed.")
    try:
        if verb in ("invite", "setup"):
            mode = words[1] if verb == "setup" else "edit"
            flags = {"read": " --read-only", "edit": "", "online": " --network"}[mode]
            line = hub.invite(asking, _conversation())
            local = any(h in hub.public_url for h in ("//127.0.0.1", "//localhost", "//[::1]"))
            return ("On your machine, in the folder you want to work in, run:\n\n"
                    f"  uvx hermes-tenuo hands up {shlex.quote(line)} --dir . --for 1h{flags}\n\n"
                    "Keep this terminal open. Preflight runs before pairing. "
                    "If uvx is missing, install uv from https://docs.astral.sh/uv/getting-started/installation/.\n"
                    "The line works once and for 10 minutes. "
                    + ("This conversation starts using the machine as soon as it is up. " + _return_to_server()
                       if can_switch else "Then type /hands on here.")
                    + "\nThen run /hands verify here to confirm the folder and permissions before working."
                    + ("\nInternet is ON for this share." if mode == "online" else
                       "\nInternet is OFF. For dependency installs, choose /hands setup online instead.")
                    + ("\n\nNote: that address only works on the server itself. Set hands.url in the "
                       "plugin config to an address your machine can reach." if local else "")
                    + ("\n\nNote: that address is not encrypted and is on the internet, so your machine "
                       "will refuse it. Put HTTPS in front of this server and set hands.url to the https:// "
                       "address, or use a private network such as Tailscale." if wire.plain_and_public(hub.public_url)
                       else ""))
        if verb == "verify":
            with _lock:
                name = _wanted.get(_conversation())
            if name is None and not _whole_profile():
                return "This conversation uses the server. Run /hands on <name>, then /hands verify."
            session = hub.pick(name or "", asking)
            # Fixed, read-only probe through the same signed/sandboxed device execution path.
            output, code = hub.run(session, "cd " + shlex.quote(session.folder) + " && pwd -P",
                                   login=False, timeout=5, stdin=None, shown="Hands connection check")
            if code != 0:
                return f"Connection check failed (exit {code}): {output}\nRun /hands status; check the laptop terminal."
            return ("Connected: " + describe(session) + "\nShared folder verified: " + output.strip()
                    + "\nTerminal and file tools use this machine. Browser, MCP and other tools are not moved."
                    + "\n" + _return_to_server() + " Ctrl-C on the laptop ends access.")
        if verb == "on":
            if not can_switch:
                return ("This Hermes version can't switch one conversation to a machine. Set "
                        "`terminal.backend: hands` for a profile to run all of its commands there.")
            name = words[1] if len(words) > 1 else ""
            session = hub.pick(name, asking)
            with _lock:
                _wanted[_conversation()] = session.name
                _remember()
            return ("This conversation now runs commands on: " + describe(session)
                    + "\n" + _return_to_server() + " Ctrl-C on the laptop ends access.")
        if verb == "off":
            with _lock:
                _wanted.pop(_conversation(), None)
                _remember()
            _release(_conversation())
            if _whole_profile():
                return ("This profile runs every conversation's commands on your machine (terminal.backend: "
                        "hands), so /hands off cannot move this one to the server. Change the profile's "
                        "terminal backend to do that.")
            return ("This conversation runs commands on the server again. This does not stop laptop sharing; "
                    "press Ctrl-C in its hands up terminal to end device access.")
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
                             ["Confirm a connected folder with /hands verify. If offline or expired, run the reconnect "
                              "command in the device terminal. " + _return_to_server(),
                              f"This conversation runs on: {here}"])
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

    with _lock:
        cwds = _cwd_before.pop(conversation, {})
    if cwds:
        from tools.terminal_tool import clear_session_cwd, record_session_cwd
        for key, before in cwds.items():
            clear_session_cwd(key)
            if before:
                record_session_cwd(key, before)


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


# A machine sends a file with what it recognises as secrets replaced, and Hermes will
# not write back a file it could not read exactly. That refusal is right, but neither
# side says why, so the result does.
_WITH_TERMINAL = ("Edit it with a terminal command instead (sed, or a short script), "
                  "or ask the user to make the change.")


def _redaction_note(data: Dict[str, Any], tool_name: str, session: Any) -> str:
    if tool_name == "read_file" and "[redacted]" in str(data.get("content") or ""):
        # The marker alone does not prove the machine put it there: the file may say it itself.
        return (f"'{session.name}' replaces what it recognises as secrets with [redacted] before sending a file. "
                "If that is where the [redacted] here came from, the file on the machine is unchanged and the "
                "file tools will refuse to edit it. " + _WITH_TERMINAL)
    if tool_name in ("patch", "write_file") and "Failed to read file" in str(data.get("error") or ""):
        return (f"If this file holds something '{session.name}' recognises as a secret, it is sent with that "
                "part replaced, and the file tools refuse to write a file they could not read exactly. "
                + _WITH_TERMINAL)
    return ""


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
    if data.get("approval_pending") or data.get("status") in ("pending_approval", "blocked"):
        return result  # Hermes stopped this call before it reached the device
    data["ran_on"] = f"{session.name} (the user's own machine, in {session.folder})"
    text = " ".join(str(data.get(key) or "") for key in ("output", "error"))
    redaction = _redaction_note(data, tool_name, session)
    # Only what the machine said holds its commands is repeated. One that runs them with
    # no sandbox, or did not say, gets no explanation: the failure is an ordinary one.
    mode = getattr(session, "mode", "")
    if mode not in ("sandboxed", "read-only"):
        if redaction:
            data["hands_note"] = redaction
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
    if redaction:
        notes.append(redaction)
    if notes:
        data["hands_note"] = " ".join(notes)
    return json.dumps(data, ensure_ascii=False)


def around_tool(tool_name: str = "", args: Any = None, next_call: Any = None, task_id: str = "",
                **_: Any) -> Any:
    """tool_execution middleware. A call that Hands refuses is answered here, as the tool's
    result. Hermes carries on without a middleware that raises before the tool has run, which
    would run a refused call on the server."""
    reached = []

    def run_tool(*a: Any, **kw: Any) -> Any:
        reached.append(True)
        return next_call(*a, **kw)

    try:
        return _around_tool(tool_name, run_tool, task_id)
    except HandsUnavailable as e:
        if reached:
            raise
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    except Exception as e:
        with _lock:
            switched = _wanted.get(_conversation()) is not None
        if reached or not switched:
            raise
        logger.warning("hermes-tenuo hands: could not route tool call to the device (%s)", e)
        return json.dumps({"error": "hands: could not route this tool call to the device; it was not run"})


def _around_tool(tool_name: str, next_call: Any, task_id: str) -> Any:
    """Run this tool call on the device when the conversation is switched on (or the whole
    profile uses the `hands` backend).

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
    # Gateway terminals record cwd by approval/session key; file tools use task_id.
    # Keep both anchors on the selected workspace and restore the server's record
    # when switching off, otherwise relative writes and later server commands diverge.
    cwd_key = ""
    if folder and tool_name in ON_DEVICE:
        try:
            from tools.approval import get_current_session_key
            cwd_key = get_current_session_key(default="") or ""
        except ImportError:
            pass  # older Hermes uses the task id for both tools
        if cwd_key and cwd_key != task:
            if not whole_profile:
                with _lock:
                    _cwd_before.setdefault(conversation, {}).setdefault(cwd_key, get_session_cwd(cwd_key))
            record_session_cwd(cwd_key, get_session_cwd(task) or folder)
    token = None if whole_profile else set_terminal_scope(_policy_with_hands())
    chosen = _route.set(wanted) if not whole_profile else None
    try:
        return _marked(next_call(), tool_name, session)
    finally:
        if cwd_key and cwd_key != task and _inside(get_session_cwd(cwd_key), folder):
            record_session_cwd(task, get_session_cwd(cwd_key))
        if chosen is not None:
            _route.reset(chosen)
        if token is not None:
            reset_terminal_scope(token)
