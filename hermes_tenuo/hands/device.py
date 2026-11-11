"""The device side of Hands: `hermes-tenuo hands up` on the machine with your files.

It dials out to the Hermes server, hands over a warrant for one folder and a time
window, then runs the commands the server sends. Every command is checked here, against
the warrant this device signed, before it runs in a sandbox limited to that folder.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import select
import shlex
import shutil
import signal
import socket
import stat
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from hermes_tenuo.hands import sandbox, wire

MAX_OUTPUT = 8 * 1024 * 1024

# Commands get a useful shell environment, but never inherit credentials exported by
# the person who started Hands. Additions to this list are an expansion of authority:
# unlike files, environment variables cannot be hidden by the OS sandbox.
SAFE_ENV = {
    "COLORTERM", "FORCE_COLOR", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "LOGNAME", "NO_COLOR", "PATH", "SHELL", "TERM", "USER", "__CF_USER_TEXT_ENCODING",
}

# Commands run with a stand-in home folder, so tools that keep their toolchains under the
# real one are told where those are. Locations only, read as any other file: no credentials.
# The variable is passed on if the person set it, else pointed at the usual folder if it exists.
TOOL_HOMES = {
    "RUSTUP_HOME": ".rustup", "PYENV_ROOT": ".pyenv", "NVM_DIR": ".nvm", "RBENV_ROOT": ".rbenv",
    "ASDF_DATA_DIR": ".asdf", "VOLTA_HOME": ".volta", "SDKMAN_DIR": ".sdkman",
}
TOOL_PATHS = ("JAVA_HOME", "ANDROID_HOME", "GOROOT")  # passed on only if set

# Commands cannot read the home folder. These folders in it stay readable when they exist,
# because programs and interpreters live there; so does every folder on PATH. Places that
# hold programs, not secrets: the protected paths are still refused inside them.
TOOL_FOLDERS = (".local/share/uv", ".local/share/mise", ".local/share/pnpm", ".local/share/pipx", ".local/pipx",
                "Library/Application Support/pipx", "Library/pnpm", ".bun", ".deno",
                "miniconda3", "anaconda3", "miniforge3", "mambaforge")

PROFILE = ".hands_profile"  # in the stand-in home; keeps this device's settings in login shells too

# Runs inside a sandbox and starts the commands, so they share it: a later command can stop
# a server an earlier one started, and nothing can signal a process outside. Standard
# library only; it must start with no site packages. When the device closes it, it stops
# everything that runs in the sandbox, including what detached itself or ignores a polite
# request to stop.
RUNNER = r"""
import json, os, select, signal, subprocess, sys, threading, time
outside = os.getppid()
groups = []
inbox, buf, closed = [], b"", False
wake_r, wake_w = os.pipe()
os.set_blocking(wake_w, False)
signal.signal(signal.SIGCHLD, lambda *a: None)
signal.set_wakeup_fd(wake_w)  # a finished command wakes the wait below at once
def stop(group, sig):
    try:
        os.killpg(group, sig)
        return True
    except OSError:
        return False
def pump(wait):
    # Read what the device has sent, waiting at most `wait` seconds.
    global buf, closed
    try:
        ready = select.select([wake_r] if closed else [0, wake_r], [], [], wait)[0]
    except InterruptedError:
        return
    if wake_r in ready:
        try:
            os.read(wake_r, 4096)
        except OSError:
            pass
    if 0 in ready:
        chunk = os.read(0, 65536)
        if not chunk:
            closed = True
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                inbox.append(json.loads(line))
def feed(pipe, text):
    try:
        pipe.write(text.encode())
        pipe.close()
    except OSError:
        pass
def confined():
    # True only when this process provably cannot touch anything outside the sandbox.
    try:
        os.kill(outside, 0)
        return False  # it can signal the device, so it is not confined
    except OSError:
        pass
    probe = "/private/tmp/.hands-probe-%d" % os.getpid()
    try:
        os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        os.unlink(probe)
        return False
    except PermissionError:
        return True
    except OSError:
        return False
def keep_to_own_sockets():
    # Required when sharing the host network: never announce readiness until abstract
    # sockets are scoped. Namespace-isolated commands need no Landlock support.
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    create, restrict = ctypes.c_long(444), ctypes.c_long(446)
    if libc.syscall(create, None, ctypes.c_size_t(0), ctypes.c_uint32(1)) < 6:
        raise RuntimeError("Hands network access needs Landlock ABI 6")
    attr = (ctypes.c_uint64 * 3)(0, 0, 1)  # scope: abstract Unix sockets
    fd = libc.syscall(create, ctypes.byref(attr), ctypes.c_size_t(24), ctypes.c_uint32(0))
    if fd < 0:
        raise OSError(ctypes.get_errno(), "cannot create Hands socket restriction")
    try:
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot set no_new_privs")
        if libc.syscall(restrict, ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:
            raise OSError(ctypes.get_errno(), "cannot enforce Hands socket restriction")
    finally:
        os.close(fd)
if sys.platform.startswith("linux") and "--scope-sockets" in sys.argv[1:]:
    keep_to_own_sockets()
sys.stdout.write("ready\n"); sys.stdout.flush()
while True:
    while not inbox and not closed:
        pump(5)
    if not inbox:
        break
    job = inbox.pop(0)
    if "argv" not in job:
        continue  # a request to stop a command that has already ended
    code = 127
    try:
        text = job.get("stdin")
        with open(job["out"], "wb") as out:
            p = subprocess.Popen(job["argv"], cwd=job["cwd"], stdout=out, stderr=subprocess.STDOUT,
                                 stdin=subprocess.PIPE if text is not None else subprocess.DEVNULL,
                                 start_new_session=True)
        groups.append(p.pid)
        sys.stdout.write(json.dumps({"started": p.pid}) + "\n"); sys.stdout.flush()
        if text is not None:
            threading.Thread(target=feed, args=(p.stdin, text), daemon=True).start()
        end = time.time() + job["timeout"]
        while True:
            code = p.poll()
            if code is not None:
                break
            asked = [m for m in inbox if m.get("stop") == job["id"]]
            if asked or closed or time.time() >= end:
                inbox[:] = [m for m in inbox if m not in asked]
                stop(p.pid, signal.SIGKILL)
                p.wait()
                code = 130 if asked else 124
                break
            pump(max(0.0, min(1.0, end - time.time())))
    except Exception as e:
        try:
            with open(job["out"], "ab") as out:
                out.write(("hands: could not start the command: %s\n" % e).encode())
        except OSError:
            pass
    sys.stdout.write(json.dumps({"id": job["id"], "code": code}) + "\n"); sys.stdout.flush()
alive = [g for g in groups if stop(g, signal.SIGTERM)]
end = time.time() + 2
while alive and time.time() < end:
    time.sleep(0.1)
    alive = [g for g in alive if stop(g, 0)]
for g in groups:
    stop(g, signal.SIGKILL)
if sys.platform == "darwin" and confined():
    # In the macOS sandbox a signal reaches only processes in the same sandbox, so this
    # ends whatever is left in it and nothing else. (On Linux the sandbox has its own
    # process list, which ends with this process.)
    try:
        os.kill(-1, signal.SIGKILL)
    except OSError:
        pass
"""


class HandsError(RuntimeError):
    pass


UNENCRYPTED = ("{url} is not encrypted and is not known to be on a private network (its address is public, its "
               "name cannot be looked up here, or requests go through a proxy): anyone between this machine and "
               "the server could read the commands and their output. Put HTTPS in front of the server (its invite "
               "then starts with hands+https://), or reach it over a private network such as Tailscale or "
               "WireGuard. To connect anyway, pass --plain-http.")


class _Stopped(Exception):
    """Raised by the stop signal while the device is only waiting for work."""


def printable(text: str) -> str:
    """`text` safe to print: what a command is called comes from the server, and control
    or invisible characters in it must not reach the terminal as instructions."""
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def say(text: str) -> None:
    print(text, flush=True)  # visible at once, also when the output goes to a file or a service log


def _within(path: str, folder: str) -> bool:
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def _read_plain(path: str, limit: int = 1024 * 1024) -> Optional[str]:
    """The text of `path` if it is an ordinary file with one name, "" if nothing is there,
    None for anything else (a link, a device, a file too large to be a profile). The file is
    opened without following a link and checked through the open handle, so it cannot be
    swapped for a link in between."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return ""
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            return None
        return os.read(fd, limit).decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def _own_folder(path: str) -> bool:
    """Make `path` a folder of its own; True if it had to be made again. Commands may write
    in their temp folder, so one can remove it or leave a link in its place. The device is
    not in the sandbox and must never write through such a link."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        info = None
    if info is not None and stat.S_ISDIR(info.st_mode):
        return False
    if info is not None:
        os.unlink(path)  # a link or a file: removed, never followed
    os.mkdir(path, 0o700)
    return True


def _in_sandbox(tmp: str, state: str) -> list:
    """On macOS, the processes running in the sandbox whose temp folder is `tmp`, whatever
    session or group they have moved to. The system is asked what each of this user's
    processes is allowed to do: one of ours is sandboxed, may write in `tmp`, and may not
    write in `state`, the folder above it. A process cannot change the sandbox it is in,
    so this finds what a process group or session cannot. Both folders must exist. Empty on
    other systems and where the system cannot be asked."""
    if sys.platform != "darwin":
        return []
    try:
        import ctypes
        check = ctypes.CDLL(None).sandbox_check
        check.restype = ctypes.c_int
        check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]  # then the path, as a variable argument
        listing = subprocess.run(["/bin/ps", "-axo", "pid=,uid="], capture_output=True, text=True, timeout=10,
                                 env={"LC_ALL": "C", "PATH": os.defpath}).stdout
    except (OSError, AttributeError, subprocess.SubprocessError):
        return []
    by_path, quiet = 1, 0x40000000  # the question is about a path; do not log the answer

    def may_write(pid: int, path: str) -> bool:
        return check(pid, b"file-write-data", by_path | quiet, ctypes.c_char_p(os.fsencode(path))) == 0

    found = []
    for line in listing.splitlines():
        parts = line.split()
        try:
            pid, owner = int(parts[0]), int(parts[1])
        except (IndexError, ValueError):
            continue
        if owner != os.getuid() or pid == os.getpid():
            continue
        if check(pid, None, 0) == 1 and may_write(pid, tmp) and not may_write(pid, state):
            found.append(pid)
    return found


def shown_in_home(extra: Any = ()) -> list:
    """The real folders inside the home folder that commands may still read: toolchains,
    folders on PATH, and `extra`, the ones the person named (those may be anywhere)."""
    real_home = os.path.realpath(os.path.expanduser("~"))
    wanted = [os.environ.get(name) or os.path.join(real_home, sub) for name, sub in TOOL_HOMES.items()]
    wanted += [os.environ[name] for name in TOOL_PATHS if os.environ.get(name)]
    wanted += [os.path.join(real_home, sub) for sub in TOOL_FOLDERS]
    if os.environ.get("PIPX_HOME"):
        wanted.append(os.environ["PIPX_HOME"])
    if os.environ.get("XDG_DATA_HOME"):
        wanted.append(os.path.join(os.environ["XDG_DATA_HOME"], "pipx"))
    wanted += [part for part in os.environ.get("PATH", "").split(os.pathsep) if part]
    found: list = []
    for path in wanted:
        real = os.path.realpath(os.path.expanduser(path))
        if os.path.isdir(real) and _within(real, real_home) and real != real_home and real not in found:
            found.append(real)
    for path in extra:
        real = os.path.realpath(os.path.expanduser(str(path)))
        if not os.path.isdir(real):
            raise HandsError(f"--read {path}: not a folder")
        if real in ("/", real_home):
            raise HandsError(f"--read {path}: name a folder inside your home folder, or use --read-home for all of it")
        if sandbox.socket_overlap(real):
            raise HandsError(f"--read {path}: that folder overlaps protected host service sockets")
        if sandbox.protected(real, [os.path.realpath(home())]):
            raise HandsError(f"--read {path}: that folder holds keys or credentials and is never shown to commands")
        if real not in found:
            found.append(real)
    return found


def _real_in_home(path: str) -> str:
    """`path` with links followed, if it is a folder in the home folder; else as it is."""
    home_folder = os.path.expanduser("~")
    if not path or not os.path.isabs(path) or not os.path.isdir(path):
        return path
    if not (_within(path, home_folder) or _within(os.path.realpath(path), os.path.realpath(home_folder))):
        return path
    return os.path.realpath(path)


def _run_quiet(argv: list) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
        return done.stdout.strip() if done.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _developer_tools() -> tuple:
    """On macOS, where the real developer tools and SDK are. `/usr/bin/git`, `cc` and the
    like are small launchers that look the real tool up, and keep a cache of that lookup
    in a folder commands cannot write; with these first on the path the launchers are not used."""
    if sys.platform != "darwin":
        return [], ""
    root = _run_quiet(["/usr/bin/xcode-select", "-p"])
    if not root:
        return [], ""
    dirs = [d for d in (os.path.join(root, "usr", "bin"),
                        os.path.join(root, "Toolchains", "XcodeDefault.xctoolchain", "usr", "bin")) if os.path.isdir(d)]
    return dirs, _run_quiet(["/usr/bin/xcrun", "--show-sdk-path"])


def _before_usr_bin(path: str, dirs: list) -> str:
    """`path` with `dirs` placed just ahead of /usr/bin: they stand in for the launchers
    there, and must not come before anything the person put on their path themselves."""
    parts = [part for part in path.split(os.pathsep) if part]
    at = parts.index("/usr/bin") if "/usr/bin" in parts else len(parts)
    return os.pathsep.join(parts[:at] + list(dirs) + parts[at:])


def _git_identity() -> tuple:
    """The name and email the person commits with, so work done through Hands is theirs."""
    git = shutil.which("git")
    if not git:
        return "", ""
    return (_run_quiet([git, "config", "--global", "user.name"]), _run_quiet([git, "config", "--global", "user.email"]))


def _git_value(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def home() -> Path:
    return Path(os.environ.get("TENUO_HANDS_HOME") or "~/.hermes-tenuo/hands").expanduser()


def _private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def device_key():
    """This device's key, created on first use and kept in a file only you can read."""
    from tenuo import SigningKey
    path = home() / "device.key"
    if path.is_file():
        return SigningKey.from_bytes(wire.unb64(path.read_text()))
    key = SigningKey.generate()
    _private_write(path, wire.b64(bytes(key.secret_key_bytes())) + "\n")
    return key


def _post(url: str, body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    request = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read(wire.MAX_BODY))
    except urllib.error.HTTPError as e:
        if e.code >= 500:
            # A proxy in front of the server, or the server itself failing: not an answer
            # about this device. It is tried again like any lost connection.
            raise ConnectionError(f"the server answered {e.code}") from e
        try:
            detail = json.loads(e.read(65536)).get("error", "")
        except ValueError:
            detail = ""
        raise HandsError(detail or f"the server answered {e.code}") from e
    except (OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise ConnectionError(
                f"this machine does not trust the server's certificate "
                f"({getattr(reason, 'verify_message', '') or reason}). If the server "
                "uses its own certificate authority or a self-signed certificate, set SSL_CERT_FILE to that "
                "certificate file and run this again") from e
        raise ConnectionError(str(reason)) from e


def check(invite: Optional[str], folder: str, read_only: bool = False, plain_http: bool = False,
          network: bool = False, allow_unsandboxed: bool = False) -> list:
    """What `hands up` needs, looked at without pairing or running anything. A list of
    (ok, text): ok is True, False, or None for a line that is only information."""
    found: list = []
    real = os.path.realpath(os.path.expanduser(folder))
    if not os.path.isdir(real):
        found.append((False, f"{folder} is not a folder"))
    elif real in ("/", os.path.realpath(os.path.expanduser("~"))):
        found.append((False, "point Hands at a project folder, not your home folder or /"))
    else:
        found.append((True, f"folder to share: {real}"))
    state = os.path.realpath(home())
    if _within(state, real) or _within(real, state):
        found.append((False, f"the shared folder and Hands's own folder ({state}) must be separate"))
    kind = sandbox.available()
    if kind:
        found.append((True, f"sandbox: {kind}" + (" (read-only)" if read_only else "")))
    elif allow_unsandboxed and not read_only:
        found.append((None, "No sandbox: --no-sandbox explicitly gives commands your full user access."))
    else:
        found.append((False, f"no sandbox on this machine: {sandbox.why_not()}. Or use --no-sandbox to give "
                             "commands your full access"))
    if network and kind == "bwrap" and not sandbox.scopes_sockets():
        found.append((False, "--network needs enabled Landlock ABI 6 or later; omit --network or upgrade the kernel"))
    url = ""
    saved = home() / "server.json"
    if invite:
        try:
            url = wire.Invite.parse(invite).url
        except ValueError as e:
            found.append((False, str(e)))
    elif saved.is_file():
        try:
            url = json.loads(saved.read_text())["url"]
        except (OSError, ValueError, KeyError):
            found.append((False, f"{saved} is damaged: pair again with a new `/hands invite` line"))
    else:
        found.append((False, "no server yet: run `/hands invite` in a Hermes chat and pass the line it prints"))
    unsafe = bool(url and wire.plain_and_public(url))
    if unsafe:
        found.append((None if plain_http else False,
                      UNENCRYPTED.format(url=url) if not plain_http else
                      f"{url} is not encrypted (--plain-http): commands and output can be read on the way"))
    if url and (not unsafe or plain_http):
        # A Hands server answers a request from no device with "no session here" (410).
        # Anything else that answers is a proxy, another service, or a wrong address.
        request = urllib.request.Request(url + wire.API + "/poll", b"{}", {"Content-Type": "application/json"})
        status: Optional[int] = None
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as e:
            status = e.code
        except (OSError, ValueError) as e:
            found.append((False, f"cannot reach the server at {url} ({getattr(e, 'reason', e)}). If Hermes runs on "
                                 "another machine, set hands.url there to an address this machine can reach"))
        if status == 410:
            found.append((True, f"server reachable: {url}"))
            try:
                hello = _post(url + wire.API + "/hello", {}, timeout=10)
                if not isinstance(hello, dict) or hello.get("protocol") != 1:
                    found.append((False, "Hands protocol mismatch: update the server plugin and laptop package together"))
                else:
                    found.append((True, "server and laptop speak Hands protocol 1"))
            except HandsError as e:
                if getattr(e.__cause__, "code", None) == 404:
                    found.append((None, "Server has no compatibility endpoint; it answers Hands v1. "
                                  "Update the server plugin for first-session checks."))
                else:
                    found.append((False, f"compatibility check refused: {e}"))
            except ConnectionError as e:
                found.append((False, f"compatibility check failed: {e}"))
        elif status is not None:
            found.append((False, f"{url} answered (HTTP {status}), but not as a Hands server: check the address, "
                                 "and that hands.listen is set in the plugin config on the server"))
    real_home = os.path.expanduser("~")
    tools = sorted(sub.lstrip(".") for name, sub in TOOL_HOMES.items()
                   if os.path.isdir(os.environ.get(name) or os.path.join(real_home, sub)))
    found.append((None, "toolchains commands will be told about: " + (", ".join(tools) if tools else "none found")))
    name, email = _git_identity()
    found.append((None, f"git commits will be authored as: {name} <{email}>" if name or email else
                  "no git name or email set: commits made through Hands will need one"))
    return found


class Device:
    def __init__(self, invite: Optional[str], folder: str, ttl_seconds: int, name: Optional[str] = None,
                 allow_unsandboxed: bool = False, say: Callable[[str], None] = say, read_only: bool = False,
                 plain_http: bool = False, read_home: bool = False, read: Any = (), network: bool = False):
        self.folder = os.path.realpath(os.path.expanduser(folder))
        if not os.path.isdir(self.folder):
            raise HandsError(f"{folder} is not a folder")
        if self.folder in ("/", os.path.realpath(os.path.expanduser("~"))):
            raise HandsError("point Hands at a project folder, not your home folder or /")
        if ttl_seconds <= 0:
            raise HandsError("the time window must be positive")
        self.ttl_seconds = ttl_seconds
        self.plain_http = plain_http
        # A command-local CA setting disappears in a fresh shell. Resolve it now,
        # before a reconnect can be printed or run from a different directory.
        ca_file = os.environ.get("SSL_CERT_FILE")
        self.ssl_cert_file = os.path.abspath(ca_file) if ca_file else ""
        self.allow_unsandboxed = allow_unsandboxed
        self.read_only = read_only  # commands may look at the folder and not change it
        self.network = network      # commands may use the internet (to install, clone, download)
        # Commands cannot read the home folder unless the person says so; what they need
        # from it (toolchains, and any folder named with --read) is put back.
        self.read_home = read_home
        self.shown = shown_in_home(read)
        self.named = [os.path.realpath(os.path.expanduser(str(path))) for path in read]
        # Where this device keeps its key, its log and the commands' temp folder. Commands
        # never see it (only the temp folder inside), so it cannot overlap what is shared.
        self.state = os.path.realpath(home())
        if _within(self.state, self.folder) or _within(self.folder, self.state):
            raise HandsError(f"the shared folder and Hands's own folder ({self.state}) must be separate: "
                             "share another folder, or set TENUO_HANDS_HOME to a folder outside it")
        self.tmp = os.path.join(self.state, "tmp")
        os.makedirs(self.state, mode=0o700, exist_ok=True)
        _own_folder(self.tmp)  # an earlier command may have left a link here
        self._tools = _developer_tools()
        self._identity = _git_identity()
        self._prepare_home(self.tmp)
        sandbox.wrap(self.folder, self.tmp, ["true"], allow_unsandboxed=allow_unsandboxed,
                     writable=not read_only, home_visible=read_home, tools=self.shown,
                     network=network)  # fail before pairing
        self.say = say
        self.key = device_key()
        self.name = name or socket.gethostname().split(".")[0]
        saved = home() / "server.json"
        if invite:
            parsed = wire.Invite.parse(invite)
            self.url, self.secret, server = parsed.url, parsed.secret, parsed.server_key
        elif saved.is_file():
            data = json.loads(saved.read_text())
            self.url, self.secret, server = data["url"], "", data["server_key"]
        else:
            raise HandsError("no server paired yet: run `/hands invite` in a Hermes chat and pass the line it prints")
        if not plain_http and wire.plain_and_public(self.url):
            raise HandsError(UNENCRYPTED.format(url=self.url))
        self.server_key = wire.public_key(server)
        self.expires = time.time() + ttl_seconds
        self.grant = wire.mint_grant(self.key, self.server_key, self.folder, ttl_seconds)
        # Valid a little longer than the grant, so the last result can still be reported.
        self.identity = wire.mint_identity(self.key, ttl_seconds + wire.REPORT_GRACE)
        self.me = wire.key_text(self.key.public_key)
        self._seen: set = set()
        self._stop = False
        self._polled_at: Optional[float] = None
        self._poll_nonce: Optional[str] = None
        self._waiting = False
        self._talk = threading.Lock()                          # one writer to a runner at a time
        self._busy: Optional[tuple] = None                     # (runner, its job id) while a command runs
        self._job: Optional[str] = None                        # the command being handled, by the server's id
        self._unsent: list = []  # results the server has not received yet: (command id, output, exit code)
        self._stop_job: Optional[str] = None                   # the command that was asked to stop
        self._groups: Dict[int, float] = {}                    # process group of each command -> when it began
        self._runner: Optional[subprocess.Popen] = None
        self._log = home() / "log.jsonl"

    # -- talking to the server ------------------------------------------------

    def _signed(self, tool: str, args: Dict[str, str]) -> str:
        return wire.sign(self.identity, self.key, tool, args)

    def _request(self, op: str, nonce: str) -> str:
        return self._signed(wire.TOOL_POLL, wire.request(op, nonce))

    def pair(self) -> None:
        grant, identity = self.grant.to_base64(), self.identity.to_base64()
        mode = self.mode()
        network = "on" if self.network or mode == "none" else "off"  # with no sandbox nothing is held back
        # The invite is signed too: whose machine this becomes follows from it.
        nonce = wire.digest(grant, self.folder, self.name, self.tmp, mode, self.secret, network)
        _post(self.url + wire.API + "/pair", {
            "invite": self.secret, "device": self.me, "name": self.name, "folder": self.folder, "tmp": self.tmp,
            "mode": mode, "network": network, "grant": grant, "identity": identity, "nonce": nonce,
            "sig": self._request("pair", nonce),
        }, timeout=30)
        _private_write(home() / "server.json", json.dumps(
            {"url": self.url, "server_key": wire.key_text(self.server_key)}) + "\n")

    def mode(self) -> str:
        """What holds commands on this machine. The server repeats it to the agent, so it
        must never claim a sandbox that is not there."""
        if sandbox.available() is None:
            return "none"
        return "read-only" if self.read_only else "sandboxed"

    def poll(self) -> Optional[Dict[str, Any]]:
        nonce = secrets.token_hex(16)
        self._polled_at, self._poll_nonce = time.time(), nonce
        reply = _post(self.url + wire.API + "/poll", {
            "device": self.me, "nonce": nonce, "sig": self._request("poll", nonce),
        }, timeout=min(wire.POLL_SECONDS + 15, max(1.0, self.expires - time.time() + 1)))
        return reply.get("job")

    def bye(self) -> None:
        """Tell the server this device is going down, so callers hear it now instead of waiting."""
        nonce = secrets.token_hex(16)
        try:
            _post(self.url + wire.API + "/bye", {
                "device": self.me, "nonce": nonce, "sig": self._request("bye", nonce),
            }, timeout=5)
        except (HandsError, ConnectionError):
            pass

    def report(self, job_id: str, output: str, returncode: int, timeout: float = 60) -> None:
        output = wire.fit(output)
        args = {"job": job_id, "digest": wire.digest(output, returncode)}
        _post(self.url + wire.API + "/result", {
            "device": self.me, "job": job_id, "output": output, "returncode": returncode,
            "sig": self._signed(wire.TOOL_RESULT, args),
        }, timeout=timeout)

    def _deliver(self, job_id: str, output: str, returncode: int) -> None:
        """Keep the result before trying delivery, including when a stop interrupts it."""
        self._unsent.append((job_id, output, returncode))
        if self._stop:
            # A command just interrupted locally can still confirm its exit immediately.
            # This is one short attempt, not a flush of previously queued results.
            self._waiting = True
            try:
                self.report(job_id, output, returncode, timeout=1)
            finally:
                self._waiting = False
            self._unsent.pop()
            return
        self._send_unsent()

    def _send_unsent(self, deadline: Optional[float] = None) -> None:
        """Retry held results with short, signal-interruptible requests. No new work runs."""
        deadline = self.expires + wire.REPORT_GRACE if deadline is None else deadline
        while self._unsent and not self._stop:
            left = deadline - time.time()
            if left <= 0:
                return
            job_id, output, returncode = self._unsent[0]
            self._waiting = True
            try:
                if self._stop:
                    return
                self.report(job_id, output, returncode, timeout=min(5, left))
            except HandsError:
                self.say("The server refused a held result; it is no longer pending for delivery.")
            else:
                self.say("Sent a result that was held while the server could not be reached.")
            finally:
                self._waiting = False
            self._unsent.pop(0)

    def _drain_results(self) -> None:
        """After expiry, retry only reporting within the existing reporting grace period."""
        deadline = self.expires + wire.REPORT_GRACE
        while self._unsent and not self._stop and time.time() < deadline:
            try:
                self._send_unsent(deadline)
            except _Stopped:
                break
            except ConnectionError:
                self._pause(1, deadline=deadline)

    # -- checking and running one command ----------------------------------------

    def verify(self, job: Dict[str, Any]) -> str:
        """The folder this command may change, or raise. Nothing here trusts the server."""
        job_id, where = str(job["id"]), str(job["dir"])
        if job_id in self._seen:
            raise HandsError("this command was already run")
        if time.time() > self.expires:
            raise HandsError("the time window has ended")
        poll = str(job.get("poll") or "")
        if self._poll_nonce is not None and poll != self._poll_nonce:
            raise HandsError("this command does not answer this device's request")
        args = {"dir": where, "cmd": wire.digest(job_id, job["cmd"], bool(job.get("login")), job.get("stdin"),
                                                int(job["timeout"]), job.get("shown") or "",
                                                int(job.get("waited_ms") or 0), poll)}
        chain = wire.load_chain(job["chain"])
        if chain[0].to_base64() != self.grant.to_base64():
            raise HandsError("this command belongs to an old Hands session")
        wire.check(chain, self.key.public_key, wire.TOOL, args, job["pop"])
        # The warrants were checked against the folder as written, so it must be the real
        # path: a link inside an allowed folder must not lead the command somewhere else.
        real = os.path.realpath(where)
        if real != where:
            raise HandsError("the command names its folder through a link; it must use the real path")
        if not (real == self.folder or real.startswith(self.folder + os.sep)) or not os.path.isdir(real):
            raise HandsError("the command is for a folder this device isn't serving")
        self._seen.add(job_id)
        return real

    def budget(self, job: Dict[str, Any]) -> int:
        """Seconds this command may still run. The server signs how long it will wait and
        how long this device's request had been open when it handed the command over, so
        the device can tell, with its own clock only, that a command reached it too late
        (the machine slept, the network stalled) and must not run. Nothing runs past the
        end of this device's own time window either."""
        timeout = max(1, min(int(job["timeout"]), 24 * 3600))
        window = self.expires - time.time()
        if window <= 0:
            raise HandsError("the time window has ended")
        if self._polled_at is not None:
            late = (time.time() - self._polled_at) - int(job.get("waited_ms") or 0) / 1000.0
            if late >= timeout:
                raise HandsError("it reached this machine too late to run (asleep or offline), so it was not run")
            timeout = math.ceil(timeout - max(0.0, late))
        return max(1, min(timeout, math.ceil(window)))

    def _env(self, tmp: Optional[str] = None) -> Dict[str, str]:
        tmp = tmp or self.tmp
        env = {name: value for name, value in os.environ.items() if name in SAFE_ENV}
        env.setdefault("PATH", os.defpath)
        env["HOME"] = tmp  # a login shell must not source the user's real dotfiles
        env["TMPDIR"] = tmp
        real_home = os.path.expanduser("~")
        for name, folder in TOOL_HOMES.items():
            where = os.environ.get(name) or os.path.join(real_home, folder)
            if os.path.isdir(where):
                env[name] = where
        for name in TOOL_PATHS:
            if os.environ.get(name):
                env[name] = os.environ[name]
        if not self.read_home:
            # The home folder is hidden except the real folders that hold tools. A name in it
            # that is a link to one (~/bin -> ~/tools/bin, or -> /opt/tools) would lead
            # nowhere, so commands get the folder it stands for.
            env["PATH"] = os.pathsep.join(_real_in_home(part) for part in env["PATH"].split(os.pathsep))
            for name in (*TOOL_HOMES, *TOOL_PATHS):
                if name in env:
                    env[name] = _real_in_home(env[name])
        dirs, sdk = self._tools
        if dirs:
            env["PATH"] = _before_usr_bin(env["PATH"], dirs)
        if sdk:
            env["SDKROOT"] = sdk
        return env

    def _prepare_home(self, tmp: str) -> None:
        """What a command's stand-in home folder starts with: the person's git name and
        email (nothing else of their git settings), and a profile that keeps the developer
        tools first on the path in login shells. Files a command has since changed are left."""
        name, email = self._identity
        config = os.path.join(tmp, ".gitconfig")
        if (name or email) and not os.path.exists(config):
            lines = ["[user]"] + [f"\t{key} = {_git_value(value)}" for key, value in (("name", name), ("email", email)) if value]
            _private_write(Path(config), "\n".join(lines) + "\n")
        dirs, _ = self._tools
        if dirs:
            # The same placement as in _env(), redone after a login shell has rebuilt the path.
            _private_write(Path(tmp) / PROFILE, "\n".join([
                "d=" + shlex.quote(os.pathsep.join(dirs)),
                'p=":$PATH:"',
                'case "$p" in *":/usr/bin:"*) p="${p/:\\/usr\\/bin:/:$d:/usr/bin:}";; *) p="$p$d:";; esac',
                'p="${p#:}"; PATH="${p%:}"; export PATH; unset p d', ""]))
            source = f'[ -f "$HOME/{PROFILE}" ] && . "$HOME/{PROFILE}"\n'
            # The stand-in home belongs to the commands: whatever is there under this name
            # is read only if it is a plain file of its own, never through a link.
            profile = Path(tmp) / ".bash_profile"
            had = _read_plain(str(profile))
            if had is None:
                had = ""  # a link or something else: it is replaced, not followed
            if source not in had:
                _private_write(profile, had + ("" if had.endswith("\n") or not had else "\n") + source)

    def run(self, job: Dict[str, Any], folder: str, timeout: Optional[int] = None) -> tuple:
        shell = ["/bin/bash", "-lc" if job.get("login") else "-c", job["cmd"]]
        timeout = timeout or max(1, min(int(job["timeout"]), 24 * 3600))
        # A narrower warrant gets its own, narrower sandbox for the one command, with a temp
        # folder of its own: the session's temp folder holds files later commands run, and
        # a narrower command must not be able to change them.
        own = folder != self.folder
        tmp = tempfile.mkdtemp(prefix="narrow-", dir=self.state) if own else self.tmp
        if own or _own_folder(tmp):
            self._prepare_home(tmp)
        lost = False
        # The command writes its output to this file. It is read back through the handle
        # opened here, never by name: the name is in a folder the command can change.
        fd, out_path = tempfile.mkstemp(prefix=".hands-out-", dir=tmp)
        try:
            if own:
                runner = self._start_runner(folder, shared=False, tmp=tmp)
            else:
                if self._runner is not None and self._runner.poll() is not None:
                    self.say("  A command ended Hands's own supervisor. What it left running was stopped where "
                             "it could be found; check for stray processes if this was not expected.")
                    self._stop_runner()  # clear what it left, start again
                if self._runner is None:
                    self._runner = self._start_runner(self.folder, shared=True)
                runner = self._runner
            if runner is None:
                return "hands: this machine could not start its sandbox, so the command was not run\n", 126
            code = self._ask(runner, shell, folder, job.get("stdin"), timeout, out_path)
            if code is None:
                try:
                    lost = runner.wait(1) is not None  # gone, not just slow to answer
                except subprocess.TimeoutExpired:
                    lost = False
            if own:
                self._close(runner)  # stops whatever the command left behind
                self._reap(tmp)
            elif code is None:
                self._stop_runner()
            if lost:
                self.say("  A command stopped Hands's own supervisor. What it had left running was stopped.")
            os.lseek(fd, 0, os.SEEK_SET)
            data = b""
            while len(data) <= MAX_OUTPUT:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(fd)
            if own:
                shutil.rmtree(tmp, ignore_errors=True)
            else:
                try:
                    os.unlink(out_path)
                except OSError:
                    pass
        text = data[:MAX_OUTPUT].decode("utf-8", errors="replace")
        if code is None and lost:
            text += "\nhands: this command stopped Hands's supervisor on the device; what it left running was stopped\n"
            code = 137
        if code is None:
            code = 124
        if code == 124:
            text += f"\nhands: stopped after {timeout} seconds\n"
        if len(data) > MAX_OUTPUT:
            text += "\nhands: output cut at 8 MB\n"
        return text, code

    # -- the sandbox the commands run in ---------------------------------------------

    def _start_runner(self, folder: str, shared: bool, tmp: Optional[str] = None) -> Optional[subprocess.Popen]:
        tmp = tmp or self.tmp
        python = os.path.realpath(getattr(sys, "_base_executable", None) or sys.executable)
        # The interpreter and its standard library, wherever they are installed.
        own = sorted({os.path.realpath(p) for p in (sys.base_prefix, sys.base_exec_prefix, os.path.dirname(python))})
        try:
            command = [python, "-I", "-S", "-c", RUNNER]
            if self.network and sandbox.available() == "bwrap":
                command.append("--scope-sockets")
            argv = sandbox.wrap(folder, tmp, command,
                                allow_unsandboxed=self.allow_unsandboxed, shared=shared, readable=own,
                                hidden=[self.state], writable=not self.read_only,
                                home_visible=self.read_home, tools=self.shown, network=self.network)
            runner = subprocess.Popen(argv, cwd=folder, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, start_new_session=True, env=self._env(tmp), bufsize=0)
        except (OSError, sandbox.SandboxUnavailable):
            return None
        try:
            ready = self._line(runner, 15)
        except EOFError:
            ready = None
        if ready != "ready":
            self._close(runner)
            return None
        return runner

    @staticmethod
    def _line(runner: subprocess.Popen, seconds: float) -> Optional[str]:
        """The next line from the runner, or None if none comes in time. EOFError if the
        runner is gone. One read can bring more than one line; the rest waits for the next call."""
        held = getattr(runner, "hands_held", b"")
        end = time.time() + seconds
        while b"\n" not in held:
            left = end - time.time()
            if left <= 0 or not select.select([runner.stdout], [], [], left)[0]:
                runner.hands_held = held
                return None
            chunk = os.read(runner.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError
            held += chunk
        line, _, runner.hands_held = held.partition(b"\n")
        return line.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _close(runner: Optional[subprocess.Popen]) -> None:
        """End a sandbox. The runner stops everything in it, then exits."""
        if runner is None:
            return
        try:
            runner.stdin.close()
            runner.wait(8)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            os.killpg(runner.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            runner.wait(2)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _stop_runner(self) -> None:
        runner, self._runner = self._runner, None
        self._close(runner)
        self._sweep()
        if runner is not None:
            self._reap(self.tmp)

    def _reap(self, tmp: str) -> None:
        """Stop whatever still runs in the sandbox that used `tmp`. Its supervisor does this
        from inside when it ends, but a command can stop the supervisor first and leave a
        process in a session of its own, which no process group leads back to. macOS only:
        on Linux the sandbox's process list ends with it."""
        if sys.platform != "darwin":
            return
        try:
            if _own_folder(tmp) and tmp == self.tmp:
                self._prepare_home(tmp)
        except OSError:
            return
        for _ in range(5):  # a process may start another while this looks
            pids = _in_sandbox(tmp, self.state)
            if not pids:
                return
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            time.sleep(0.1)

    def _sweep(self) -> None:
        """Stop what commands left behind when their sandbox could not do it itself (a
        command ended the runner). macOS only: there the device sees the same process
        numbers as its commands, and each command ran in a process group of its own. On
        Linux the sandbox's process list ends with it. A process that also left its
        command's group is not found this way."""
        groups, self._groups = self._groups, {}
        if sys.platform != "darwin" or not groups:
            return
        try:
            listing = subprocess.run(["/bin/ps", "-axo", "pid=,pgid=,lstart="], capture_output=True, text=True,
                                     timeout=10, env={"LC_ALL": "C", "PATH": os.defpath}).stdout
        except (OSError, subprocess.SubprocessError):
            return
        rows = []
        for line in listing.splitlines():
            parts = line.split(None, 2)
            try:
                rows.append((int(parts[0]), int(parts[1]), time.mktime(time.strptime(parts[2].strip(), "%c"))))
            except (IndexError, ValueError):
                continue
        born_now = {pid: born for pid, _, born in rows}
        for group, began in groups.items():
            leader = born_now.get(group)
            if leader is not None and abs(leader - began) > 5:
                continue  # that number belongs to another program now
            for pid, pgid, _ in rows:
                if pgid == group and pid != os.getpid():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass

    def _ask(self, runner: subprocess.Popen, shell: list, folder: str, stdin: Optional[str], timeout: int,
             out_path: str) -> Optional[int]:
        """Run one command in a sandbox; None if the sandbox hung or died."""
        job_id = secrets.token_hex(8)
        line = json.dumps({"id": job_id, "argv": shell, "cwd": folder, "stdin": stdin, "timeout": timeout,
                           "out": out_path}) + "\n"
        try:
            with self._talk:
                if self._stop or (self._job is not None and self._stop_job == self._job):
                    return 130  # stopped before it was started: it does not start
                runner.stdin.write(line.encode())
                runner.stdin.flush()
                self._busy = (runner, job_id)
            give_up, asked, answer = time.time() + timeout + 20, False, {}
            while time.time() < give_up:
                reply = self._line(runner, 1.0)  # short waits, so a local stop is noticed
                if reply is None:
                    if self._stop and not asked:
                        asked = True
                        self.cancel()  # Ctrl-C on this machine stops the command that is running
                    continue
                answer = json.loads(reply)
                if "started" not in answer:
                    break
                self._groups[int(answer.pop("started"))] = time.time()
                while len(self._groups) > 2000:
                    self._groups.pop(next(iter(self._groups)))
        except (OSError, ValueError, EOFError):
            answer = {}
        finally:
            with self._talk:
                self._busy = None
        if answer.get("id") != job_id:
            return None
        return int(answer.get("code", 127))

    def cancel(self, job: Optional[str] = None) -> None:
        """Stop the command being handled, with everything it started in its group. Given a
        command's id, only that command: a request that arrives late must not stop the next
        one. A command that has not started yet is kept from starting."""
        with self._talk:
            if job is not None and job != self._job:
                return
            self._stop_job = self._job
            if self._busy is None:
                return
            runner, job_id = self._busy
            try:
                runner.stdin.write((json.dumps({"stop": job_id}) + "\n").encode())
                runner.stdin.flush()
            except OSError:
                pass

    def _watch(self, job_id: str, done: threading.Event) -> None:
        """While a command runs, ask the server whether to stop it. Only an answer signed by
        the server, for this command, stops it."""
        if done.wait(0.3):
            return  # most commands are over before anyone could want them stopped
        while not done.is_set():
            nonce = secrets.token_hex(16)
            try:
                reply = _post(self.url + wire.API + "/watch", {
                    "device": self.me, "job": job_id, "nonce": nonce, "sig": self._request("watch", nonce),
                }, timeout=45)
            except (HandsError, ConnectionError):
                if done.wait(2):
                    return
                continue
            if not reply.get("cancel"):
                continue
            try:
                wire.check([self.grant], self.key.public_key, wire.TOOL,
                           {"dir": self.folder, "cmd": wire.digest("cancel", job_id)}, str(reply.get("pop", "")))
            except Exception:
                return
            self.cancel(job_id)
            return

    def handle(self, job: Dict[str, Any]) -> None:
        job_id = str(job.get("id", ""))
        shown = str(job.get("shown") or "(session setup)")[:500]
        try:
            folder = self.verify(job)
            timeout = self.budget(job)
        except Exception as e:  # a refusal is reported, never run
            reason = str(e) or type(e).__name__
            self._record(shown, None, f"refused: {reason}")
            self._deliver(job_id, f"hands: refused on the device: {reason}\n", 126)
            return
        done = threading.Event()
        with self._talk:
            self._job, self._stop_job = job_id, None
        threading.Thread(target=self._watch, args=(job_id, done), daemon=True).start()
        try:
            output, code = self.run(job, folder, timeout)
        finally:
            done.set()
            with self._talk:
                self._job = None
        if code == 130:
            output += ("\nhands: stopped because Hands was stopped on the device\n" if self._stop else
                       "\nhands: stopped at the server's request\n")
        self._record(shown, code, "stopped" if code == 130 else "")
        self._deliver(job_id, output, code)

    def _record(self, shown: str, code: Optional[int], note: str) -> None:
        line = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "folder": self.folder, "command": shown,
                "exit": code, "note": note}
        with open(self._log, "a") as f:
            f.write(json.dumps(line) + "\n")
        self.say(f"  {time.strftime('%H:%M:%S')}  {'refused' if code is None else f'exit {code}'}  "
                 f"{printable(shown[:100])}")

    # -- the loop ---------------------------------------------------------------

    def _pause(self, seconds: float, deadline: Optional[float] = None) -> None:
        """Wait, but not past a request to stop or the end of the time window."""
        end = min(time.time() + seconds, self.expires if deadline is None else deadline)
        while not self._stop and time.time() < end:
            time.sleep(0.2)

    def summary(self) -> list:
        """What commands from the server can and cannot do here, in plain words."""
        kind = sandbox.available()
        if kind is None:
            return ["No sandbox on this machine: commands run with your full access (--no-sandbox)."]
        lines = ["Commands can read this folder and cannot change it (--read-only)." if self.read_only else
                 "Commands can change files only in this folder."]
        if self.read_home:
            lines.append("They can read the rest of your home folder (--read-home), except your keys, credentials, "
                         "browser data and shell history.")
        else:
            lines.append("They cannot read the rest of your home folder, except your toolchains"
                         + (" and " + ", ".join(self.named) if self.named else "") + ".")
        lines.append("They can read system files.")
        if self.network:
            lines.append("They can use the internet (--network), and reach programs listening on this machine.")
        elif kind == "sandbox-exec":
            lines.append("They have no internet (start with --network to let them install or download). "
                         "They can reach programs listening on this machine.")
        else:
            lines.append("They have no network: no internet, and no programs on this machine "
                         "(start with --network to let them install or download).")
        if kind == "sandbox-exec":
            lines.append("They cannot open apps, control other apps, or touch other programs' processes.")
        return lines

    def stop(self, *from_signal: Any) -> None:
        self._stop = True
        if from_signal and self._waiting:
            raise _Stopped()  # leave the open request now; a running command is stopped by its own loop

    def reconnect_command(self) -> str:
        """A fresh local consent action; never include the consumed invite or its secret."""
        args = ["env", f"TENUO_HANDS_HOME={self.state}"]
        if self.ssl_cert_file:
            args.append(f"SSL_CERT_FILE={self.ssl_cert_file}")
        args.extend(["uvx", "hermes-tenuo", "hands", "up", "--dir", self.folder,
                     "--for", f"{self.ttl_seconds}s", "--name", self.name])
        for enabled, flag in ((self.read_only, "--read-only"), (self.network, "--network"),
                              (self.read_home, "--read-home"), (self.allow_unsandboxed, "--no-sandbox")):
            if enabled:
                args.append(flag)
        for path in self.named:
            args.extend(("--read", path))
        # Preserve only an explicitly accepted unencrypted public connection.
        if self.plain_http:
            args.append("--plain-http")
        return shlex.join(args)

    def serve(self) -> int:
        self.pair()
        until = time.strftime("%H:%M", time.localtime(self.expires))
        self.say(f"Hands is up: {self.url} can run commands in {self.folder} until {until}.")
        for line in self.summary():
            self.say("  " + line)
        self.say("Press Ctrl-C to stop device access. /hands off only changes chat routing.")
        self.say("Back in the originating Hermes chat, run /hands verify to confirm this connection.")
        self.say("Reconnect or renew locally with: " + self.reconnect_command())
        failures, rejoins = 0, 0
        while not self._stop and time.time() < self.expires:
            try:
                self._send_unsent()
                self._waiting = True
                try:
                    job = self.poll()
                finally:
                    self._waiting = False
                failures, rejoins = 0, 0
            except _Stopped:
                break
            except HandsError as e:
                # The server forgot this session, which is what a restart of Hermes looks
                # like from here. A machine it still knows pairs again by itself, with the
                # grant and time window it already has. Only the server refusing to pair
                # it (it was revoked) ends the session; a server that cannot be reached
                # is tried again, and one that keeps forgetting is given longer each time.
                ended = str(e)
                if rejoins < 6:
                    rejoins += 1
                    if rejoins > 1:
                        self._pause(min(30, 2 ** rejoins))
                    if self._stop or time.time() >= self.expires:
                        break
                    try:
                        self.pair()
                    except ConnectionError as lost:
                        rejoins -= 1  # the server did not answer: not one of its refusals to remember
                        failures += 1
                        if failures == 1:
                            self.say(f"Can't reach the server ({lost}); retrying.")
                        self._pause(min(30, 2 ** min(failures, 5)))
                        continue
                    except HandsError as refused:
                        ended = str(refused)
                    else:
                        self.say("The server restarted; this machine is paired with it again.")
                        continue
                self._stop_runner()
                self.say(f"The server ended this session: {ended}")
                self.say("If revoked, request a new /hands setup invite. Otherwise reconnect locally with: "
                         + self.reconnect_command())
                return 1
            except ConnectionError as e:
                if time.time() >= self.expires:
                    break
                failures += 1
                if failures == 1:
                    self.say(f"Can't reach the server ({e}); retrying.")
                self._pause(min(30, 2 ** min(failures, 5)))  # a request to stop is not kept waiting
                continue
            if job:
                try:
                    self.handle(job)
                except _Stopped:
                    break
                except ConnectionError as e:
                    self.say(f"Couldn't reach the server to report a result ({e}); it is kept and sent when "
                             "the connection is back.")
                except HandsError as e:
                    self.say(f"Couldn't report a result: {e}")
        self._stop_runner()
        self._drain_results()  # commands are already stopped; only reporting may continue
        self.bye()
        self.say("Hands is down: the time window ended." if not self._stop else "Hands is down.")
        self.say("Commands and background processes have been stopped. This does not undo file changes.")
        self.say("To share again for a fresh time window, run locally: " + self.reconnect_command())
        return 0
