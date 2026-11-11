"""Run a command so it can change only one folder.

macOS uses `sandbox-exec`, Linux uses bubblewrap. Anything else is refused unless the
person starting the device passes --no-sandbox: a command the server sends must never
get the whole machine because a tool was missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence

# Never readable by a command, wherever the folder is.
PRIVATE = (".ssh", ".aws", ".gnupg", ".config/gh", ".config/gcloud", ".azure", ".kube", ".docker/config.json",
           ".netrc", ".npmrc", ".pypirc", ".git-credentials", "Library/Keychains", ".hermes", ".hermes-tenuo",
           ".claude", ".claude.json", ".codex", ".config/op", ".password-store", ".tenuo", ".vault-token",
           ".terraform.d", ".cargo/credentials", ".cargo/credentials.toml", ".config/stripe",
           ".zsh_history", ".bash_history", ".Xauthority", ".ICEauthority", "Library/Cookies",
           "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
           "Library/Application Support/BraveSoftware", "Library/Application Support/Microsoft Edge",
           ".mozilla", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware")

# The only system services a command may reach on macOS: name lookups, logging, DNS and
# certificate checks. Everything else is refused, including the services that launch apps,
# send events to other apps, start background jobs, and hold the clipboard and keychain.
_MAC_SERVICES = (
    "com.apple.system.opendirectoryd.libinfo", "com.apple.system.opendirectoryd.membership",
    "com.apple.system.notification_center", "com.apple.system.logger", "com.apple.logd",
    "com.apple.diagnosticd", "com.apple.bsd.dirhelper", "com.apple.trustd", "com.apple.trustd.agent",
    "com.apple.ocspd", "com.apple.networkd", "com.apple.dnssd.service",
    "com.apple.SystemConfiguration.configd", "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.cfprefsd.daemon", "com.apple.cfprefsd.agent", "com.apple.FSEvents", "com.apple.sysmond",
)


class SandboxUnavailable(RuntimeError):
    pass


def _home() -> str:
    return os.path.realpath(os.path.expanduser("~"))


def _private_paths() -> List[str]:
    """Each protected path as named and as resolved: one that is a link to somewhere else
    is hidden at its real place too."""
    home = os.path.realpath(os.path.expanduser("~"))
    paths: List[str] = []
    for name in PRIVATE:
        named = os.path.join(home, name)
        for path in (named, os.path.realpath(named)):
            if path not in paths:
                paths.append(path)
    return paths


def _ancestors(path: str) -> List[str]:
    out, parent = [], os.path.dirname(path)
    while parent and parent != os.sep and parent not in out:
        out.append(parent)
        parent = os.path.dirname(parent)
    return out


def _mac_profile(folder: str, tmp: str, readable: Sequence[str] = (), hidden: Sequence[str] = (),
                 writable: bool = True, home_visible: bool = True, tools: Sequence[str] = (),
                 network: bool = False, excluded: Sequence[str] = ()) -> str:
    """Refuse everything, then allow what a build or test run needs. Later rules win."""
    def q(path: str) -> str:
        return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'

    private = [*_private_paths(), *hidden]
    hidden_rule = " ".join(f"(subpath {q(p)})" for p in private)
    own = f"(subpath {q(folder)}) (subpath {q(tmp)})"
    may_change = own if writable else f"(subpath {q(tmp)})"  # look, don't touch: only its temp folder
    extra = " ".join(f"(subpath {q(p)})" for p in readable)
    # With the home folder hidden, only `tools` (toolchains and folders the person named)
    # stay readable in it. The protected paths are refused after that, so one inside a
    # tool folder stays hidden.
    home = _home()
    closed = [] if home_visible else [home]
    home_rule = [f"(deny file-read* (subpath {q(home)}))"] if closed else []
    tool_rule = [f"(allow file-read* {' '.join(f'(subpath {q(p)})' for p in tools)})"] if tools else []
    # Folders on the way to an allowed one stay visible by name (not listable), so
    # `mkdir -p` and path lookups work when the allowed folder sits under a hidden one.
    above = sorted({a for p in (folder, tmp, *readable, *tools) for a in _ancestors(p)
                    if any(a == h or a.startswith(h + os.sep) for h in [*private, *closed])})
    on_the_way = " ".join(f"(literal {q(a)})" for a in above)
    services = " ".join(f'(global-name "{name}")' for name in _MAC_SERVICES)
    return "\n".join([
        "(version 1)", "(deny default)",
        "(allow process-fork)", "(allow process-exec)",
        # A command may signal and inspect only processes started through Hands.
        "(allow signal (target same-sandbox))", "(allow process-info* (target same-sandbox))",
        "(allow process-info-pidinfo)", "(allow process-info-setcontrol (target self))",
        "(allow sysctl-read)", "(allow user-preference-read)",
        "(allow ipc-posix-sem)", "(allow ipc-posix-shm*)", "(allow pseudo-tty)",
        '(allow iokit-open (iokit-registry-entry-class "RootDomainUserClient"))',
        f"(allow mach-lookup {services})",
        # Without `network`, commands reach this machine only: a dev server and what talks
        # to it work, the internet and name lookups do not. With it, the network is on.
        # Other programs' local sockets are out of reach either way.
        "(allow system-socket)", "(allow network-bind (local ip))",
        *(["(allow network-inbound (local ip))", "(allow network-outbound (remote ip))",
           '(allow network-outbound (literal "/private/var/run/mDNSResponder"))'] if network else
          ['(allow network-inbound (local ip "localhost:*"))', '(allow network-outbound (remote ip "localhost:*"))']),
        "(allow file-read*)", *home_rule, *tool_rule,
        f"(deny file-read* {hidden_rule})", f"(allow file-read* {own} {extra})",
        *([f"(allow file-read-metadata {on_the_way})"] if on_the_way else []),
        f"(allow file-write* {may_change}"
        ' (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper")'
        ' (regex #"^/dev/tty") (regex #"^/dev/fd/"))',
        *[f"(deny file-read* file-write* (subpath {q(p)}))" for p in excluded],
        *[f"(deny file-write-unlink (literal {q(p)}))"
          for p in sorted({a for path in excluded for a in _ancestors(path)})],
        '(allow file-ioctl (literal "/dev/null") (literal "/dev/dtracehelper") (regex #"^/dev/tty"))',
    ])


def _bwrap(folder: str, tmp: str, command: List[str], shared: bool = False,
           readable: Sequence[str] = (), hidden: Sequence[str] = (), writable: bool = True,
           home_visible: bool = True, tools: Sequence[str] = (), network: bool = False, excluded: Sequence[str] = ()) -> List[str]:
    # Its own process list: commands see and signal only what runs in the same sandbox, and
    # everything in it stops when it ends (for the shared one, when the device goes down).
    argv = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc",
            "--die-with-parent"]
    if not network:
        # A private network namespace also hides abstract Unix sockets, which cannot be
        # masked with filesystem mounts. Commands have loopback only; the device keeps
        # its host network connection outside the sandbox. With `network` they share the
        # machine's network, and newer kernels still keep them from those sockets.
        argv += ["--unshare-net"]
    emptied: List[str] = []  # folders shown empty; made read-only at the end, once what goes inside is in place
    if not home_visible:
        argv += ["--tmpfs", _home()]  # an empty home folder; what commands need from it is put back below
        emptied.append(_home())
    masked: List[str] = []
    for path in [*_private_paths(), *hidden]:
        path = os.path.realpath(path)  # bubblewrap cannot mount onto a path through a link
        if path in masked or path in (os.sep, os.path.realpath(os.path.expanduser("~"))):
            continue
        masked.append(path)
        if os.path.isdir(path):
            argv += ["--tmpfs", path]
            emptied.append(path)
        elif os.path.exists(path):
            argv += ["--ro-bind", "/dev/null", path]
    # The user's session sockets (the desktop bus, the service manager, agents) can start
    # programs outside the sandbox, so a command does not get them. Paths are resolved
    # first: bubblewrap cannot mount onto a path that goes through a symlink.
    runtime = _runtime_dir()
    if os.path.isdir(runtime):
        argv += ["--tmpfs", runtime]
        emptied.append(runtime)
    sockets = {os.path.realpath(p) for p in ("/run/docker.sock", "/var/run/docker.sock") if os.path.exists(p)}
    for socket_path in sorted(sockets):
        if not socket_path.startswith(runtime + os.sep):
            argv += ["--ro-bind", "/dev/null", socket_path]
    # Last, so the folder and the temp folder stay usable even under a hidden path.
    # /tmp is the device's own temp folder too.
    argv += ["--bind", tmp, "/tmp"]
    if not home_visible:
        # The toolchains and the folders the person named, read-only. A protected path
        # inside one of them is masked again, since putting the folder back uncovered it.
        for path in tools:
            argv += ["--ro-bind", path, path]
        for path in masked:
            if any(path.startswith(tool.rstrip(os.sep) + os.sep) for tool in tools):
                if os.path.isdir(path):
                    argv += ["--tmpfs", path]
                    emptied.append(path)
                elif os.path.exists(path):
                    argv += ["--ro-bind", "/dev/null", path]
    for path in readable:
        argv += ["--ro-bind", path, path]
    argv += ["--bind" if writable else "--ro-bind", folder, folder, "--bind", tmp, tmp]
    # An emptied folder is not a place to write: a write there would seem to work and be
    # lost when the sandbox ends. What was put back inside it keeps its own setting.
    shared_tmp = os.path.realpath("/tmp")
    for path in emptied:
        # One under /tmp is no longer there to change: the temp folder took /tmp's place.
        if path != shared_tmp and not path.startswith(shared_tmp + os.sep):
            argv += ["--remount-ro", path]
    # Make writable ancestors mount points too: otherwise Linux allows renaming
    # a parent of a masked directory, unlike Seatbelt's unlink denial.
    parents = sorted({a for p in excluded for a in _ancestors(os.path.realpath(p))
                      if a.startswith(folder.rstrip(os.sep) + os.sep)})
    for path in parents:
        argv += ["--bind" if writable else "--ro-bind", path, path]
    # Apply exclusions last. An excluded directory already covers descendants;
    # mounting a second mask inside that empty read-only directory would fail.
    roots: List[str] = []
    for path in sorted(set(os.path.realpath(p) for p in excluded)):
        if not any(path.startswith(root.rstrip(os.sep) + os.sep) for root in roots):
            roots.append(path)
    for path in roots:
        if not os.path.exists(path):
            raise SandboxUnavailable(f"never-share path disappeared: {path}")
        if os.path.isdir(path):
            argv += ["--tmpfs", path, "--remount-ro", path]
        else:
            argv += ["--ro-bind", "/dev/null", path]
    return argv + ["--chdir", folder, "--", *command]


def scopes_sockets() -> bool:
    """True if this Linux kernel can keep commands from other programs' named local
    sockets (Landlock, 6.12 and later). Asking changes nothing."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        return libc.syscall(ctypes.c_long(444), None, ctypes.c_size_t(0), ctypes.c_uint32(1)) >= 6
    except Exception:
        return False


_probe: List[Optional[str]] = []
_refusal: List[str] = []  # what bubblewrap said when the system would not let it start


def why_not() -> str:
    """Why this machine has no sandbox, for the person at it. Empty if it has one."""
    if available() is not None:
        return ""
    if sys.platform.startswith("linux"):
        if not shutil.which("bwrap"):
            return "bubblewrap is not installed (on Debian and Ubuntu: sudo apt install bubblewrap)"
        said = f" ({_refusal[0]})" if _refusal and _refusal[0] else ""
        return ("bubblewrap is installed, but this system does not let it start a sandbox for your user" + said
                + ". Ubuntu 24.04 and later need one rule that allows it: see \"Hands on Ubuntu\" in the README")
    return "this system has no sandbox Hands can use (macOS sandbox-exec or Linux bubblewrap)"


def available() -> Optional[str]:
    """Which sandbox works here. bubblewrap is tried once: some systems install it but
    forbid the user namespaces it needs."""
    if not _probe:
        kind = None
        if sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec"):
            kind = "sandbox-exec"
        elif sys.platform.startswith("linux") and shutil.which("bwrap"):
            try:
                tried = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-pid", "--unshare-net", "--", "true"],
                                       capture_output=True, text=True, timeout=10)
                ok = tried.returncode == 0
                if not ok:
                    _refusal.append((tried.stderr or "").strip().splitlines()[-1][:200] if tried.stderr.strip() else "")
            except (OSError, subprocess.SubprocessError):
                ok = False
            kind = "bwrap" if ok else None
        _probe.append(kind)
    return _probe[0]


def _runtime_dir() -> str:
    return os.path.realpath(f"/run/user/{os.getuid()}")


def socket_overlap(path: str) -> bool:
    """An extra read mount must not restore a masked host service or its parent."""
    if not sys.platform.startswith("linux"):
        return False
    real = os.path.realpath(path)
    masks = (_runtime_dir(), "/run/docker.sock", "/var/run/docker.sock")
    return any(real == mask or real.startswith(mask.rstrip(os.sep) + os.sep)
               or mask.startswith(real.rstrip(os.sep) + os.sep)
               for mask in map(os.path.realpath, masks))


def protected(path: str, hidden: Sequence[str] = ()) -> bool:
    """True if `path` is one of the protected paths or inside one (or inside `hidden`)."""
    real = os.path.realpath(path)
    return any(real == p or real.startswith(p.rstrip(os.sep) + os.sep)
               for p in [os.path.realpath(q) for q in (*_private_paths(), *hidden)])


def wrap(folder: str, tmp: str, command: List[str], *, allow_unsandboxed: bool = False,
         shared: bool = False, readable: Sequence[str] = (), hidden: Sequence[str] = (),
         writable: bool = True, home_visible: bool = True, tools: Sequence[str] = (),
         network: bool = False, excluded: Sequence[str] = ()) -> List[str]:
    """`command` wrapped so it can write only under `folder` and its own temp folder `tmp`.
    `shared` marks the one long-lived sandbox a device runs its commands in. `readable`
    names folders that stay readable even under a hidden path (the Python that runs it);
    `hidden` names more folders a command must not read (the device's own state). With
    `writable` off the command can read `folder` and change only its temp folder. With
    `home_visible` off the home folder cannot be read at all, except `tools`: real folders
    in it that hold toolchains, or that the person chose to show. Without `network` the
    command has no internet: on Linux a network of its own, on macOS this machine only."""
    # A folder to show that is itself protected, or inside something protected, is not
    # shown: putting it back would uncover exactly what is hidden on purpose.
    tools = [path for path in tools if not protected(path, hidden) and not socket_overlap(path)]
    kind = available()
    if kind == "sandbox-exec":
        return ["/usr/bin/sandbox-exec", "-p",
                _mac_profile(folder, tmp, readable, hidden, writable, home_visible, tools, network, excluded), *command]
    if kind == "bwrap":
        if network and not scopes_sockets():
            raise SandboxUnavailable("--network needs Landlock ABI 6 or later to isolate host abstract sockets. "
                                     "Enable Landlock on a supported Linux kernel, or omit --network.")
        return _bwrap(folder, tmp, command, shared, readable, hidden, writable, home_visible, tools, network, excluded)
    if allow_unsandboxed:
        if not writable:
            raise SandboxUnavailable("--read-only needs a sandbox to hold commands to it; this machine has none")
        return command
    raise SandboxUnavailable(f"no sandbox on this machine: {why_not()}. "
                             "Or pass --no-sandbox to run commands with your full access.")
