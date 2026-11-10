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


def _mac_profile(folder: str, tmp: str, readable: Sequence[str] = (), hidden: Sequence[str] = ()) -> str:
    """Refuse everything, then allow what a build or test run needs. Later rules win."""
    def q(path: str) -> str:
        return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'

    private = [*_private_paths(), *hidden]
    hidden_rule = " ".join(f"(subpath {q(p)})" for p in private)
    own = f"(subpath {q(folder)}) (subpath {q(tmp)})"
    extra = " ".join(f"(subpath {q(p)})" for p in readable)
    # Folders on the way to an allowed one stay visible by name (not listable), so
    # `mkdir -p` and path lookups work when the allowed folder sits under a hidden one.
    above = sorted({a for p in (folder, tmp, *readable) for a in _ancestors(p)
                    if any(a == h or a.startswith(h + os.sep) for h in private)})
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
        # The network stays on; other programs' local sockets do not.
        "(allow system-socket)", "(allow network-bind (local ip))", "(allow network-inbound (local ip))",
        "(allow network-outbound (remote ip))",
        '(allow network-outbound (literal "/private/var/run/mDNSResponder"))',
        "(allow file-read*)", f"(deny file-read* {hidden_rule})", f"(allow file-read* {own} {extra})",
        *([f"(allow file-read-metadata {on_the_way})"] if on_the_way else []),
        f"(allow file-write* {own}"
        ' (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper")'
        ' (regex #"^/dev/tty") (regex #"^/dev/fd/"))',
        '(allow file-ioctl (literal "/dev/null") (literal "/dev/dtracehelper") (regex #"^/dev/tty"))',
    ])


def _bwrap(folder: str, tmp: str, command: List[str], shared: bool = False,
           readable: Sequence[str] = (), hidden: Sequence[str] = ()) -> List[str]:
    # Its own process list: commands see and signal only what runs in the same sandbox, and
    # everything in it stops when it ends (for the shared one, when the device goes down).
    argv = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc",
            "--die-with-parent"]
    masked: List[str] = []
    for path in [*_private_paths(), *hidden]:
        path = os.path.realpath(path)  # bubblewrap cannot mount onto a path through a link
        if path in masked or path in (os.sep, os.path.realpath(os.path.expanduser("~"))):
            continue
        masked.append(path)
        if os.path.isdir(path):
            argv += ["--tmpfs", path]
        elif os.path.exists(path):
            argv += ["--ro-bind", "/dev/null", path]
    # The user's session sockets (the desktop bus, the service manager, agents) can start
    # programs outside the sandbox, so a command does not get them. Paths are resolved
    # first: bubblewrap cannot mount onto a path that goes through a symlink.
    runtime = os.path.realpath(f"/run/user/{os.getuid()}")
    if os.path.isdir(runtime):
        argv += ["--tmpfs", runtime]
    sockets = {os.path.realpath(p) for p in ("/run/docker.sock", "/var/run/docker.sock") if os.path.exists(p)}
    for socket_path in sorted(sockets):
        if not socket_path.startswith(runtime + os.sep):
            argv += ["--ro-bind", "/dev/null", socket_path]
    # Last, so the folder and the temp folder stay usable even under a hidden path.
    # /tmp is the device's own temp folder too.
    argv += ["--bind", tmp, "/tmp"]
    for path in readable:
        argv += ["--ro-bind", path, path]
    argv += ["--bind", folder, folder, "--bind", tmp, tmp]
    return argv + ["--chdir", folder, "--", *command]


_probe: List[Optional[str]] = []


def available() -> Optional[str]:
    """Which sandbox works here. bubblewrap is tried once: some systems install it but
    forbid the user namespaces it needs."""
    if not _probe:
        kind = None
        if sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec"):
            kind = "sandbox-exec"
        elif sys.platform.startswith("linux") and shutil.which("bwrap"):
            try:
                ok = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--", "true"], capture_output=True,
                                    timeout=10).returncode == 0
            except (OSError, subprocess.SubprocessError):
                ok = False
            kind = "bwrap" if ok else None
        _probe.append(kind)
    return _probe[0]


def wrap(folder: str, tmp: str, command: List[str], *, allow_unsandboxed: bool = False,
         shared: bool = False, readable: Sequence[str] = (), hidden: Sequence[str] = ()) -> List[str]:
    """`command` wrapped so it can write only under `folder` and its own temp folder `tmp`.
    `shared` marks the one long-lived sandbox a device runs its commands in. `readable`
    names folders that stay readable even under a hidden path (the Python that runs it);
    `hidden` names more folders a command must not read (the device's own state)."""
    kind = available()
    if kind == "sandbox-exec":
        return ["/usr/bin/sandbox-exec", "-p", _mac_profile(folder, tmp, readable, hidden), *command]
    if kind == "bwrap":
        return _bwrap(folder, tmp, command, shared, readable, hidden)
    if allow_unsandboxed:
        return command
    raise SandboxUnavailable(
        "no sandbox on this machine (macOS sandbox-exec or Linux bubblewrap). "
        "Install bubblewrap, or pass --no-sandbox to run commands with your full access.")
