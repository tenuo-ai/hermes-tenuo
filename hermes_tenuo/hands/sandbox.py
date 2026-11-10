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
from typing import List, Optional

# Never readable by a command, wherever the folder is.
PRIVATE = (".ssh", ".aws", ".gnupg", ".config/gh", ".config/gcloud", ".azure", ".kube", ".docker/config.json",
           ".netrc", ".npmrc", ".pypirc", ".git-credentials", "Library/Keychains", ".hermes", ".hermes-tenuo",
           ".claude", ".codex", ".config/op", ".password-store")


class SandboxUnavailable(RuntimeError):
    pass


def _private_paths() -> List[str]:
    home = os.path.realpath(os.path.expanduser("~"))
    return [os.path.join(home, p) for p in PRIVATE]


def _mac_profile(folder: str, tmp: str) -> str:
    def q(path: str) -> str:
        return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'

    hidden = " ".join(f"(subpath {q(p)})" for p in _private_paths() if not folder.startswith(p))
    return "\n".join([
        "(version 1)", "(allow default)",
        *([f"(deny file-read* {hidden})"] if hidden else []),
        '(deny file-write* (subpath "/"))',
        f"(allow file-write* (subpath {q(folder)}) (subpath {q(tmp)})"
        ' (regex #"^/private/tmp/hermes-") (literal "/dev/null") (literal "/dev/zero")'
        ' (literal "/dev/dtracehelper") (regex #"^/dev/tty") (regex #"^/dev/fd/"))',
    ])


def _bwrap(folder: str, tmp: str, command: List[str]) -> List[str]:
    # /tmp is the device's own temp folder, so Hermes's session files there last between commands.
    argv = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--bind", tmp, "/tmp",
            "--bind", folder, folder, "--bind", tmp, tmp, "--die-with-parent"]
    for path in _private_paths():
        if os.path.isdir(path):
            argv += ["--tmpfs", path]
        elif os.path.exists(path):
            argv += ["--ro-bind", "/dev/null", path]
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


def wrap(folder: str, tmp: str, command: List[str], *, allow_unsandboxed: bool = False) -> List[str]:
    """`command` wrapped so it can write only under `folder` and its own temp folder `tmp`."""
    kind = available()
    if kind == "sandbox-exec":
        return ["/usr/bin/sandbox-exec", "-p", _mac_profile(folder, tmp), *command]
    if kind == "bwrap":
        return _bwrap(folder, tmp, command)
    if allow_unsandboxed:
        return command
    raise SandboxUnavailable(
        "no sandbox on this machine (macOS sandbox-exec or Linux bubblewrap). "
        "Install bubblewrap, or pass --no-sandbox to run commands with your full access.")
