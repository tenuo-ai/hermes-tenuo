"""Git settings in a shared folder that make git run programs.

Commands may change the shared folder, and that includes its repository's own
settings. Git runs some of those as programs (hooks, a file-system monitor, a
pager, an alias), and runs them for whoever uses git there next: the person,
their editor or their shell prompt, outside the sandbox. Refusing the writes
would also refuse ``git init`` and ``git remote add``, so the device reports
them to the person instead.

Everything read here was written by commands, so nothing is trusted: paths are
walked one component at a time without following links, only regular files are
read, never more than a fixed size, and never in a way that can block. What
cannot be read that way is reported instead of skipped.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from typing import Dict, List, Optional, Tuple

# Keys whose value git runs.
_RUNS = frozenset({
    "core.fsmonitor", "core.sshcommand", "core.pager", "core.editor", "core.askpass",
    "core.gitproxy", "diff.external", "sequence.editor", "gpg.program",
    "credential.helper", "uploadpack.packobjectshook",
})
_RUNS_IN = {  # section → keys git runs, for any subsection
    "filter": {"clean", "smudge", "process"}, "diff": {"textconv", "command"},
    "merge": {"driver"}, "mergetool": {"cmd"}, "difftool": {"cmd"}, "credential": {"helper"},
}
_SECTION = re.compile(r'^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(.*)$')
_ENTRY = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$", re.S)
_LIMIT = 1 << 20      # bytes read from one settings file
_FILES = 8            # settings files followed through includes
_ENTRIES = 200        # entries looked at in one hooks folder
_UNCHECKED = "cannot be checked"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _inside(folder: str, path: str, base: str) -> Optional[str]:
    """*path* (as git reads it from a file in *base*) relative to *folder*, or None if outside."""
    if path.startswith("~"):
        return None
    full = os.path.normpath(path if os.path.isabs(path) else os.path.join(folder, base, path))
    root = os.path.normpath(folder)
    if full != root and not full.startswith(root + os.sep):
        return None
    return os.path.relpath(full, root)


def _open(folder_fd: int, relative: str, directory: bool) -> int:
    """Open *relative* under the folder without following a link at any step, or raise OSError."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    parts = [p for p in relative.split(os.sep) if p not in ("", ".")]
    if not parts or ".." in parts:
        raise OSError("not a path inside the folder")
    fd = os.dup(folder_fd)
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            step = os.open(part, flags | (os.O_DIRECTORY if directory or not last else 0), dir_fd=fd)
            os.close(fd)
            fd = step
        if not directory and not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(folder_fd: int, relative: str) -> Optional[str]:
    """The text of a regular file under the folder; None if it is absent. Raises OSError otherwise."""
    try:
        fd = _open(folder_fd, relative, directory=False)
    except FileNotFoundError:
        return None
    try:
        data = b""
        while len(data) <= _LIMIT:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
        if len(data) > _LIMIT:
            raise OSError("too large")
        return data.decode("utf-8", "replace")
    finally:
        os.close(fd)


def _logical_lines(text: str) -> List[str]:
    """Lines as git reads them: one ending in a backslash continues on the next."""
    out: List[str] = []
    pending = ""
    for line in text.splitlines():
        stripped = line.rstrip("\r")
        trailing = len(stripped) - len(stripped.rstrip("\\"))
        if trailing % 2:
            pending += stripped[:-1]
            continue
        out.append(pending + stripped)
        pending = ""
    if pending:
        out.append(pending)
    return out


def _entries(text: str) -> List[Tuple[str, str, str, str]]:
    """(section, subsection, key, value) for each setting in a config file's text."""
    found: List[Tuple[str, str, str, str]] = []
    section = sub = ""
    for line in _logical_lines(text):
        header = _SECTION.match(line)
        if header:
            section, sub, line = header.group(1).lower(), header.group(2) or "", header.group(3)
        entry = _ENTRY.match(line)
        if entry and section:
            found.append((section, sub, entry.group(1).lower(), (entry.group(2) or "").strip()))
    return found


def _hooks(folder_fd: int, relative: str, label: str, found: Dict[str, str]) -> None:
    try:
        fd = _open(folder_fd, relative, directory=True)
    except FileNotFoundError:
        return
    except OSError:
        found[f"{label} ({_UNCHECKED})"] = "unchecked"
        return
    try:
        with os.scandir(fd) as listing:
            for count, entry in enumerate(listing):
                if count >= _ENTRIES:
                    found[f"{label} (more than {_ENTRIES} files, {_UNCHECKED})"] = "unchecked"
                    break
                if entry.name.endswith(".sample"):
                    continue
                try:
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                except OSError:
                    continue
                found[f"{label}/{entry.name}"] = f"{info.st_size}:{info.st_mtime_ns}:{info.st_mode}:{info.st_ino}"
    except OSError:
        found[f"{label} ({_UNCHECKED})"] = "unchecked"
    finally:
        os.close(fd)


def settings(folder: str) -> Dict[str, str]:
    """What in *folder*'s own repository makes git run a program: name → fingerprint.

    Follows the repository's settings into files they include and a hooks folder they
    name, where those are inside *folder* (commands cannot change anything outside it).
    """
    found: Dict[str, str] = {}
    if not hasattr(os, "O_NOFOLLOW"):
        return found
    try:
        kind = os.lstat(os.path.join(folder, ".git")).st_mode
        folder_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return found          # no repository here
    try:
        if stat.S_ISREG(kind):
            return found      # a worktree's pointer: its settings live outside the folder
        if not stat.S_ISDIR(kind):
            return {f".git ({_UNCHECKED})": "unchecked"}
        queue, seen, hook_folders = [os.path.join(".git", "config")], set(), []
        while queue:
            relative = queue.pop(0)
            if relative in seen:
                continue
            seen.add(relative)
            if len(seen) > _FILES:
                found[f"more included settings files ({_UNCHECKED})"] = "unchecked"
                break
            try:
                text = _read(folder_fd, relative)
            except OSError:
                found[f"{relative} ({_UNCHECKED})"] = "unchecked"
                continue
            if text is None:
                continue
            for section, sub, key, value in _entries(text):
                name = ".".join(part for part in (section, sub, key) if part)
                if (section, key) in (("include", "path"), ("includeif", "path")):
                    target = _inside(folder, value.strip('"'), os.path.dirname(relative))
                    if target is not None:
                        queue.append(target)
                elif (section, key) == ("core", "hookspath"):
                    found[name] = _digest(found.get(name, "") + value)
                    target = _inside(folder, value.strip('"'), "")
                    if target is not None:
                        hook_folders.append(target)
                elif (f"{section}.{key}" in _RUNS or key in _RUNS_IN.get(section, ())
                        or section == "pager" or (section == "alias" and value.lstrip('" ').startswith("!"))):
                    found[name] = _digest(found.get(name, "") + value)
        _hooks(folder_fd, os.path.join(".git", "hooks"), "hooks", found)
        for target in hook_folders[:4]:
            _hooks(folder_fd, target, target, found)
        return found
    finally:
        os.close(folder_fd)


def changed(before: Dict[str, str], after: Dict[str, str]) -> List[str]:
    """Names that are new or different in *after*."""
    return sorted(name for name, mark in after.items() if before.get(name) != mark)
