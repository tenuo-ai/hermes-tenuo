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
from typing import Dict, List, Optional, Sequence, Tuple

# Keys whose value git runs.
_RUNS = frozenset({
    "core.fsmonitor", "core.sshcommand", "core.pager", "core.editor", "core.askpass",
    "core.gitproxy", "core.alternaterefscommand", "diff.external", "sequence.editor",
    "interactive.difffilter", "credential.helper", "uploadpack.packobjectshook",
})
_RUNS_IN = {  # section → keys git runs, with or without a subsection
    "filter": {"clean", "smudge", "process"}, "diff": {"textconv", "command"},
    "merge": {"driver"}, "mergetool": {"cmd"}, "difftool": {"cmd"}, "credential": {"helper"},
    "gpg": {"program"}, "browser": {"cmd"}, "man": {"cmd"}, "trailer": {"command", "cmd"},
    "remote": {"uploadpack", "receivepack", "vcs"},
}
_HELPER_URL = re.compile(r"^\s*[A-Za-z0-9+.-]+::")   # ext::command, or any other remote helper


def _runs(section: str, sub: str, key: str, value: str) -> bool:
    """Whether git runs this setting's value as a program, now or on a later command."""
    if f"{section}.{key}" in _RUNS or key in _RUNS_IN.get(section, ()) or section == "pager":
        return True
    if section in ("alias", "submodule") and (section == "alias" or key == "update"):
        return value.lstrip().startswith("!")
    if section == "remote" and key in ("url", "pushurl"):
        return bool(_HELPER_URL.match(value))
    if section == "url" and key in ("insteadof", "pushinsteadof"):
        return bool(_HELPER_URL.match(sub))
    if section == "sendemail":
        return key.endswith("cmd") or (key == "smtpserver" and value.lstrip().startswith("/"))
    return False


_SECTION = re.compile(r'^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(.*)$')
_ENTRY = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$", re.S)
_LIMIT = 1 << 20      # bytes read from one settings file
_FILES = 8            # settings files followed through includes
_HOOK_FOLDERS = 16    # hooks folders looked at
_HOOK_BYTES = 4 << 20  # hook programs read in one look, in total
# The file names git runs from a hooks folder. Anything else there is not a hook.
_HOOK_NAMES = (
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
    "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
    "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist",
    "p4-pre-submit", "post-index-change",
)
_UNCHECKED = "cannot be checked"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _locate(roots: List[Tuple[str, int, str]], path: str, origin: int, base: str) -> Optional[Tuple[int, str]]:
    """Which writable folder *path* is in, and where: (index into *roots*, relative path).

    *path* is as git reads it from a file in folder *base* of root *origin*. None when it
    is in none of them, where commands cannot change it.
    """
    if not path or path.startswith("~"):
        return None
    full = os.path.normpath(path if os.path.isabs(path) else os.path.join(roots[origin][0], base, path))
    # As written first; then with links resolved, since the same place can be spelled two
    # ways (/tmp and /private/tmp). Either way it is opened from the root without following links.
    for candidate in (full, os.path.realpath(full)):
        for index, (root, _fd, _label) in enumerate(roots):
            for spelling in {root, os.path.realpath(root)}:
                if candidate == spelling or candidate.startswith(spelling + os.sep):
                    return index, os.path.relpath(candidate, spelling)
    # Last, by what the folders are rather than how they are spelled: another letter case
    # on a case-insensitive disk, or a second name the system gives the same folder.
    try:
        known = {(info.st_dev, info.st_ino): index
                 for index, info in ((i, os.fstat(fd)) for i, (_root, fd, _label) in enumerate(roots))}
    except OSError:
        return None
    above, below = full, []
    for _ in range(64):
        try:
            info = os.stat(above)
        except OSError:
            info = None
        if info is not None and (info.st_dev, info.st_ino) in known:
            return known[(info.st_dev, info.st_ino)], os.path.join(*reversed(below)) if below else "."
        parent, name = os.path.split(above)
        if not name or parent == above:
            return None
        above, below = parent, below + [name]
    return None


def _open(folder_fd: int, relative: str, directory: bool) -> int:
    """Open *relative* under the folder without following a link at any step, or raise OSError."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    parts = [p for p in relative.split(os.sep) if p not in ("", ".")]
    if ".." in parts or (not parts and not directory):
        raise OSError("not a path inside the folder")
    fd = os.dup(folder_fd)          # with no parts left, the folder itself
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


def _value(raw: str) -> str:
    """A setting's value as git reads it: quotes and escapes decoded, a comment dropped."""
    out: List[str] = []
    quoted, keep, i = False, 0, 0   # keep: how much of `out` survives trimming trailing spaces
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            out.append({"n": "\n", "t": "\t", "b": "\b"}.get(raw[i + 1], raw[i + 1]))
            i, keep = i + 2, len(out)
            continue
        if ch == '"':
            quoted, i, keep = not quoted, i + 1, len(out)
            continue
        if not quoted and ch in "#;":
            break
        out.append(ch)
        if quoted or not ch.isspace():
            keep = len(out)
        i += 1
    return "".join(out[:keep])


def _entries(text: str) -> List[Tuple[str, str, str, str]]:
    """(section, subsection, key, value) for each setting in a config file's text."""
    found: List[Tuple[str, str, str, str]] = []
    section = sub = ""
    for line in _logical_lines(text.lstrip("\ufeff")):
        header = _SECTION.match(line)
        if header:
            section, sub, line = header.group(1).lower(), header.group(2) or "", header.group(3)
            if "." in section and not sub:      # the older spelling: [section.subsection]
                section, sub = section.split(".", 1)
        entry = _ENTRY.match(line)
        if entry and section:
            found.append((section, sub, entry.group(1).lower(), _value(entry.group(2) or "")))
    return found


def _hook_mark(fd: int, name: str, budget: List[int]) -> Optional[str]:
    """A fingerprint of one hook's program and mode, or None if it cannot be read safely."""
    try:
        hook = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
    except OSError:
        return None
    try:
        info = os.fstat(hook)
        if not stat.S_ISREG(info.st_mode) or info.st_size > budget[0]:
            return None
        digest, left = hashlib.sha256(), info.st_size + 1
        while left > 0:
            chunk = os.read(hook, min(65536, left))
            if not chunk:
                break
            digest.update(chunk)
            left -= len(chunk)
        if left <= 0:
            return None                      # it grew while being read
        budget[0] -= info.st_size
        return f"{stat.S_IMODE(info.st_mode):o}:{digest.hexdigest()[:16]}"
    except OSError:
        return None
    finally:
        os.close(hook)


def _hooks(folder_fd: int, relative: str, label: str, found: Dict[str, str], budget: List[int]) -> None:
    """Fingerprint the hooks in one folder. Only the names git runs are looked at, so a
    hooks folder that is the project itself costs no more than any other."""
    try:
        fd = _open(folder_fd, relative, directory=True)
    except FileNotFoundError:
        return
    except OSError:
        found[f"{label} ({_UNCHECKED})"] = "unchecked"
        return
    try:
        for name in _HOOK_NAMES:
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                found[f"{label}/{name} ({_UNCHECKED})"] = "unchecked"
                continue
            mark = _hook_mark(fd, name, budget)
            if mark is not None:
                found[f"{label}/{name}"] = mark
            else:
                # A link, a pipe, a folder or something too large: say so, and still
                # notice when it is replaced.
                found[f"{label}/{name} ({_UNCHECKED})"] = (
                    f"{info.st_mode}:{info.st_size}:{info.st_mtime_ns}:{info.st_ino}")
    finally:
        os.close(fd)


def _path_label(roots: List[Tuple[str, int, str]], index: int, relative: str) -> str:
    return relative if not roots[index][2] else os.path.join(roots[index][2], relative)


def _git_dirs(roots: List[Tuple[str, int, str]], kind: int,
              found: Dict[str, str]) -> List[Tuple[int, str]]:
    """Repository metadata in any writable root, including the commands' temp folder."""
    if stat.S_ISDIR(kind):
        dirs = [(0, ".git")]
    elif stat.S_ISREG(kind):
        try:
            text = _read(roots[0][1], ".git") or ""
        except OSError:
            found[f".git ({_UNCHECKED})"] = "unchecked"
            return []
        # Retargeting metadata is itself worth reporting, even when the new
        # target is outside the roots we can inspect or contains no run settings.
        found[".git pointer"] = _digest(text)
        pointer = re.match(r"gitdir:[ \t]*(.+)", text.strip())
        target = _locate(roots, pointer.group(1).strip(), 0, "") if pointer else None
        if target is None:
            found[f".git ({_UNCHECKED})"] = _digest(text)
            return []
        dirs = [target]
    else:
        found[f".git ({_UNCHECKED})"] = "unchecked"
        return []
    for index, gitdir in list(dirs):
        name = os.path.join(gitdir, "commondir")
        shown = _path_label(roots, index, name)
        try:
            common = _read(roots[index][1], name)
        except OSError:
            found[f"{shown} ({_UNCHECKED})"] = "unchecked"
            continue
        if common is None:
            continue
        found[shown] = _digest(common)
        target = _locate(roots, common.strip(), index, gitdir)
        if target is None:
            found[f"{shown} ({_UNCHECKED})"] = _digest(common)
        elif target not in dirs:
            dirs.append(target)
    return dirs


def settings(folder: str, also: Sequence[str] = ()) -> Dict[str, str]:
    """What in *folder*'s own repository makes git run a program: name → fingerprint.

    Follows the repository's settings into the files they include and the hooks folders
    they name, wherever commands can write: inside *folder*, and inside the folders in
    *also* (the commands' temp folder). A setting that pulls in a file is itself recorded,
    so one that points anywhere else is still seen when it is added or changed.
    """
    found: Dict[str, str] = {}
    if not hasattr(os, "O_NOFOLLOW"):
        return found
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    try:
        # The folder itself must not be a link either: everything is read relative to it.
        folder_fd = os.open(folder, flags | os.O_NOFOLLOW)
    except FileNotFoundError:
        return found
    except OSError:
        return {f"the shared folder ({_UNCHECKED})": "unchecked"}
    roots: List[Tuple[str, int, str]] = [(os.path.normpath(folder), folder_fd, "")]
    try:
        try:
            kind = os.stat(".git", dir_fd=folder_fd, follow_symlinks=False).st_mode
        except OSError:
            return found      # no repository here
        for extra in also:
            try:
                roots.append((os.path.normpath(extra), os.open(extra, flags | os.O_NOFOLLOW), "temp folder"))
            except FileNotFoundError:
                continue      # not there (yet): nothing in it to read
            except OSError:
                found[f"temp folder ({_UNCHECKED})"] = "unchecked"   # a link, or not a folder

        def label(index: int, relative: str) -> str:
            return _path_label(roots, index, relative)

        git_dirs = _git_dirs(roots, kind, found)
        # Each of the repository's folders may hold shared and per-worktree settings.
        queue = [(index, os.path.join(gitdir, name)) for index, gitdir in git_dirs for name in ("config", "config.worktree")]
        seen: set = set()
        hook_folders: List[Tuple[int, str]] = []
        while queue:
            index, relative = queue.pop(0)
            if (index, relative) in seen:
                continue
            seen.add((index, relative))
            if len(seen) > _FILES + 2 * len(git_dirs):
                found[f"more included settings files ({_UNCHECKED})"] = "unchecked"
                break
            try:
                text = _read(roots[index][1], relative)
            except OSError:
                found[f"{label(index, relative)} ({_UNCHECKED})"] = "unchecked"
                continue
            if text is None:
                continue
            for section, sub, key, value in _entries(text):
                name = ".".join(part for part in (section, sub, key) if part)
                if (section, key) in (("include", "path"), ("includeif", "path")):
                    found[name] = _digest(found.get(name, "") + value)
                    target = _locate(roots, value, index, os.path.dirname(relative))
                    if target is not None and target[1] != ".":
                        queue.append(target)
                elif (section, key) == ("core", "hookspath"):
                    found[name] = _digest(found.get(name, "") + value)
                    target = _locate(roots, value, 0, "")
                    if target is not None and target not in hook_folders:
                        hook_folders.append(target)   # "." is the folder itself
                elif _runs(section, sub, key, value):
                    found[name] = _digest(found.get(name, "") + value)
        budget = [_HOOK_BYTES]
        for index, gitdir in git_dirs:
            hooks = os.path.join(gitdir, "hooks")
            shown = "hooks" if (index, gitdir) == (0, ".git") else label(index, hooks)
            _hooks(roots[index][1], hooks, shown, found, budget)
        # Git uses the last hooks path it reads; every one named is looked at, so the
        # order files were read in here cannot hide the one in effect.
        for index, relative in hook_folders[:_HOOK_FOLDERS]:
            where = "hooks in the shared folder" if (index, relative) == (0, ".") else label(index, relative)
            _hooks(roots[index][1], relative, where, found, budget)
        if len(hook_folders) > _HOOK_FOLDERS:
            found[f"more hooks folders ({_UNCHECKED})"] = "unchecked"
        return found
    finally:
        for _root, fd, _label in roots:
            os.close(fd)


def changed(before: Dict[str, str], after: Dict[str, str]) -> List[str]:
    """Names that are new or different in *after*."""
    return sorted(name for name, mark in after.items() if before.get(name) != mark)
