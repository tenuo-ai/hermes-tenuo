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
    if path.startswith("~"):
        # Git expands this for whoever runs it; that is the person at this machine, and
        # the shared folder is usually somewhere under their home folder.
        path = os.path.expanduser(path)
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
        return _text(fd)
    finally:
        os.close(fd)


def _text(fd: int) -> str:
    data = b""
    while len(data) <= _LIMIT:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        data += chunk
    if len(data) > _LIMIT:
        raise OSError("too large")
    return data.decode("utf-8", "replace")


def _read_outside(path: str) -> Optional[str]:
    """The text of a regular file commands cannot write; None if it is absent. Raises OSError otherwise."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except (FileNotFoundError, NotADirectoryError):
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        if info.st_nlink > 1:
            raise OSError("outside settings may have a writable hard-link alias")
        return _text(fd)
    finally:
        os.close(fd)


def _full(value: str, base: str) -> str:
    """A path from a settings file in folder *base*, as git reads it; empty if it cannot be told."""
    path = os.path.expanduser(value) if value.startswith("~") else value
    if not path or path.startswith("~"):
        return ""
    return os.path.normpath(path if os.path.isabs(path) else os.path.join(base, path))


def _through_a_root(roots: List[Tuple[str, int, str]], path: str) -> bool:
    """Detect writable links in any component, including links reached via outside aliases."""
    pending = os.path.abspath(path).split(os.sep)
    current, links = os.sep, 0
    while pending:
        part = pending.pop(0)
        if not part or part == ".":
            continue
        current = os.path.normpath(os.path.join(current, part))
        if _locate(roots, current, 0, "") is not None:
            return True
        if os.path.islink(current):
            links += 1
            if links > 40:
                return True
            target = os.readlink(current)
            target = target if os.path.isabs(target) else os.path.join(os.path.dirname(current), target)
            pending = target.split(os.sep) + pending
            current = os.sep
    return False


def _spelled(value: str, base: str) -> str:
    """A path from a settings file in folder *base*, as git hands it to the system: `..`
    is left for the system to take from where the path really is. Empty if it cannot be told."""
    path = os.path.expanduser(value) if value.startswith("~") else value
    if not path or path.startswith("~"):
        return ""
    return path if os.path.isabs(path) else os.path.join(base, path)


def _followed(roots: List[Tuple[str, int, str]], value: str, base: str) -> Optional[str]:
    """Where *value*, a path in a settings file in folder *base*, really leads, taken one
    component at a time the way the system does. None when commands could make it lead
    somewhere else, or when it cannot be told.

    That is the case when it follows a link that is in a folder commands can write, and
    when it goes into such a folder and back up with `..`: the folder it went into can be
    replaced with a link, and `..` is then taken from where that link leads. Going up from
    *base* itself is fine: the folders above a settings file are held in place with it.
    """
    path = os.path.expanduser(value) if value.startswith("~") else value
    if not path or path.startswith("~"):
        return None

    def writable(folder: str) -> bool:
        # By what the folder is, not how it is spelled: _locate also knows another letter case.
        return _locate(roots, folder, 0, "") is not None

    here = os.sep if os.path.isabs(path) else os.path.realpath(base)
    parts, hops, went_in = path.split(os.sep), 0, False
    while parts:
        part = parts.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if went_in:
                return None
            here = os.path.dirname(here)
            continue
        step = os.path.join(here, part)
        if os.path.islink(step):
            hops += 1
            if hops > 40 or writable(here):
                return None
            parts = os.readlink(step).split(os.sep) + parts
            if not parts[0]:
                here = os.sep
            continue
        here = step
        went_in = went_in or writable(here)
    return here


def _pointed(roots: List[Tuple[str, int, str]], problems: List[str]) -> List[str]:
    """The settings files git reads for a folder whose `.git` is a pointer to a git
    folder commands cannot write: a linked worktree, or a submodule's checkout."""
    try:
        text = _read(roots[0][1], ".git") or ""
    except OSError:
        text = ""
    pointer = re.match(r"gitdir:[ \t]*(.+)", text.strip())
    gitdir = _full(pointer.group(1).strip(), roots[0][0]) if pointer else ""
    if not gitdir or not os.path.isdir(gitdir):
        problems.append(".git does not point to a git folder")
        return []
    try:
        common = _read_outside(os.path.join(gitdir, "commondir"))
    except OSError:
        common = ""
    shared = gitdir if common is None else _full(common.strip(), gitdir)
    if not shared or _locate(roots, shared, 0, "") is not None:
        problems.append(".git leads to settings in a folder that cannot be locked")
        return []
    _outside_hooks(roots, os.path.join(shared, "hooks"), problems)
    return [os.path.join(shared, "config"), os.path.join(gitdir, "config.worktree")]


def _outside_hooks(roots: List[Tuple[str, int, str]], hooks: str, problems: List[str]) -> None:
    """Outside hook locations must not be redirectable or aliased from writable paths."""
    try:
        if _through_a_root(roots, hooks):
            problems.append("external hooks traverse a writable folder")
        else:
            # Individual hook symlinks may reference project scripts (documented),
            # but a regular hook must not have an unprotected writable hard-link alias.
            for hook in _HOOK_NAMES:
                try:
                    info = os.lstat(os.path.join(hooks, hook))
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                    problems.append(f"external hook {hook} has a second name (a hard link)")
    except OSError:
        problems.append("external hooks cannot be inspected")


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


def _hooks(folder_fd: int, relative: str, label: str, found: Dict[str, str], budget: List[int],
           odd: Optional[List[str]] = None) -> None:
    """Fingerprint the hooks in one folder. Only the names git runs are looked at, so a
    hooks folder that is the project itself costs no more than any other. `odd` collects
    the hooks that are there but are not plain files."""
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
                if odd is not None:
                    odd.append(f"{label}/{name} ({_UNCHECKED})")
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
    return _scan(folder, also, None)


def _scan(folder: str, also: Sequence[str], read: Optional[Dict[str, list]]) -> Dict[str, str]:
    """settings(), and into *read* (when given) where the settings came from. Only then are
    settings files outside the folders read too: the ones a `.git` pointer leads to, and
    the ones an included file names. Commands cannot change those, but what they pull in
    can be somewhere commands can."""
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
        if read is not None:
            read.update(kind=kind, git_dirs=list(git_dirs), files=[], missing=[], hooks=[], odd=[], pointer=[])
        # Each of the repository's folders may hold shared and per-worktree settings.
        own = [(index, os.path.join(gitdir, name)) for index, gitdir in git_dirs for name in ("config", "config.worktree")]
        queue: list = list(own)
        odd = read["odd"] if read is not None else None
        if read is not None and stat.S_ISREG(kind) and not git_dirs:
            queue += [(None, path) for path in _pointed(roots, read["pointer"])]
        most = _FILES + len(queue)
        seen: set = set()
        hook_folders: List[Tuple[int, str]] = []
        while queue:
            index, relative = queue.pop(0)
            if (index, relative) in seen:
                continue
            seen.add((index, relative))
            if len(seen) > most:
                found[f"more included settings files ({_UNCHECKED})"] = "unchecked"
                break
            try:
                if index is None and _through_a_root(roots, relative):
                    raise OSError("reached through a link commands can change")
                text = _read(roots[index][1], relative) if index is not None else _read_outside(relative)
            except OSError:
                found[f"{relative if index is None else label(index, relative)} ({_UNCHECKED})"] = "unchecked"
                continue
            here = os.path.dirname(relative) if index is None else os.path.join(roots[index][0], os.path.dirname(relative))
            if read is not None and index is not None and (index, relative) not in own:   # a file the settings include
                read["files" if text is not None else "missing"].append(os.path.join(roots[index][0], relative))
            if text is None:
                continue
            for section, sub, key, value in _entries(text):
                name = ".".join(part for part in (section, sub, key) if part)
                if (section, key) in (("include", "path"), ("includeif", "path")):
                    found[name] = _digest(found.get(name, "") + value)
                    full = _full(value, here)
                    if read is None:
                        target = _locate(roots, full, 0, "") if full else None
                        if target is not None and target[1] != ".":
                            queue.append(target)
                        continue
                    # Before locking, the file is the one the system would open, not the
                    # one the path reads as once `..` is taken out of it.
                    ends = _followed(roots, value, here) if full else None
                    target = _locate(roots, ends, 0, "") if ends else None
                    if full and ends is None:
                        found[f"{full} ({_UNCHECKED})"] = "unchecked"   # commands can change where it leads
                    elif target is not None and target[1] != ".":
                        queue.append(target)
                    elif target is None and full:
                        queue.append((None, _spelled(value, here)))
                elif (section, key) == ("core", "hookspath"):
                    found[name] = _digest(found.get(name, "") + value)
                    if read is None:
                        target = _locate(roots, value, 0, "")
                        if target is not None and target not in hook_folders:
                            hook_folders.append(target)   # "." is the folder itself
                        continue
                    full = _full(value, roots[0][0])
                    ends = _followed(roots, value, roots[0][0]) if full else None
                    target = _locate(roots, ends, 0, "") if ends else None
                    if full and ends is None:
                        found[f"{full} ({_UNCHECKED})"] = "unchecked"
                    elif target is not None and target not in hook_folders:
                        hook_folders.append(target)
                    elif target is None and full:
                        issues: List[str] = []
                        _outside_hooks(roots, _spelled(value, roots[0][0]), issues)
                        for issue in issues:
                            found[f"{issue} ({_UNCHECKED})"] = "unchecked"
                elif _runs(section, sub, key, value):
                    found[name] = _digest(found.get(name, "") + value)
        budget = [_HOOK_BYTES]
        for index, gitdir in git_dirs:
            hooks = os.path.join(gitdir, "hooks")
            shown = "hooks" if (index, gitdir) == (0, ".git") else label(index, hooks)
            _hooks(roots[index][1], hooks, shown, found, budget, odd)
        # Git uses the last hooks path it reads; every one named is looked at, so the
        # order files were read in here cannot hide the one in effect.
        for index, relative in hook_folders[:_HOOK_FOLDERS]:
            where = "hooks in the shared folder" if (index, relative) == (0, ".") else label(index, relative)
            _hooks(roots[index][1], relative, where, found, budget, odd)
        if read is not None:
            read["hooks"] = [os.path.normpath(os.path.join(roots[index][0], relative)) for index, relative in hook_folders]
        if len(hook_folders) > _HOOK_FOLDERS:
            found[f"more hooks folders ({_UNCHECKED})"] = "unchecked"
        return found
    finally:
        for _root, fd, _label in roots:
            os.close(fd)


def sources(folder: str, also: Sequence[str] = ()) -> Tuple[List[str], List[str], List[str]]:
    """What must not change for git in *folder* to keep running what it runs now.

    Returns (paths, problems, notes). *paths* are the files and hooks folders the
    repository's settings pull in from places commands can write; its own settings files
    and hooks folder have fixed names and are not listed. *problems* say why they cannot
    all be named; with any, the list is not complete. *notes* are hooks that are links or
    other special files: the name can be held in place, not what it leads to.

    *folder* may be a repository, or a linked worktree or submodule checkout whose git
    folder is somewhere commands cannot write.
    """
    read: Dict[str, list] = {}
    found = _scan(folder, also, read)
    odd = list(read.get("odd", ()))
    problems = sorted(name for name in found if name.endswith(f"({_UNCHECKED})") and name not in odd)
    kind, top = read.get("kind"), os.path.normpath(folder)
    if kind is not None and stat.S_ISREG(kind):
        problems = [p for p in problems if p != f".git ({_UNCHECKED})"] + read.get("pointer", [])
        if read.get("git_dirs"):
            problems.insert(0, ".git points to a git folder that commands can write")
    elif kind is not None and stat.S_ISDIR(kind) and (
            read.get("git_dirs") != [(0, ".git")] or os.path.lexists(os.path.join(top, ".git", "commondir"))):
        problems.append(".git/commondir sends git to another folder for its settings")
    problems += [f"{os.path.relpath(path, top)} is named in git settings and does not exist"
                 for path in read.get("missing", ())]
    paths: List[str] = []
    for path in [*read.get("files", ()), *read.get("hooks", ())]:
        if path in (top, *map(os.path.normpath, also)):
            problems.append("core.hooksPath names a whole folder commands work in")
        elif not os.path.lexists(path):
            problems.append(f"{os.path.relpath(path, top)} is named in git settings and does not exist")
        elif path not in paths:
            paths.append(path)
    return paths, problems, sorted(odd)


_WALKED = 150000    # directory entries inspected for repositories, in one start
_CHECKED = 200000   # files looked at inside git folders, in one start
# Object files are shared between repositories on purpose, and git runs none of them.
_OBJECT = re.compile(r"/objects/(?:[0-9a-f]{2}/[0-9a-f]{38,62}|pack/[^/]+\.(?:pack|idx|rev|bitmap|mtimes))$")


def _held(path: str) -> bool:
    """Whether *path* is a git folder the --protect-git rules hold by its name: a `.git`,
    one of its worktree records, or something under its `modules`."""
    parts = path.split(os.sep)
    for at, part in enumerate(parts):
        rest = [p.lower() for p in parts[at + 1:]]
        if part.lower() == ".git" and (not rest or rest[0] == "modules" or (len(rest) == 2 and rest[0] == "worktrees")):
            return True
    return False


def loose(folder: str, also: Sequence[str] = (), paths: Sequence[str] = ()) -> Tuple[List[str], bool]:
    """What the path rules of --protect-git would not hold in *folder* as it is now, and
    whether everything could be looked at.

    The rules go by path. They do not hold for a settings file or hook that has a second
    name (a hard link), is a link, or belongs to a repository whose `.git` sends git to a
    folder with another name. Looks at the folder's own repository, every repository in
    a subfolder, their submodules and worktree records, and *paths* (what the settings
    pull in). Reads only pointer files; follows no link.
    """
    top = os.path.normpath(folder)
    reach = [os.path.realpath(p) for p in (folder, *also)]
    problems: List[str] = []
    left = [_CHECKED]

    def name(path: str) -> str:
        return os.path.relpath(path, top)

    def held(target: str) -> bool:
        real = os.path.realpath(target)
        return _held(real) or not any(real == r or real.startswith(r + os.sep) for r in reach)

    def plain(path: str, links: bool = False, objects: bool = False) -> Optional[os.stat_result]:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError:
            problems.append(f"{name(path)} cannot be inspected")
            return None
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            problems.append(f"{name(path)} is not a regular file or directory")
        if stat.S_ISLNK(info.st_mode) and not links:
            problems.append(f"{name(path)} is a link")
        elif stat.S_ISREG(info.st_mode) and info.st_nlink > 1 and not (objects and _OBJECT.search(path)):
            problems.append(f"{name(path)} has a second name (a hard link)")
        return info

    def tree(path: str, links: bool, objects: bool = False) -> None:
        info = plain(path)
        stack = [path] if info is not None and stat.S_ISDIR(info.st_mode) else []
        while stack and left[0] >= 0:
            here = stack.pop()
            try:
                with os.scandir(here) as scan:
                    entries = []
                    for entry in scan:
                        entries.append(entry.path)
                        if len(entries) > left[0]:
                            left[0] = -1
                            return
            except OSError:
                problems.append(f"{name(here)} cannot be read")
                continue
            left[0] -= len(entries) + 1
            for entry in entries:
                info = plain(entry, links, objects)
                if not links and os.path.basename(entry).lower() == "commondir":
                    target = pointer(entry, os.path.dirname(entry))
                    if target is not None and not held(target):
                        problems.append(f"{name(entry)} sends git to a folder the lock does not hold")
                if info is not None and stat.S_ISDIR(info.st_mode):
                    stack.append(entry)

    def pointer(path: str, base: str, prefix: str = "") -> Optional[str]:
        """Where a pointer file sends git, or None if it is absent or not one."""
        try:
            text = (_read_outside(path) or "").strip()
        except OSError:
            problems.append(f"{name(path)} cannot be read")
            return None
        if prefix and not text.startswith(prefix):
            return None
        return _full(text[len(prefix):].strip(), base) or None

    def repository(meta: str, nested: bool) -> None:
        for settings in ("config", "config.worktree", "commondir"):
            plain(os.path.join(meta, settings))
        if nested and os.path.lexists(os.path.join(meta, "commondir")):
            problems.append(f"{name(meta)}/commondir sends git to another folder for its settings")
        tree(os.path.join(meta, "hooks"), links=True)   # a hook may be a link; the folder may not
        tree(os.path.join(meta, "modules"), links=False, objects=True)
        records = os.path.join(meta, "worktrees")
        tree(records, links=False)
        try:
            names = os.listdir(records)
        except OSError:
            names = []
        for record in names:
            target = pointer(os.path.join(records, record, "commondir"), os.path.join(records, record))
            if target is not None and not held(target):
                problems.append(f"{name(os.path.join(records, record))}/commondir sends git to a folder the lock does not hold")

    walked, stack = _WALKED, [top, *(p for p in also if os.path.isdir(p))]
    while stack and walked >= 0:
        here = stack.pop()
        walked -= 1
        try:
            with os.scandir(here) as scan:
                entries = []
                for entry in scan:
                    walked -= 1
                    if walked < 0:
                        break
                    entries.append(entry)
        except OSError:
            problems.append(f"{name(here)} cannot be read")
            continue
        for entry in entries:
            if entry.name.lower() != ".git":
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                continue
            nested = here != top
            info = plain(entry.path, links=not nested)   # at the top, sources() has the say
            if info is None:
                continue
            if stat.S_ISDIR(info.st_mode):
                repository(entry.path, nested)
                # A repository can itself contain repositories (even under objects/).
                stack.append(entry.path)
            elif stat.S_ISREG(info.st_mode) and nested:
                target = pointer(entry.path, here, "gitdir:")
                if target is not None and not held(target):
                    problems.append(f"{name(entry.path)} points to a git folder the lock does not hold")
    for path in paths:
        tree(path, links=True)
    return sorted(set(problems)), left[0] >= 0 and walked >= 0


def changed(before: Dict[str, str], after: Dict[str, str]) -> List[str]:
    """Names that are new or different in *after*."""
    return sorted(name for name, mark in after.items() if before.get(name) != mark)
