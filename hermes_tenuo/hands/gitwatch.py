"""Git settings in a shared folder that make git run programs.

Commands may change the shared folder, and that includes its repository's own
settings. Git runs some of those as programs (hooks, a file-system monitor, a
pager, an alias), and runs them for whoever uses git there next: the person,
their editor or their shell prompt, outside the sandbox. Refusing the writes
would also refuse ``git init`` and ``git remote add``, so the device reports
them to the person instead.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Dict, List

# Keys whose value git runs, or that pull in more settings.
_RUNS = frozenset({
    "core.fsmonitor", "core.hookspath", "core.sshcommand", "core.pager", "core.editor",
    "core.askpass", "core.gitproxy", "diff.external", "sequence.editor", "gpg.program",
    "credential.helper", "uploadpack.packobjectshook", "include.path", "includeif.path",
})
_RUNS_IN = {  # section → keys git runs, for any subsection
    "filter": {"clean", "smudge", "process"}, "diff": {"textconv", "command"},
    "merge": {"driver"}, "mergetool": {"cmd"}, "difftool": {"cmd"}, "credential": {"helper"},
}
_SECTION = re.compile(r'^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]')
_ENTRY = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$")
_LIMIT = 1 << 20


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _from_config(path: str) -> Dict[str, str]:
    found: Dict[str, str] = {}
    try:
        if os.path.getsize(path) > _LIMIT:
            return {".git/config": "too large to check"}
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return found
    section = sub = ""
    for line in lines:
        header = _SECTION.match(line)
        if header:
            section, sub = header.group(1).lower(), header.group(2) or ""
            continue
        entry = _ENTRY.match(line)
        if not entry or not section:
            continue
        key, value = entry.group(1).lower(), (entry.group(2) or "").strip()
        runs = (f"{section}.{key}" in _RUNS or key in _RUNS_IN.get(section, ())
                or section == "pager" or (section == "alias" and value.lstrip('"').startswith("!")))
        if runs:
            label = ".".join(part for part in (section, sub, key) if part)
            found[label] = _digest(found.get(label, "") + value)
    return found


def _from_hooks(folder: str) -> Dict[str, str]:
    found: Dict[str, str] = {}
    try:
        names = sorted(os.listdir(folder))[:200]
    except OSError:
        return found
    for name in names:
        if name.endswith(".sample"):
            continue
        try:
            info = os.stat(os.path.join(folder, name))
        except OSError:
            continue
        found[f"hooks/{name}"] = f"{info.st_size}:{info.st_mtime_ns}:{info.st_mode}"
    return found


def settings(folder: str) -> Dict[str, str]:
    """What in *folder*'s own repository makes git run a program: name → fingerprint."""
    git = os.path.join(folder, ".git")
    if not os.path.isdir(git):
        return {}
    return {**_from_config(os.path.join(git, "config")), **_from_hooks(os.path.join(git, "hooks"))}


def changed(before: Dict[str, str], after: Dict[str, str]) -> List[str]:
    """Names that are new or different in *after*."""
    return sorted(name for name, mark in after.items() if before.get(name) != mark)
