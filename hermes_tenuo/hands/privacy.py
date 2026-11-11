"""Local sharing policy and best-effort redaction; no network or identity creation."""
from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import stat
import sys
from pathlib import Path


def policy_file() -> Path:
    config = os.environ.get("XDG_CONFIG_HOME", "")
    root = Path(config) if os.path.isabs(config) else Path.home() / ".config"
    return root / "hermes-tenuo" / "never-share"


def exclusions(folder: str) -> list[str]:
    """Literal paths, relative to the project or absolute. Never silently skip a rule."""
    source = policy_file()
    source_real = str(source.resolve())
    if source_real == folder or source_real.startswith(folder.rstrip(os.sep) + os.sep):
        raise ValueError("keep never-share rules outside the shared folder")
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        if source.is_symlink():
            raise ValueError(f"broken never-share link: {source}")
        return []
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read never-share rules: {source}") from exc
    result = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if any(c in value for c in "*?[]\x00") or value.startswith("!"):
            raise ValueError("never-share accepts literal paths, not glob patterns or negation")
        path = os.path.abspath(os.path.join(folder, os.path.expanduser(value)))
        real = os.path.realpath(path)
        if not os.path.exists(real):
            raise ValueError(f"never-share path does not exist: {path}; create it or correct the rule")
        if not (os.path.isfile(real) or os.path.isdir(real)):
            raise ValueError(f"never-share needs a regular file or directory: {path}")
        if folder == real or folder.startswith(real.rstrip(os.sep) + os.sep):
            raise ValueError(f"the shared folder is excluded by never-share: {path}")
        for p in (path, real):
            if p not in result:
                result.append(p)
    return result


_SECRET_NAME = re.compile(r"secret|token|password|passwd|api_?key|private_key|access_key|credential", re.I)
_TOKEN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    r"|gh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"
    r"|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}\b"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
)
_ASSIGNMENT = re.compile(
    r'''(?i)(\b[\w.-]*(?:secret|token|password|passwd|api_?key|private_key|credential)[\w.-]*["']?\s*[:=]\s*)(["']?)([^\s"',;]{6,})'''
)
_AUTH = re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)\S+")
_URL = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
# A path like config/credentials.json: a slash and a short file extension.
_PATHISH = re.compile(r"[\w.~-]*/[\w./~-]*\.[A-Za-z]{1,6}")


def _not_a_secret(value: str, quoted: bool) -> bool:
    """Whether a value assigned to a secret-named field is ordinary source, not a secret to
    redact. A file path is never a secret. A quoted string literal is kept: it is the shape a
    real secret takes, so it is redacted even when it reads like a word or contains brackets.
    An unquoted value is a bare expression or reference (len(x), timedelta(...), a variable),
    not a credential literal; an opaque unquoted token is still caught by the token patterns
    and by the environment and dotenv values collected above."""
    if _PATHISH.fullmatch(value):
        return True                                 # a file path: config/credentials.json
    if quoted:
        return False                                # a string literal under a secret field
    return any(c in value for c in "(){}[]") or value.isalpha()


class Redactor:
    def __init__(self, folder: str):
        self.folder = Path(folder)
        self.values = {v for k, v in os.environ.items() if _SECRET_NAME.search(k) and len(v) >= 6}
        self._refresh()

    def _refresh(self) -> None:
        # Refresh project-root dotenv values: a build can create or rotate them mid-session.
        # Do not follow symlinks, read devices, or read unbounded files.
        for path in self.folder.glob(".env*"):
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                        continue
                    content = os.read(fd, 65537).decode("utf-8")
                finally:
                    os.close(fd)
                for line in content.splitlines():
                    key, sep, value = line.removeprefix("export ").partition("=")
                    value = value.strip().strip("\"'")
                    # Only values under a secret-looking key, as for environment variables.
                    # A dotenv also holds ordinary settings (LOG_LEVEL, HOST, APP_NAME) whose
                    # values are plain words; redacting those everywhere they appear hides
                    # non-secret text. A credential in a URL value is still caught by _URL.
                    if sep and _SECRET_NAME.search(key) and len(value) >= 6:
                        self.values.add(value)
            except (OSError, UnicodeError):
                continue

    def clean(self, text: str) -> str:
        self._refresh()
        # Hermes file reads include a base64 sample and plaintext page between
        # random framing markers. Scrub both representations without consuming
        # a marker adjacent to a token (files need not end with a newline).
        parts = re.split(r"(__HERMES_[A-Z]+_[0-9a-f]+__)", text)
        for i in range(0, len(parts), 2):
            # Hermes consumes cwd as routing metadata, not file/command content.
            # It already knows this path; replacing it would break subsequent tools.
            if (0 < i < len(parts) - 1 and parts[i - 1] == parts[i + 1]
                    and parts[i - 1].startswith("__HERMES_CWD_")):
                continue
            part = parts[i]
            compact = "".join(part.split())
            # The first RF-delimited field is the encoded sample. Other fields
            # are plaintext/status data, even when they happen to look like base64.
            sample = (i > 0 and parts[i - 1].startswith("__HERMES_RF_")
                      and parts.index(parts[i - 1]) == i - 1)
            if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
                try:
                    data = base64.b64decode(compact, validate=True)
                    try:
                        decoded = data.decode("utf-8")
                    except UnicodeError:
                        if sample:
                            continue  # preserve binary samples as valid base64
                        raise
                    cleaned = self._text(decoded)
                    if cleaned != decoded:
                        leading = part[:len(part) - len(part.lstrip())]
                        trailing = part[len(part.rstrip()):]
                        part = leading + base64.b64encode(cleaned.encode("utf-8")).decode("ascii") + trailing
                    if sample or cleaned != decoded:
                        # Never perform literal replacement on encoded bytes.
                        parts[i] = part
                        continue
                except (ValueError, UnicodeError, binascii.Error):
                    pass
            parts[i] = self._text(part)
        return "".join(parts)

    def _text(self, text: str) -> str:
        for value in sorted(self.values, key=len, reverse=True):
            text = text.replace(value, "[redacted]")
        text = _TOKEN.sub("[redacted]", text)
        text = _AUTH.sub(r"\1[redacted]", text)
        text = _URL.sub(r"\1[redacted]@", text)
        return _ASSIGNMENT.sub(
            lambda m: m[0] if _not_a_secret(m[3], bool(m[2])) else m[1] + m[2] + "[redacted]", text)


def preview(args, duration: int) -> list[str]:
    from . import device, wire
    from .paths import workspace
    folder = workspace(args.dir).root
    paths = exclusions(folder)
    kind = ("sandbox-exec" if sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec")
            else "bubblewrap (not probed)" if sys.platform.startswith("linux") and shutil.which("bwrap") else None)
    if paths and (args.no_sandbox or kind is None):
        raise ValueError("never-share rules require a sandbox; cannot use --no-sandbox")
    if args.invite:
        server = wire.Invite.parse(args.invite).url
    else:
        import json
        saved = device.home() / "server.json"
        server = json.loads(saved.read_text())["url"] if saved.is_file() else "not paired yet"
    unrestricted = args.no_sandbox and kind is None
    return [
        f"Server: {server}", f"Folder: {folder}",
        f"Access: {'read only' if args.read_only else 'read and write'}; duration: {duration} seconds",
        f"Internet: {'unrestricted' if unrestricted else 'on' if args.network else 'off'}; sandbox: {kind or 'unavailable'}",
        "Readable toolchains and extra paths: " + (", ".join(device.shown_in_home(args.read or ())) or "none"),
        f"Read whole home: {'yes' if args.read_home else 'no'}",
        f"Never-share rules: {policy_file()}",
        *[f"Excluded: {p}" for p in paths],
        ("No sandbox: exclusions and credential protections are unavailable; commands have your full access."
         if unrestricted else "Known credential locations are protected by the sandbox. Excluded names may remain visible."),
        "Recognized secrets in results are redacted locally; detection is best effort.",
        "Command and file results go to remote Hermes and may be sent to its model provider.",
        "Preview only: no connection, pairing, key creation, or commands executed.",
    ]
