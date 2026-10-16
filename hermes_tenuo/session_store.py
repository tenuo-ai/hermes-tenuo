"""Atomic operator-published session membership. No private keys are stored here."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
import tempfile
from contextlib import contextmanager

_MAX_BYTES = 4 * 1024 * 1024
_MAX_WARRANTS = 128


def _path(session_id: str, directory: str | Path) -> Path:
    if not isinstance(session_id, str) or not session_id or len(session_id) > 1024:
        raise ValueError("session must be a nonempty identifier of at most 1024 characters")
    name = hashlib.sha256(session_id.encode()).hexdigest()
    return Path(directory).expanduser() / f"{name}.json"


def read_session(session_id: str, directory: str | Path) -> list[str]:
    path = _path(session_id, directory)
    try:
        if path.is_symlink():
            raise ValueError("session manifest cannot be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(_MAX_BYTES + 1)
    except FileNotFoundError:
        return []
    if len(raw) > _MAX_BYTES:
        raise ValueError("session manifest exceeds size limit")
    record = json.loads(raw)
    if not isinstance(record, dict):
        raise ValueError("invalid session manifest")
    warrants = record.get("warrants")
    if (record.get("version") != 1 or record.get("session_id") != session_id
            or not isinstance(warrants, list) or len(warrants) > _MAX_WARRANTS
            or any(not isinstance(w, str) for w in warrants)):
        raise ValueError("invalid session manifest")
    return warrants


@contextmanager
def _operator_lock(directory: str | Path):
    import fcntl
    import time
    directory = Path(directory).expanduser()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / ".membership.lock").open("a") as lock:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("session membership is busy; retry")
                time.sleep(0.01)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _publication_metadata(path: Path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("session manifest must be a regular file, not a symlink")
    if metadata.st_mode & 0o022:
        raise ValueError("session manifest must not be group- or world-writable")
    return metadata


def _write(session_id: str, directory: str | Path, warrants: list[str]) -> None:
    path = _path(session_id, directory)
    metadata = _publication_metadata(path)
    payload = json.dumps({"version": 1, "session_id": session_id, "warrants": warrants})
    if len(warrants) > _MAX_WARRANTS or len(payload.encode()) > _MAX_BYTES:
        raise ValueError("session membership limit exceeded")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".publish-")
    try:
        with os.fdopen(fd, "w") as stream:
            if metadata is not None:
                current = os.fstat(stream.fileno())
                if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                    os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                # Preserve read access, never propagate execute or special bits.
                os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode) & 0o644)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _decode(raw: str):
    from tenuo import Warrant
    try:
        return Warrant.from_bytes(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except Exception as exc:
        raise ValueError("invalid encoded warrant") from exc


def _member_id(raw: str) -> str | None:
    try:
        return str(_decode(raw).id)
    except ValueError:
        return None


def preflight_attachment(session_id: str, directory: str | Path) -> Path:
    """Check the publication destination before a separate issuance operation.

    This reserves nothing: later I/O can still fail and must be reported as a
    publication failure, without obscuring that a warrant has already been issued.
    """
    destination = Path(directory).expanduser().resolve()
    with _operator_lock(destination):
        existing = read_session(session_id, destination)
        _publication_metadata(_path(session_id, destination))
        if len(existing) >= _MAX_WARRANTS:
            raise ValueError("session membership limit reached")
        descriptor, probe = tempfile.mkstemp(dir=destination, prefix=".preflight-")
        os.close(descriptor)
        os.unlink(probe)
    return destination


def _validate_replacement(candidate, previous) -> None:
    """Replacement preserves identity continuity; rotation is a separate operation."""
    if candidate.holder_key.to_bytes() != previous.holder_key.to_bytes():
        raise ValueError("replacement holder does not match the attached warrant")
    if candidate.issuer.to_bytes() != previous.issuer.to_bytes():
        raise ValueError("replacement issuer does not match the attached warrant")
    if not candidate.verify(previous.issuer.to_bytes()):
        raise ValueError("replacement signature is invalid")
    if candidate.is_expired():
        raise ValueError("replacement warrant is expired")


def attach_warrant(warrant: str | Path, session_id: str, directory: str | Path,
                   *, replace_id: str | None = None, expected_id: str | None = None) -> str:
    """Publish an encoded warrant file; runtime independently verifies its authority.

    replace_id atomically replaces one grant, retaining all unrelated grants.
    """
    with Path(warrant).open() as stream:
        raw = stream.read(_MAX_BYTES + 1).strip()
    return attach_encoded_warrant(raw, session_id, directory, replace_id=replace_id, expected_id=expected_id)


def attach_encoded_warrant(raw: str, session_id: str, directory: str | Path,
                           *, replace_id: str | None = None, expected_id: str | None = None) -> str:
    """Publish an already-reviewed artifact without rereading agent-writable files."""
    if not isinstance(raw, str) or len(raw.encode()) > _MAX_BYTES:
        raise ValueError("warrant exceeds size limit")
    parsed = _decode(raw)
    if parsed.session_id is not None and parsed.session_id != session_id:
        raise ValueError("warrant is signed for another session")
    identifier = str(parsed.id)
    if expected_id is not None and identifier != expected_id:
        raise ValueError("warrant ID does not match the reviewed artifact")
    with _operator_lock(directory):
        existing = read_session(session_id, directory)
        if replace_id is not None:
            previous = next((_decode(w) for w in existing if _member_id(w) == replace_id), None)
            if previous is None:
                raise ValueError("replacement target is not attached")
            _validate_replacement(parsed, previous)
        existing = [w for w in existing if _member_id(w) != identifier
                    and (replace_id is None or _member_id(w) != replace_id)]
        _write(session_id, directory, existing + [raw])
    return identifier


def detach_warrant(session_id: str, warrant_id: str, directory: str | Path) -> None:
    with _operator_lock(directory):
        existing = read_session(session_id, directory)
        _write(session_id, directory, [w for w in existing if _member_id(w) != warrant_id])


def clear_session(session_id: str, directory: str | Path) -> None:
    """Remove all membership, even if the existing manifest cannot be parsed."""
    with _operator_lock(directory):
        _write(session_id, directory, [])


def session_status(session_id: str, directory: str | Path) -> list[dict]:
    """Published membership, not an acknowledgement from the running agent."""
    result = []
    for raw in read_session(session_id, directory):
        try:
            warrant = _decode(raw)
        except ValueError:
            result.append({"invalid": True, "sha256": hashlib.sha256(raw.encode()).hexdigest()})
            continue
        result.append({"warrant_id": str(warrant.id), "expired": warrant.is_expired()})
    return result
