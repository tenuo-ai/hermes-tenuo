"""Shared helpers for the agent-access pairing spike."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

from tenuo import PublicKey, SigningKey


def b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def fingerprint(public_key_bytes: bytes) -> str:
    digest = hashlib.sha256(bytes(public_key_bytes)).hexdigest()[:8]
    return f"{digest[:4]}-{digest[4:]}"


def code_hash(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_or_create_key(path: Path) -> SigningKey:
    if path.exists():
        return SigningKey.from_bytes(unb64(path.read_text().strip()))
    key = SigningKey.generate()
    write_private(path, b64(key.secret_key_bytes()).encode())
    return key


def public_bytes(key: SigningKey) -> bytes:
    return bytes(key.public_key_bytes())


def public_key(data: bytes) -> PublicKey:
    return PublicKey.from_bytes(bytes(data))


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def write_json(path: Path, value) -> None:
    write_private(path, json.dumps(value, indent=2, sort_keys=True).encode())


def until(warrant) -> str:
    from datetime import datetime
    value = warrant.expires_at()
    when = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else datetime.fromtimestamp(value)
    return when.astimezone().strftime("%a %H:%M")
