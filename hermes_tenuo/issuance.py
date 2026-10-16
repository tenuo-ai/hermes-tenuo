"""Operator-side identity files and issuance; no holder secret is needed."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import tempfile
from typing import Any


def _read_key(path: str | Path) -> bytes:
    return base64.b64decode(Path(path).expanduser().read_text().strip(), validate=True)


def read_signing_key(path: str | Path):
    from tenuo import SigningKey
    return SigningKey.from_bytes(_read_key(path))


def read_public_key(path: str | Path):
    from tenuo import PublicKey
    return PublicKey.from_bytes(_read_key(path))


def write_private_file(path: str | Path, text: str, *, overwrite: bool = False) -> None:
    """Publish a complete 0600 file atomically; existing files are safe by default."""
    destination = Path(path).expanduser()
    fd, temporary = tempfile.mkstemp(prefix=f'.{destination.name}.', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text.rstrip('\n') + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)  # atomic no-clobber, also rejects symlinks
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def mint_for_holder(issuer: Any, holder: Any, capabilities: dict[str, dict],
                    ttl_seconds: int, session_id: str | None = None):
    """Sign a root execution warrant using only the recipient's public key."""
    from tenuo import Warrant
    if not capabilities:
        raise ValueError('at least one capability is required')
    if ttl_seconds <= 0:
        raise ValueError('TTL must be positive')
    builder = Warrant.mint_builder().holder(holder).ttl(ttl_seconds)
    if session_id is not None:
        if not session_id.strip():
            raise ValueError('session ID must not be empty')
        builder = builder.session_id(session_id)
    for tool, constraints in capabilities.items():
        builder = builder.capability(tool, **constraints)
    return builder.mint(issuer)


def renew_warrant(previous: Any, issuer: Any, ttl_seconds: int):
    """Reissue a verified simple root grant; never discard unsupported restrictions."""
    from tenuo_core import WarrantType
    if previous.issuer.to_bytes() != issuer.public_key.to_bytes():
        raise ValueError('issuer key does not match the previous warrant')
    if not previous.verify(issuer.public_key.to_bytes()):
        raise ValueError('previous warrant signature is invalid')
    if previous.depth != 0 or previous.parent_hash is not None or previous.warrant_type != WarrantType.Execution:
        raise ValueError('renewal supports root execution warrants only')
    if (previous.extensions() or previous.terminal or previous.agent_id() is not None
            or previous.clearance is not None
            or previous.constraint_bounds_dict() is not None
            or previous.required_approvers() or previous.min_approvals() is not None
            or previous.max_issue_depth is not None or previous.issuable_tools is not None
            or previous.max_depth != 64):
        raise ValueError('warrant has additional restrictions unsupported by renewal; explicitly reissue it')
    return mint_for_holder(issuer, previous.holder_key, previous.capabilities,
                           ttl_seconds,
                           previous.session_id)
