"""Operator-side identity files and issuance; no holder secret is needed."""
from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
import tempfile
from typing import Any


def _read_key(path: str | Path) -> bytes:
    return base64.b64decode(Path(path).expanduser().read_text().strip(), validate=True)


def read_signing_key(path: str | Path):
    from tenuo import SigningKey
    return SigningKey.from_bytes(_read_key(path))


def read_public_key(path: str | Path):
    try:
        from tenuo.local import load_public_key
    except ImportError:
        resolved = Path(path).expanduser().resolve(strict=True)
        if resolved.suffix.lower() != '.pub':
            raise ValueError('public keys must use a .pub file; never pass a private signing key')
        path = resolved
    else:
        return load_public_key(path)
    from tenuo import PublicKey
    return PublicKey.from_bytes(_read_key(path))


def write_private_file(path: str | Path, text: str, *, overwrite: bool = False,
                       preserve_permissions: bool = False) -> None:
    """Publish a complete 0600 file atomically; existing files are safe by default."""
    destination = Path(path).expanduser()
    metadata = None
    if preserve_permissions:
        from hermes_tenuo.session_store import _publication_metadata
        metadata = _publication_metadata(destination)
    fd, temporary = tempfile.mkstemp(prefix=f'.{destination.name}.', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            if metadata is not None:
                current = os.fstat(stream.fileno())
                if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                    os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode) & 0o644)
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
                    ttl_seconds: int, session_id: str | None = None, *,
                    approval_gates: list[str] | None = None, approvers: list | None = None,
                    min_approvals: int = 1):
    """Sign a root execution warrant using only the recipient's public key."""
    from tenuo import Warrant
    import hmac
    if any(hmac.compare_digest(bytes(issuer.secret_key_bytes()), bytes(public.to_bytes()))
           for public in [holder, *(approvers or [])]):
        raise ValueError('public warrant fields contain private signing material; use a public key')
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
    if approval_gates or approvers:
        if not approval_gates or not approvers:
            raise ValueError('approval gates and approver public keys must be supplied together')
        if any(tool not in capabilities for tool in approval_gates):
            raise ValueError('approval gates must name granted tools')
        if len({p.to_bytes() for p in approvers}) != len(approvers):
            raise ValueError('approver keys must be distinct')
        if type(min_approvals) is not int or not 1 <= min_approvals <= len(approvers):
            raise ValueError('approval threshold must be between 1 and the number of approvers')
        builder = (builder.approval_gates({tool: None for tool in approval_gates})
                   .required_approvers(approvers).min_approvals(min_approvals))
    elif min_approvals != 1:
        raise ValueError('approval threshold requires gates and approvers')
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
