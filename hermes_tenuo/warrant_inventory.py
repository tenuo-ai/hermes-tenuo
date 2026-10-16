"""Inspect SDK-decoded warrants published to local sessions; no issuance ledger."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

from hermes_tenuo.operation_approvals import fingerprint
from hermes_tenuo.session_store import read_session, _decode, _path


def published(directory):
    from tenuo import parse_strict_json
    warrants, errors = {}, []
    directory = Path(directory).expanduser().resolve() if directory is not None else None
    paths = sorted(Path(directory).glob('*.json')) if directory is not None else []
    if len(paths) > 10000:
        raise ValueError('session inventory exceeds 10000 manifests; inspect a specific session')
    for path in paths:
        try:
            if path.is_symlink():
                raise ValueError('session manifest cannot be a symlink')
            with path.open('rb') as stream:
                raw = stream.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('session manifest exceeds size limit')
            record = parse_strict_json(raw.decode('utf-8'))
            session = record['session_id']
            if _path(session, directory) != path:
                raise ValueError('session manifest filename does not match session ID')
            for encoded in read_session(session, directory):
                try:
                    warrant = _decode(encoded)
                    entry = warrants.setdefault(str(warrant.id), {'warrant': warrant, 'sessions': []})
                    if session not in entry['sessions']:
                        entry['sessions'].append(session)
                except Exception as exc:
                    errors.append({'manifest': path.name, 'error': str(exc)})
        except Exception as exc:
            errors.append({'manifest': path.name, 'error': str(exc)})
    return warrants, errors


def describe(warrant, sessions, roots, srl):
    """SDK decoding/typed introspection, never an authorization verdict."""
    gates = {}
    for tool in warrant.capabilities:
        inspection = warrant.inspect_approval_gate(tool)
        if inspection.is_gated():
            gates[tool] = {'kind': inspection.kind, 'arguments': inspection.arguments, 'message': inspection.message}
    trusted = None
    if roots:
        trusted = any(root.to_bytes() == warrant.issuer.to_bytes() for root in roots) if warrant.depth == 0 else None
    return {'warrant_id': str(warrant.id), 'warrant_type': str(warrant.warrant_type),
        'holder_public_key': base64.b64encode(warrant.holder_key.to_bytes()).decode(),
        'holder_fingerprint': fingerprint(warrant.holder_key),
        'issuer_public_key': base64.b64encode(warrant.issuer.to_bytes()).decode(),
        'issuer_fingerprint': fingerprint(warrant.issuer), 'issuer_trusted': trusted,
        'signature_valid': warrant.verify(warrant.issuer.to_bytes()),
        'signed_session_id': warrant.session_id, 'attached_sessions': sessions,
        'expires_at': str(warrant.expires_at()), 'expired': warrant.is_expired(),
        'directly_revoked': srl.is_revoked(str(warrant.id)) if srl is not None else None,
        'revoked': (True if srl.is_revoked(str(warrant.id)) else (False if warrant.depth == 0 else None))
                   if srl is not None else None,
        'revocation_version': srl.version if srl is not None else None,
        'capabilities': {tool: {arg: repr(value) for arg, value in arguments.items()}
                         for tool, arguments in warrant.capabilities.items()},
        'approval_gates': gates, 'approval_keys': [fingerprint(key) for key in (warrant.required_approvers() or [])],
        'required_signatures': warrant.approval_threshold(), 'depth': warrant.depth,
        'parent_hash': str(warrant.parent_hash) if warrant.parent_hash is not None else None,
        'terminal': warrant.terminal, 'max_depth': warrant.max_depth,
        'clearance': str(warrant.clearance) if warrant.clearance is not None else None,
        'agent_id': warrant.agent_id(), 'max_issue_depth': warrant.max_issue_depth,
        'issuable_tools': warrant.issuable_tools,
        'constraint_bounds': repr(warrant.constraint_bounds_dict()) if warrant.constraint_bounds_dict() is not None else None,
        'extensions_base64': {key: base64.b64encode(value).decode() for key, value in (warrant.extensions() or {}).items()},
        'structural_errors': warrant.validate_warrant()}


def cmd_warrants(args):
    try:
        from hermes_tenuo._config import get_session_warrants_dir, get_trusted_roots
        from hermes_tenuo.issuance import read_public_key
        from hermes_tenuo.revocation import configured_store, RevocationStore
        directory = args.directory or get_session_warrants_dir(None)
        roots = [read_public_key(args.trusted_root)] if args.trusted_root else get_trusted_roots(None)
        store = RevocationStore(args.revocations_dir) if args.revocations_dir else configured_store(None)
        srl, revocation_error = None, None
        if store is not None:
            try:
                srl = store.load(roots)
            except Exception as exc:
                revocation_error = str(exc)
        entries, errors = published(directory)
        if args.warrant_command == 'list':
            rows = []
            for entry in entries.values():
                try:
                    row = describe(entry['warrant'], entry['sessions'], roots, srl)
                except Exception as exc:
                    errors.append({'warrant_id': str(entry['warrant'].id), 'error': str(exc)})
                    continue
                rows.append({key: row[key] for key in ('warrant_id', 'holder_fingerprint', 'attached_sessions',
                    'expires_at', 'expired', 'revoked', 'signature_valid', 'issuer_trusted', 'capabilities')})
            print(json.dumps({'published': rows, 'errors': errors, 'revocation_error': revocation_error,
                              'note': 'Published attachments, not all issued warrants or a runtime activation acknowledgement.'}, indent=2))
        else:
            target = Path(args.target).expanduser()
            if target.is_file():
                with target.open() as stream:
                    encoded = stream.read(4 * 1024 * 1024 + 1).strip()
                if len(encoded.encode()) > 4 * 1024 * 1024:
                    raise ValueError('warrant file exceeds size limit')
                warrant = _decode(encoded)
                sessions = entries.get(str(warrant.id), {}).get('sessions', [])
            else:
                entry = entries.get(args.target)
                if entry is None:
                    raise ValueError('warrant ID not found in published sessions; provide its warrant file instead')
                warrant, sessions = entry['warrant'], entry['sessions']
            view = describe(warrant, sessions, roots, srl)
            view['revocation_error'] = revocation_error
            print(json.dumps(view, indent=2))
        return 0
    except Exception as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


def register_commands(subparsers):
    parser = subparsers.add_parser('warrants', help='List published warrants or decode a warrant for inspection')
    commands = parser.add_subparsers(dest='warrant_command', required=True)
    for name in ('list', 'show'):
        child = commands.add_parser(name)
        if name == 'show':
            child.add_argument('target', help='Full warrant ID in the session store, or encoded warrant file')
        child.add_argument('--directory', help='Published session directory; defaults to profile config')
        child.add_argument('--trusted-root', help='Issuer public key file; defaults to profile config')
        child.add_argument('--revocations-dir', help='SRL history directory; defaults to profile config')
