"""Portable local operation approval requests. Transport is deliberately manual."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

from hermes_tenuo.authority_requests import _unique_object
from hermes_tenuo.issuance import read_public_key, read_signing_key, write_private_file

from tenuo.approval import ApprovalRequired

MAX_BYTES = 128 * 1024
MAX_PENDING = 100


def fingerprint(public) -> str:
    return hashlib.sha256(public.to_bytes()).hexdigest()


def _reject_constant(value):
    raise ValueError('non-finite JSON is not supported')


def _load(path):
    with Path(path).expanduser().open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('approval file exceeds 128 KiB')
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant)


def _save(path, data):
    raw = json.dumps(data, sort_keys=True, indent=2, allow_nan=False)
    if len(raw.encode()) > MAX_BYTES:
        raise ValueError('approval file exceeds 128 KiB')
    write_private_file(path, raw)


def identity_directory(directory=None):
    return Path(directory or '~/.config/hermes-tenuo/approvers').expanduser()


def identity_path(name, directory=None):
    if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@+-]{0,127}', name):
        raise ValueError('identity name must use 1-128 letters, digits, or ._@+-')
    return identity_directory(directory) / f'{name}.json'


def register_identity(name, public, directory=None):
    path = identity_path(name, directory)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _save(path, {'version': 1, 'name': name, 'public_key': base64.b64encode(public.to_bytes()).decode()})


def load_identity(name, directory=None):
    from tenuo import PublicKey
    data = _load(identity_path(name, directory))
    if (not isinstance(data, dict) or set(data) != {'version', 'name', 'public_key'}
            or type(data['version']) is not int or data['version'] != 1 or data['name'] != name):
        raise ValueError('invalid registered approver identity')
    return PublicKey.from_bytes(base64.b64decode(data['public_key'], validate=True))


def verify_warrant(warrant, roots):
    # This first file protocol handles root warrants. Never pretend a leaf
    # signature establishes a delegation chain back to an issuer trust root.
    if warrant.depth != 0 or warrant.parent_hash is not None:
        raise ValueError('portable approvals currently require a root warrant')
    if not any(warrant.issuer.to_bytes() == root.to_bytes() and warrant.verify(root.to_bytes()) for root in roots):
        raise ValueError('warrant issuer is not trusted or its signature is invalid')
    if warrant.is_expired():
        raise ValueError('warrant has expired; request new authority')


def request_document(request, warrant, session):
    return {'version': 1, 'kind': 'operation-approval-request', 'session_id': session,
            'warrant': warrant.to_base64(), 'tool': request.tool, 'arguments': request.arguments,
            'request_hash': request.request_hash.hex()}


def validate_request(data, roots):
    from tenuo import Warrant
    from tenuo.approval import ApprovalRequest
    from tenuo_core import py_compute_request_hash
    fields = {'version', 'kind', 'session_id', 'warrant', 'tool', 'arguments', 'request_hash'}
    if (not isinstance(data, dict) or set(data) != fields or type(data['version']) is not int
            or data['version'] != 1 or data['kind'] != 'operation-approval-request'):
        raise ValueError('invalid operation approval request')
    if not isinstance(data['session_id'], str) or not data['session_id'] or len(data['session_id']) > 1024:
        raise ValueError('request needs a session identifier')
    if not isinstance(data['tool'], str) or not data['tool'] or not isinstance(data['arguments'], dict):
        raise ValueError('request needs a tool and argument mapping')
    warrant = Warrant.from_base64(data['warrant'])
    verify_warrant(warrant, roots)
    if warrant.session_id is not None and warrant.session_id != data['session_id']:
        raise ValueError('request session does not match the signed warrant')
    requirement = warrant.approval_requirement(data['tool'], data['arguments'])
    if not requirement.requires_approval():
        raise ValueError('this call is denied or does not require operation approval')
    if not warrant.required_approvers():
        raise ValueError('warrant has no authorized approvers')
    digest = py_compute_request_hash(str(warrant.id), data['tool'], data['arguments'], warrant.holder_key)
    if data['request_hash'] != digest.hex():
        raise ValueError('request hash does not match the warrant, holder, tool and arguments')
    request = ApprovalRequest.for_warrant_gate(data['tool'], data['arguments'], warrant, digest,
                                              holder_key=warrant.holder_key)
    return request, warrant


def response_approval(data, request, warrant):
    from tenuo_core import SignedApproval, verify_approvals
    if (not isinstance(data, dict) or set(data) != {'version', 'kind', 'request_hash', 'approval'}
            or type(data['version']) is not int or data['version'] != 1
            or data['kind'] != 'operation-approval-response' or data['request_hash'] != request.request_hash.hex()):
        raise ValueError('response does not match the operation approval request')
    signed = SignedApproval.from_bytes(base64.b64decode(data['approval'], validate=True))
    # A single valid response may be one part of an m-of-n collection.
    payloads = verify_approvals(request.request_hash, [signed], warrant.required_approvers(), 1, 0)
    if payloads[0].expires_at > request.warrant_expires_at_unix:
        raise ValueError('approval expiry must not exceed warrant expiry')
    return signed


def review(request, warrant):
    return json.dumps({'tool': request.tool, 'arguments': request.arguments, 'warrant_id': str(warrant.id),
        'holder_fingerprint': fingerprint(warrant.holder_key), 'issuer_fingerprint': fingerprint(warrant.issuer),
        'authorized_approvers': [fingerprint(p) for p in warrant.required_approvers()],
        'required_signatures': warrant.approval_threshold(), 'request_hash': request.request_hash.hex(),
        'warrant_expires_at_unix': request.warrant_expires_at_unix}, indent=2, sort_keys=True, allow_nan=False)


def _bucket(directory, session, digest):
    return Path(directory) / hashlib.sha256(session.encode()).hexdigest() / digest


class OperationApprovalPending(ApprovalRequired):
    """A useful block signal, never an authorization grant."""

    def __init__(self, request, message):
        super().__init__(request)
        self.args = (message,)


class OperationApprovalStore:
    def __init__(self, requests, responses):
        self.requests = Path(requests).expanduser().resolve()
        self.responses = Path(responses).expanduser().resolve()

    def handler(self, warrant, session, roots):
        def collect(request):
            from tenuo_core import verify_approvals
            verify_warrant(warrant, roots)
            data = request_document(request, warrant, session)
            # Recompute rather than trusting adapter-supplied request metadata.
            checked, _ = validate_request(data, roots)
            directory = _bucket(self.responses, session, checked.request_hash.hex())
            approvals = []
            for public in warrant.required_approvers():
                path = directory / f'{fingerprint(public)}.json'
                try:
                    signed = response_approval(_load(path), checked, warrant)
                    if signed.approver_key.to_bytes() != public.to_bytes():
                        continue
                    approvals.append(signed)
                except Exception:
                    continue  # A bad response cannot hide an independent valid signature.
            try:
                verify_approvals(checked.request_hash, approvals, warrant.required_approvers(),
                                 warrant.approval_threshold(), 0)
                collect.approved_by = [{'identity': signed.verify().external_id,
                                        'fingerprint': fingerprint(signed.approver_key)} for signed in approvals]
                return approvals
            except Exception:
                pass
            request_dir = self.requests / hashlib.sha256(session.encode()).hexdigest()
            request_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = request_dir / f'{checked.request_hash.hex()}.operation.json'
            if not path.exists():
                if sum(1 for _ in request_dir.glob('*.operation.json')) >= MAX_PENDING:
                    raise ValueError('pending operation request limit reached; archive reviewed requests')
                try:
                    _save(path, data)
                except FileExistsError:
                    pass
            # Restore a request that was modified after the previous blocked attempt.
            if _load(path) != data:
                raise ValueError('pending operation request changed; archive it and retry')
            command = f'hermes-tenuo approvals show {shlex.quote(str(path))} --trusted-root ISSUER_PUBLIC_KEY_FILE'
            raise OperationApprovalPending(checked,
                f'Human approval required ({len(approvals)}/{warrant.approval_threshold()} signatures). '
                f'The tool did not execute. Request file: {path}. '
                f'Review: {command}. Send this file to an authorized approver; import their signed response, then retry.'
            )
        collect.approved_by = []
        return collect


def configured_store(ctx):
    from hermes_tenuo._config import _get_plugin_entry
    from hermes_tenuo._home import hermes_home
    entry = _get_plugin_entry(ctx)
    paths = []
    for key in ('operation_requests_dir', 'operation_approvals_dir'):
        raw = entry.get(key)
        if raw is None:
            paths.append(None)
        elif not isinstance(raw, str) or not raw.strip():
            raise ValueError(f'{key} must be a nonempty path')
        else:
            path = Path(raw).expanduser()
            paths.append((path if path.is_absolute() else hermes_home() / path).resolve())
    if paths == [None, None]:
        return None
    if None in paths:
        raise ValueError('configure both operation_requests_dir and operation_approvals_dir')
    if paths[0] == paths[1] or paths[0] in paths[1].parents or paths[1] in paths[0].parents:
        raise ValueError('operation request and approval directories must be separate, non-nested paths')
    return OperationApprovalStore(*paths)


def cmd_approver(args):
    try:
        if args.approver_command == 'register':
            public = read_public_key(args.public_key)
            register_identity(args.name, public, args.identities_dir)
        else:
            public = load_identity(args.name, args.identities_dir)
        print(json.dumps({'name': args.name, 'fingerprint': fingerprint(public),
                          'public_key': base64.b64encode(public.to_bytes()).decode()}, indent=2))
        return 0
    except Exception as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


def cmd_approvals(args):
    try:
        snapshot = _load(args.request)
        request, warrant = validate_request(snapshot, [read_public_key(args.trusted_root)])
        print(review(request, warrant))
        if args.approvals_command == 'show':
            print('Next: send this file to an authorized approver. They run:')
            print('hermes-tenuo approvals sign ' + shlex.quote(str(args.request)) +
                  ' --identity NAME --key APPROVER_PRIVATE_KEY_FILE --trusted-root ISSUER_PUBLIC_KEY_FILE --out response.json')
            return 0
        if args.approvals_command == 'sign':
            from tenuo_core import ApprovalPayload, SignedApproval
            from hermes_tenuo.cli import _parse_ttl
            public = load_identity(args.identity, args.identities_dir)
            if not any(public.to_bytes() == p.to_bytes() for p in warrant.required_approvers()):
                raise ValueError('registered identity is not an authorized approver for this warrant')
            ttl = min(_parse_ttl(args.ttl), request.warrant_expires_at_unix - int(time.time()))
            if ttl < 1:
                raise ValueError('warrant has expired')
            print(json.dumps({'sign_as': args.identity, 'fingerprint': fingerprint(public), 'ttl_seconds': ttl}))
            print('This approval permits repeated identical calls until expiry; it is not single-use.')
            if not args.yes and input('Approve exactly this operation? [y/N] ').strip().lower() not in ('y', 'yes'):
                print('Not approved.')
                return 1
            key = read_signing_key(args.key)
            if key.public_key.to_bytes() != public.to_bytes():
                raise ValueError('private key does not match the registered identity')
            now = int(time.time())
            expires = min(now + _parse_ttl(args.ttl), request.warrant_expires_at_unix)
            if expires <= now:
                raise ValueError('warrant expired during review; nothing was signed')
            signed = SignedApproval.create(ApprovalPayload(
                request_hash=request.request_hash, nonce=os.urandom(16), external_id=args.identity,
                approved_at=now, expires_at=expires), key)
            response = {'version': 1, 'kind': 'operation-approval-response',
                        'request_hash': request.request_hash.hex(),
                        'approval': base64.b64encode(signed.to_bytes()).decode()}
            _save(args.out, response)
            print(f'Signed response saved: {args.out}. Send this file back to the operator.')
            print('Operator: hermes-tenuo approvals import REQUEST_FILE --response ' +
                  shlex.quote(str(args.out)) + ' --trusted-root ISSUER_PUBLIC_KEY_FILE')
        else:
            response = _load(args.response)
            signed = response_approval(response, request, warrant)
            directory = args.directory
            if directory is None:
                store = configured_store(None)
                if store is None:
                    raise ValueError('set --directory or configure operation_approvals_dir and operation_requests_dir')
                directory = store.responses
            destination = _bucket(Path(directory).expanduser(), snapshot['session_id'], request.request_hash.hex())
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Reimporting the same signer replaces its response, never increases the count.
            write_private_file(destination / f'{fingerprint(signed.approver_key)}.json',
                               json.dumps(response, sort_keys=True), overwrite=True, preserve_permissions=True)
            print(json.dumps({'signed_identity': signed.verify().external_id,
                              'approver_fingerprint': fingerprint(signed.approver_key),
                              'expires_at_unix': signed.verify().expires_at}))
            print('Published signed approval. Ask Hermes to retry; no gateway restart needed.')
        return 0
    except Exception as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


def register_commands(subparsers):
    approver = subparsers.add_parser('approver', help='Register or inspect a named local approver public key')
    commands = approver.add_subparsers(dest='approver_command', required=True)
    for name in ('register', 'show'):
        parser = commands.add_parser(name)
        parser.add_argument('name')
        parser.add_argument('--identities-dir', help='Public identity directory (default: ~/.config/hermes-tenuo/approvers)')
        if name == 'register':
            parser.add_argument('--public-key', required=True)
    approvals = subparsers.add_parser('approvals', help='Review, sign, or import portable operation approvals')
    commands = approvals.add_subparsers(dest='approvals_command', required=True)
    for name in ('show', 'sign', 'import'):
        parser = commands.add_parser(name)
        parser.add_argument('request', help='Portable operation request file')
        parser.add_argument('--trusted-root', required=True, help='Independently trusted issuer public key file')
        if name == 'sign':
            parser.add_argument('--identity', required=True)
            parser.add_argument('--identities-dir')
            parser.add_argument('--key', required=True, help='Approver private key file; never an issuer or holder key')
            parser.add_argument('--ttl', default='5m')
            parser.add_argument('--out', required=True, help='New portable signed response file')
            parser.add_argument('--yes', action='store_true', help='Explicit noninteractive approval')
        elif name == 'import':
            parser.add_argument('--response', required=True)
            parser.add_argument('--directory', help='Operator-published approval directory; defaults to plugin config')
