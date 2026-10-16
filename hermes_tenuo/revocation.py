"""Local files around Tenuo's native signed revocation list APIs."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading

from hermes_tenuo.issuance import read_public_key, read_signing_key
from hermes_tenuo.operation_approvals import fingerprint
from hermes_tenuo.session_store import _operator_lock

MAX_BYTES = 4 * 1024 * 1024


def read_srl(path):
    from tenuo import SignedRevocationList
    with Path(path).expanduser().open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('signed revocation list exceeds 4 MiB')
    return SignedRevocationList.from_bytes(raw)


def _publish(path, raw):
    """Native CBOR bytes; atomic publication without replacing existing versions."""
    destination = Path(path).expanduser()
    fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix='.srl-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)


def _latest(directory):
    paths = [p for p in Path(directory).glob('*.srl') if re.fullmatch(r'[0-9]{20}\.srl', p.name)]
    if not paths:
        raise ValueError('no signed revocation list published; import an initial empty list first')
    path = max(paths)
    if path.is_symlink():
        raise ValueError('published revocation list cannot be a symlink')
    srl = read_srl(path)
    if srl.version != int(path.stem):
        raise ValueError('revocation list version does not match its published filename')
    return srl


def verify_srl(srl, roots):
    from tenuo_core import Authorizer
    if not roots:
        raise ValueError('explicit trusted issuer keys are required for revocation')
    authorizer = Authorizer(trusted_roots=roots)
    authorizer.set_revocation_list(srl)
    return authorizer


def import_srl(srl, directory, roots):
    """Verify and append native SRL history. No issuer private key is needed."""
    authorizer = verify_srl(srl, roots)
    with _operator_lock(directory):
        existing = list(Path(directory).glob('*.srl'))
        if existing:
            previous = _latest(directory)
            authorizer = verify_srl(previous, roots)
            authorizer.set_revocation_list(srl)  # Core enforces trust, signature and version/content rules.
            if previous.version == srl.version:
                if previous.to_bytes() != srl.to_bytes():
                    raise ValueError('this version is already published; advance the version to publish re-signed bytes')
                return  # Exact artifact retry; published version files are immutable.
        _publish(Path(directory) / f'{srl.version:020d}.srl', srl.to_bytes())


class RevocationStore:
    def __init__(self, directory):
        self.directory = Path(directory).expanduser().resolve()
        self._lock = threading.Lock()
        self._current = None

    def load(self, roots):
        with self._lock:
            candidate = _latest(self.directory)
            authorizer = verify_srl(candidate, roots)
            if self._current is not None:
                authorizer = verify_srl(self._current, roots)
                authorizer.set_revocation_list(candidate)
            self._current = candidate
            return candidate

    @contextmanager
    def scope(self, warrant, parents, holder, roots):
        from tenuo import Runtime, HolderIdentity
        srl = self.load(roots)
        authorizer = verify_srl(srl, roots)
        # Check revocation before asking for operation approvals. The normal
        # enforcement call still performs full capability and PoP verification.
        if parents:
            authorizer.verify_chain(list(parents) + [warrant])
        else:
            authorizer.verify(warrant)
        runtime = Runtime(HolderIdentity(holder), trusted_roots=roots, revocation_list=srl)
        with runtime.bind():
            yield


def configured_store(ctx):
    from hermes_tenuo._config import _get_plugin_entry
    from hermes_tenuo._home import hermes_home
    raw = _get_plugin_entry(ctx).get('revocations_dir')
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError('revocations_dir must be a nonempty path')
    path = Path(raw).expanduser()
    return RevocationStore(path if path.is_absolute() else hermes_home() / path)


def _roots(args):
    if args.trusted_root:
        return [read_public_key(args.trusted_root)]
    from hermes_tenuo._config import get_trusted_roots
    roots = get_trusted_roots(None)
    if not roots:
        raise ValueError('set --trusted-root or configure the trusted issuer public key')
    return roots


def describe_srl(srl):
    return {'version': srl.version, 'issued_at': srl.issued_at,
            'issuer_fingerprint': fingerprint(srl.issuer), 'revoked_ids': srl.revoked_ids,
            'sha256': hashlib.sha256(srl.to_bytes()).hexdigest()}


def cmd_revocations(args):
    try:
        if args.revocation_command == 'create':
            from tenuo import SignedRevocationList
            key = read_signing_key(args.issuer_key)
            builder = SignedRevocationList.builder()
            version = 1
            if args.from_path:
                previous = read_srl(args.from_path)
                verify_srl(previous, [key.public_key])
                builder.from_existing(previous)
                version = previous.version + 1
            for identifier in args.revoke or []:
                if not re.fullmatch(r'tnu_wrt_[A-Za-z0-9_-]+', identifier):
                    raise ValueError('use a complete warrant ID from warrants list/show')
                builder.revoke(identifier)
            srl = builder.version(version).build(key)
            _publish(args.out, srl.to_bytes())
            print(json.dumps(describe_srl(srl), indent=2))
            print(f'Signed revocation list saved: {args.out}. Import it to apply; creation alone changes no runtime.')
        else:
            srl = read_srl(args.path)
            roots = _roots(args)
            verify_srl(srl, roots)
            if args.revocation_command == 'import':
                store = configured_store(None) if not args.directory else RevocationStore(args.directory)
                if store is None:
                    raise ValueError('set --directory or configure revocations_dir')
                import_srl(srl, store.directory, roots)
                print(f'Published SRL version {srl.version}. The next protected call reloads it; no restart needed.')
            print(json.dumps(describe_srl(srl), indent=2))
        return 0
    except Exception as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


def register_commands(subparsers):
    parser = subparsers.add_parser('revocations', help='Create, inspect or import native Tenuo signed revocation lists')
    commands = parser.add_subparsers(dest='revocation_command', required=True)
    create = commands.add_parser('create', help='Sign an SRL outside Hermes; omit --revoke for initial empty list')
    create.add_argument('--issuer-key', required=True)
    create.add_argument('--revoke', action='append', metavar='WARRANT_ID')
    create.add_argument('--from', dest='from_path', help='Retain previous entries and advance its signed version')
    create.add_argument('--out', required=True, help='New native CBOR signed revocation list file')
    for name in ('show', 'import'):
        child = commands.add_parser(name)
        child.add_argument('path', help='Native Tenuo SRL file')
        child.add_argument('--trusted-root', help='Trusted SRL issuer public key; defaults to profile config')
        if name == 'import':
            child.add_argument('--directory', help='Operator-published SRL history; defaults to revocations_dir')
