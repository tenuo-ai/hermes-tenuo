"""Real cryptographic file round trips, including offline human signers."""
import argparse
import base64
import json
import shutil
import subprocess
import sys
import time

import pytest
from tenuo import SigningKey
from tenuo.approval import sign_approval
from tenuo_core import ApprovalPayload, SignedApproval

from hermes_tenuo import operation_approvals as op
from hermes_tenuo.hermes_guard import HermesGuard
from hermes_tenuo.issuance import mint_for_holder
from hermes_tenuo.session_guard import SessionGuard
from hermes_tenuo.session_store import attach_encoded_warrant


def public_file(path, key):
    path.write_text(base64.b64encode(key.public_key.to_bytes()).decode())
    return path


def private_file(path, key):
    path.write_text(base64.b64encode(key.secret_key_bytes()).decode())
    return path


def cli(*args, cwd=None):
    result = subprocess.run([sys.executable, '-m', 'hermes_tenuo.cli', *map(str, args)],
                            cwd=cwd, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture
def setup(tmp_path):
    issuer, holder, alice, bob = [SigningKey.generate() for _ in range(4)]
    store = op.OperationApprovalStore(tmp_path / 'requests', tmp_path / 'responses')
    events = []
    def create(*, threshold=1, approvers=None, static=False, session='conversation', ttl=600):
        warrant = mint_for_holder(issuer, holder.public_key, {'restart_service': {}, 'get_status': {}}, ttl,
            session, approval_gates=['restart_service'], approvers=approvers or [alice.public_key],
            min_approvals=threshold)
        if static:
            guard = HermesGuard(warrant, holder, trusted_roots=[issuer.public_key],
                                audit_callback=events.append, operation_approval_store=store)
        else:
            attach_encoded_warrant(warrant.to_base64(), session, tmp_path / 'sessions')
            guard = SessionGuard(tmp_path / 'sessions', signing_key=holder,
                trusted_roots=[issuer.public_key], audit_callback=events.append, operation_approval_store=store)
        return warrant, guard
    return tmp_path, issuer, holder, alice, bob, store, events, create


def pending(setup, guard, args=None, session='conversation'):
    result = guard.pre_tool_call('restart_service', args or {'service': 'example'}, session_id=session)
    assert result['action'] == 'block' and result['code'] == 'operation_approval_required'
    assert 'tool did not execute' in result['message']
    path = next(setup[5].requests.rglob('*.operation.json'))
    request, warrant = op.validate_request(op._load(path), [setup[1].public_key])
    return path, request, warrant


def response(request, signed):
    return {'version': 1, 'kind': 'operation-approval-response', 'request_hash': request.request_hash.hex(),
            'approval': base64.b64encode(signed.to_bytes()).decode()}


def publish(setup, path, request, warrant, signer, name='alice'):
    tmp, issuer, *_ = setup
    root = public_file(tmp / 'issuer.pub', issuer)
    artifact = tmp / f'{name}.response.json'
    artifact.write_text(json.dumps(response(request, sign_approval(request, signer, external_id=name, ttl_seconds=60))))
    args = argparse.Namespace(request=path, trusted_root=root, approvals_command='import',
                              response=artifact, directory=setup[5].responses)
    assert op.cmd_approvals(args) == 0
    return artifact


@pytest.mark.parametrize('static', [False, True])
def test_manual_offline_journey_and_live_reload(setup, static, monkeypatch):
    tmp, issuer, holder, alice, _, store, events, create = setup
    _, guard = create(static=static)
    assert guard.pre_tool_call('get_status', {}, session_id='conversation') is None
    assert not store.requests.exists()
    path, request, warrant = pending(setup, guard)
    assert events[-1].decision == 'DENY'
    # The recipient has only the copied request, their own identity/key, and
    # an independently obtained issuer PUBLIC key. No issuer or holder secret.
    recipient = tmp / 'recipient'
    recipient.mkdir()
    sent = recipient / 'restart.operation.json'
    shutil.copyfile(path, sent)
    root = public_file(recipient / 'issuer.pub', issuer)
    public = public_file(recipient / 'alice.pub', alice)
    key = private_file(recipient / 'alice.key', alice)
    identities = recipient / 'identities'
    cli('approver', 'register', 'alice', '--public-key', public, '--identities-dir', identities)
    assert op.fingerprint(alice.public_key) in cli('approver', 'show', 'alice', '--identities-dir', identities)
    assert 'Next:' in cli('approvals', 'show', sent, '--trusted-root', root)
    returned = recipient / 'response.json'
    text = cli('approvals', 'sign', sent, '--identity', 'alice', '--identities-dir', identities,
        '--key', key, '--trusted-root', root, '--out', returned, '--yes')
    assert 'not single-use' in text
    assert base64.b64encode(alice.secret_key_bytes()).decode() not in text
    # Signing on the recipient's machine has no effect until the response returns.
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    cli('approvals', 'import', path, '--response', returned, '--trusted-root', root, '--directory', store.responses)
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation') is None
    assert events[-1].decision == 'ALLOW'
    assert events[-1].approvers == [{'identity': 'alice', 'fingerprint': op.fingerprint(alice.public_key)}]
    # Repeated identical calls within TTL are explicitly supported by Tenuo.
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation') is None
    assert guard.pre_tool_call('restart_service', {'service': 'different'}, session_id='conversation')
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='different')
    assert guard.pre_tool_call('ungranted_tool', {}, session_id='conversation')
    assert not list(recipient.glob('*.warrant'))


def test_multisig_counts_distinct_authorized_keys_and_expired_signature(setup):
    _, _, _, alice, bob, store, events, create = setup
    _, guard = create(threshold=2, approvers=[alice.public_key, bob.public_key])
    path, request, warrant = pending(setup, guard)
    publish(setup, path, request, warrant, alice)
    result = guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    assert '1/2 signatures' in result['message']
    publish(setup, path, request, warrant, alice)  # Reimport never counts twice.
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    publish(setup, path, request, warrant, bob, 'bob')
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation') is None
    # Corruption of one signature causes the threshold to fail closed.
    signature = next(store.responses.rglob(f'{op.fingerprint(bob.public_key)}.json'))
    signature.write_text('corrupt')
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    assert events[-1].decision == 'DENY'


@pytest.mark.parametrize('mutation', ['tool', 'arguments', 'hash', 'session', 'issuer'])
def test_signer_recomputes_request_binding_and_checks_trust(setup, mutation):
    _, issuer, _, _, _, _, _, create = setup
    _, guard = create()
    path, _, _ = pending(setup, guard)
    data = op._load(path)
    if mutation == 'tool':
        data['tool'] = 'delete_service'
    elif mutation == 'arguments':
        data['arguments'] = {'service': 'other'}
    elif mutation == 'hash':
        data['request_hash'] = '00' * 32
    elif mutation == 'session':
        data['session_id'] = 'other'
    roots = [SigningKey.generate().public_key] if mutation == 'issuer' else [issuer.public_key]
    with pytest.raises(Exception):
        op.validate_request(data, roots)


def test_untrusted_expired_and_modified_responses_do_not_authorize(setup):
    tmp, issuer, _, alice, _, store, _, create = setup
    _, guard = create()
    path, request, warrant = pending(setup, guard)
    alien = SigningKey.generate()
    for signer in [alien, alice]:
        signed = sign_approval(request, signer, ttl_seconds=60)
        data = response(request, signed)
        if signer == alice:
            raw = bytearray(base64.b64decode(data['approval']))
            raw[-1] ^= 1
            data['approval'] = base64.b64encode(raw).decode()
        with pytest.raises(Exception):
            op.response_approval(data, request, warrant)
    expired = SignedApproval.create(ApprovalPayload(request_hash=request.request_hash,
        nonce=b'1' * 16, external_id='alice', approved_at=int(time.time()) - 120,
        expires_at=int(time.time()) - 60), alice)
    with pytest.raises(Exception):
        op.response_approval(response(request, expired), request, warrant)
    data = response(request, expired)
    destination = op._bucket(store.responses, 'conversation', request.request_hash.hex())
    destination.mkdir(parents=True)
    (destination / f'{op.fingerprint(alice.public_key)}.json').write_text(json.dumps(data))
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    assert not list(tmp.glob('*.key'))


def test_registered_identity_does_not_grant_authority_and_mismatch_never_signs(setup, monkeypatch):
    tmp, issuer, _, alice, bob, _, _, create = setup
    _, guard = create()
    path, _, _ = pending(setup, guard)
    root = public_file(tmp / 'issuer.pub', issuer)
    identities = tmp / 'identities'
    op.register_identity('bob', bob.public_key, identities)
    args = argparse.Namespace(request=path, trusted_root=root, approvals_command='sign',
        identity='bob', identities_dir=identities, key=tmp / 'missing.key', ttl='5m', yes=True, out=tmp / 'out.json')
    def unexpected(*args):
        pytest.fail('unauthorized or declined approval must not read a private key')
    monkeypatch.setattr(op, 'read_signing_key', unexpected)
    assert op.cmd_approvals(args) == 1
    op.register_identity('alice', alice.public_key, identities)
    args.identity, args.yes = 'alice', False
    monkeypatch.setattr('builtins.input', lambda _: 'n')
    assert op.cmd_approvals(args) == 1
    monkeypatch.undo()
    args.key, args.yes = private_file(tmp / 'wrong.key', bob), True
    assert op.cmd_approvals(args) == 1
    assert not args.out.exists()
    with pytest.raises(FileExistsError):
        op.register_identity('alice', bob.public_key, identities)
    with pytest.raises(ValueError):
        op.register_identity('../escape', bob.public_key, identities)


def test_request_from_untrusted_warrant_is_not_published(setup):
    tmp, _, holder, alice, _, store, _, _ = setup
    alien = SigningKey.generate()
    warrant = mint_for_holder(alien, holder.public_key, {'restart_service': {}}, 600, 's',
        approval_gates=['restart_service'], approvers=[alice.public_key])
    guard = SessionGuard(tmp / 'sessions', signing_key=holder, trusted_roots=[SigningKey.generate().public_key],
                         operation_approval_store=store)
    attach_encoded_warrant(warrant.to_base64(), 's', tmp / 'sessions')
    assert guard.pre_tool_call('restart_service', {}, session_id='s')
    assert not store.requests.exists()


def test_cli_mint_with_registered_approver_and_no_secret_leak(tmp_path):
    issuer, holder, alice = [SigningKey.generate() for _ in range(3)]
    issuer_key = private_file(tmp_path / 'issuer.key', issuer)
    holder_pub = public_file(tmp_path / 'holder.pub', holder)
    alice_pub = public_file(tmp_path / 'alice.pub', alice)
    identities = tmp_path / 'identities'
    cli('approver', 'register', 'alice', '--public-key', alice_pub, '--identities-dir', identities)
    path = tmp_path / 'gated.warrant'
    text = cli('mint', '--issuer-key', issuer_key, '--holder-public-key', holder_pub,
        '--allow', 'restart_service:service=example', '--require-approval', 'restart_service',
        '--approver', 'alice', '--identities-dir', identities, '--session-id', 'conversation', '--out', path)
    from tenuo import Warrant
    warrant = Warrant.from_base64(path.read_text().strip())
    assert warrant.approval_requirement('restart_service', {'service': 'example'}).requires_approval()
    assert warrant.required_approvers()[0].to_bytes() == alice.public_key.to_bytes()
    assert base64.b64encode(issuer.secret_key_bytes()).decode() not in text
    assert base64.b64encode(holder.secret_key_bytes()).decode() not in text


def test_conditional_gate_uses_core_matching_and_alternative_grant(setup):
    from tenuo import Exact, Warrant
    tmp, issuer, holder, alice, _, store, _, _ = setup
    warrant = (Warrant.mint_builder().holder(holder.public_key).ttl(600).session_id('conversation')
        .capability('restart_service').approval_gates({'restart_service': {'environment': Exact('production')}})
        .required_approvers([alice.public_key]).min_approvals(1).mint(issuer))
    attach_encoded_warrant(warrant.to_base64(), 'conversation', tmp / 'sessions')
    guard = SessionGuard(tmp / 'sessions', signing_key=holder, trusted_roots=[issuer.public_key],
                         operation_approval_store=store)
    assert guard.pre_tool_call('restart_service', {'environment': 'development'}, session_id='conversation') is None
    assert not store.requests.exists()
    assert guard.pre_tool_call('restart_service', {'environment': 'production'}, session_id='conversation')
    other = mint_for_holder(issuer, holder.public_key, {'restart_service': {'environment': Exact('production')}},
                            600, 'conversation')
    attach_encoded_warrant(other.to_base64(), 'conversation', tmp / 'sessions')
    # Each attached grant is independently authoritative; approval requirements
    # on one grant are not a global deny on another explicitly issued grant.
    assert guard.pre_tool_call('restart_service', {'environment': 'production'}, session_id='conversation') is None


def test_configuration_paths_and_missing_settings_fail_closed(tmp_path, monkeypatch):
    from hermes_tenuo import _config, _home
    from hermes_tenuo._guard import build_plugin_guard, WarrantLoadError
    entry = {'operation_requests_dir': 'outgoing', 'operation_approvals_dir': 'incoming'}
    monkeypatch.setattr(_config, '_get_plugin_entry', lambda ctx: entry)
    monkeypatch.setattr(_home, 'hermes_home', lambda: tmp_path)
    store = op.configured_store(None)
    assert store.requests == tmp_path / 'outgoing'
    assert store.responses == tmp_path / 'incoming'
    entry.pop('operation_approvals_dir')
    with pytest.raises(WarrantLoadError, match='configure both'):
        build_plugin_guard(None)
    entry['operation_approvals_dir'] = 'outgoing/nested'
    with pytest.raises(WarrantLoadError, match='non-nested'):
        build_plugin_guard(None)
    entry['operation_approvals_dir'] = ' '
    with pytest.raises(WarrantLoadError, match='nonempty'):
        build_plugin_guard(None)
    with pytest.raises(ValueError, match='on_denial: block'):
        HermesGuard(operation_approval_store=store, on_denial='log')


def test_response_reimport_preserves_group_read_permissions(setup):
    import stat
    _, _, _, alice, _, store, _, create = setup
    _, guard = create()
    path, request, warrant = pending(setup, guard)
    publish(setup, path, request, warrant, alice)
    output = next(store.responses.rglob(f'{op.fingerprint(alice.public_key)}.json'))
    output.chmod(0o640)
    publish(setup, path, request, warrant, alice)
    assert stat.S_IMODE(output.stat().st_mode) == 0o640


def test_audit_post_timing_preserves_verified_identity(tmp_path):
    from hermes_tenuo.audit import LocalAuditLog, read_audit_log
    from hermes_tenuo.hermes_guard import HermesAuditEvent
    path = tmp_path / 'audit.jsonl'
    log = LocalAuditLog(path)
    identity = [{'identity': 'alice', 'fingerprint': 'verified-fingerprint'}]
    log(HermesAuditEvent('restart_service', {}, 'ALLOW', '', tool_call_id='call', approvers=identity))
    log(HermesAuditEvent('restart_service', {}, 'ALLOW', '', tool_call_id='call', duration_ms=100))
    assert read_audit_log(path)[0]['approvers'] == identity


def test_pending_request_cap_and_tampering_never_allow_execution(setup, monkeypatch):
    _, _, _, _, _, store, _, create = setup
    _, guard = create()
    path, request, _ = pending(setup, guard)
    # Repeated blocked attempts reuse the existing file instead of flooding disk.
    for _ in range(3):
        assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    assert len(list(store.requests.rglob('*.operation.json'))) == 1
    monkeypatch.setattr(op, 'MAX_PENDING', 1)
    assert guard.pre_tool_call('restart_service', {'service': 'other'}, session_id='conversation')
    assert len(list(store.requests.rglob('*.operation.json'))) == 1
    data = op._load(path)
    data['arguments'] = {'service': 'modified'}
    path.write_text(json.dumps(data))
    assert guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')


def test_expired_warrant_and_other_holder_or_warrant_cannot_use_approval(setup):
    tmp, issuer, holder, alice, _, store, _, create = setup
    _, guard = create(ttl=60)
    path, request, warrant = pending(setup, guard)
    publish(setup, path, request, warrant, alice)
    other_holder = SigningKey.generate()
    wrong_holder_guard = SessionGuard(tmp / 'sessions', signing_key=other_holder,
        trusted_roots=[issuer.public_key], operation_approval_store=store)
    assert wrong_holder_guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    other_warrant = mint_for_holder(issuer, holder.public_key, {'restart_service': {}}, 600, 'conversation',
        approval_gates=['restart_service'], approvers=[alice.public_key])
    other_guard = HermesGuard(other_warrant, holder, trusted_roots=[issuer.public_key], operation_approval_store=store)
    assert other_guard.pre_tool_call('restart_service', request.arguments, session_id='conversation')
    short = mint_for_holder(issuer, holder.public_key, {'restart_service': {}}, 1, 'short',
        approval_gates=['restart_service'], approvers=[alice.public_key])
    time.sleep(1.1)
    with pytest.raises(ValueError, match='expired'):
        op.verify_warrant(short, [issuer.public_key])


def test_signs_reviewed_snapshot_when_request_file_changes(setup, monkeypatch):
    tmp, issuer, _, alice, _, _, _, create = setup
    _, guard = create()
    path, request, warrant = pending(setup, guard)
    identities = tmp / 'identities'
    op.register_identity('alice', alice.public_key, identities)
    root = public_file(tmp / 'issuer.pub', issuer)
    key = private_file(tmp / 'alice.key', alice)
    out = tmp / 'response.json'
    def approve_after_file_edit(prompt):
        data = op._load(path)
        data['arguments'] = {'service': 'modified-after-review'}
        path.write_text(json.dumps(data))
        return 'y'
    monkeypatch.setattr('builtins.input', approve_after_file_edit)
    args = argparse.Namespace(request=path, trusted_root=root, approvals_command='sign',
        identity='alice', identities_dir=identities, key=key, ttl='5m', yes=False, out=out)
    assert op.cmd_approvals(args) == 0
    signed = op.response_approval(op._load(out), request, warrant)
    assert bytes(signed.verify().request_hash) == request.request_hash


@pytest.mark.parametrize('config', [
    {'approval_gates': ['missing'], 'approvers': []},
    {'approval_gates': ['restart_service'], 'approvers': []},
    {'approval_gates': [], 'approvers': [SigningKey.generate().public_key]},
    {'approval_gates': ['restart_service'], 'approvers': [SigningKey.generate().public_key], 'min_approvals': 2},
    {'min_approvals': 2},
])
def test_misconfigured_gate_cannot_silently_mint_ungated_warrant(config):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    with pytest.raises(ValueError):
        mint_for_holder(issuer, holder.public_key, {'restart_service': {}}, 600, **config)


def test_approval_files_reject_duplicate_fields_oversize_and_nonfinite(tmp_path):
    path = tmp_path / 'request.json'
    for raw in ['{"version":1,"version":1}', '{"amount":NaN}', 'x' * (op.MAX_BYTES + 1)]:
        path.write_text(raw)
        with pytest.raises(ValueError):
            op._load(path)


def test_review_delay_cannot_extend_approval_past_warrant_expiry(setup, monkeypatch):
    tmp, issuer, _, alice, _, _, _, create = setup
    _, guard = create()
    path, request, warrant = pending(setup, guard)
    identities = tmp / 'identities'
    op.register_identity('alice', alice.public_key, identities)
    root = public_file(tmp / 'issuer.pub', issuer)
    key = private_file(tmp / 'alice.key', alice)
    out = tmp / 'response.json'
    real_now = time.time()
    def slow_review(prompt):
        monkeypatch.setattr(op.time, 'time', lambda: real_now + 10)
        return 'y'
    monkeypatch.setattr('builtins.input', slow_review)
    args = argparse.Namespace(request=path, trusted_root=root, approvals_command='sign',
        identity='alice', identities_dir=identities, key=key, ttl='20m', yes=False, out=out)
    assert op.cmd_approvals(args) == 0
    data = op._load(out)
    signed = SignedApproval.from_bytes(base64.b64decode(data['approval']))
    assert signed.verify().expires_at == request.warrant_expires_at_unix
