"""Native SRLs and core verification, exercised through local CLI and guards."""
import base64
import json
import subprocess
import sys

import pytest
from tenuo import SigningKey, Warrant, SignedRevocationList

from hermes_tenuo.revocation import RevocationStore, import_srl, read_srl, _latest
from hermes_tenuo.session_guard import SessionGuard
from hermes_tenuo.hermes_guard import HermesGuard
from hermes_tenuo.session_store import attach_encoded_warrant, detach_warrant


def cli(*args, success=True):
    result = subprocess.run([sys.executable, '-m', 'hermes_tenuo.cli', *map(str, args)], capture_output=True, text=True)
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    return result


def keyfile(path, key, private=False):
    path.write_text(base64.b64encode(key.secret_key_bytes() if private else key.public_key.to_bytes()).decode())
    return path


@pytest.fixture
def setup(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().holder(holder.public_key).capability('read_file').ttl(600).mint(issuer)
    directory = tmp_path / 'revocations'
    empty = SignedRevocationList.builder().version(1).build(issuer)
    import_srl(empty, directory, [issuer.public_key])
    return tmp_path, issuer, holder, warrant, directory, empty


@pytest.mark.parametrize('static', [False, True])
def test_live_revocation_blocks_handler_without_detaching_and_survives_restart(setup, static):
    from tenuo.runtime import get_runtime
    tmp, issuer, holder, warrant, directory, empty = setup
    events = []
    def create():
        store = RevocationStore(directory)
        if static:
            return HermesGuard(warrant, holder, trusted_roots=[issuer.public_key],
                               revocation_store=store, audit_callback=events.append)
        return SessionGuard(tmp / 'sessions', signing_key=holder, trusted_roots=[issuer.public_key],
                            revocation_store=store, audit_callback=events.append)
    for session in ('a', 'b'):
        attach_encoded_warrant(warrant.to_base64(), session, tmp / 'sessions')
    guard = create()
    calls = []
    def dispatch(session='a'):
        denial = guard.pre_tool_call('read_file', {}, session_id=session)
        if denial is None:
            calls.append(session)
        return denial
    outer_runtime = get_runtime()
    assert dispatch() is None and calls == ['a']
    revoked = SignedRevocationList.builder().from_existing(empty).revoke(str(warrant.id)).version(2).build(issuer)
    import_srl(revoked, directory, [issuer.public_key])
    assert 'revoked' in dispatch()['message'].lower()
    assert 'revoked' in dispatch('b')['message'].lower()
    assert calls == ['a']
    assert events[-1].decision == 'DENY' and 'revoked' in events[-1].reason.lower()
    detach_warrant('a', str(warrant.id), tmp / 'sessions')
    attach_encoded_warrant(warrant.to_base64(), 'a', tmp / 'sessions')
    guard = create()
    assert 'revoked' in guard.pre_tool_call('read_file', {}, session_id='a')['message'].lower()
    assert get_runtime() is outer_runtime


def test_cli_creates_native_core_list_and_imports_external_core_list(setup):
    tmp, issuer, _, warrant, directory, empty = setup
    issuer_key = keyfile(tmp / 'issuer.key', issuer, True)
    root = keyfile(tmp / 'issuer.pub', issuer)
    initial = tmp / 'initial.srl'
    cli('revocations', 'create', '--issuer-key', issuer_key, '--out', initial)
    assert read_srl(initial).version == 1
    output = tmp / 'revoked.srl'
    cli('revocations', 'create', '--issuer-key', issuer_key, '--from', initial,
        '--revoke', str(warrant.id), '--out', output)
    native = SignedRevocationList.from_bytes(output.read_bytes())
    assert native.version == 2 and native.is_revoked(str(warrant.id))
    cli('revocations', 'show', output, '--trusted-root', root)
    cli('revocations', 'import', output, '--trusted-root', root, '--directory', directory)
    # Idempotent import does not create another version.
    cli('revocations', 'import', output, '--trusted-root', root, '--directory', directory)
    assert len(list(directory.glob('*.srl'))) == 2
    # An artifact built directly with core is accepted without wrapping/conversion.
    external = tmp / 'external.srl'
    external.write_bytes(SignedRevocationList.builder().from_existing(native).version(3).build(issuer).to_bytes())
    cli('revocations', 'import', external, '--trusted-root', root, '--directory', directory)
    assert _latest(directory).version == 3
    cli('revocations', 'create', '--issuer-key', issuer_key, '--out', initial, success=False)


@pytest.mark.parametrize('failure', ['untrusted', 'tampered', 'older', 'same_version'])
def test_import_rejects_invalid_or_unsafe_updates_without_changing_current(setup, failure):
    _, issuer, _, warrant, directory, empty = setup
    other = SigningKey.generate()
    current = SignedRevocationList.builder().from_existing(empty).version(2).revoke(str(warrant.id)).build(issuer)
    import_srl(current, directory, [issuer.public_key, other.public_key])
    if failure == 'untrusted':
        candidate = SignedRevocationList.builder().from_existing(current).version(3).build(other)
    elif failure == 'older':
        candidate = empty
    elif failure == 'same_version':
        candidate = SignedRevocationList.builder().version(2).build(issuer)
    else:
        raw = bytearray(current.to_bytes())
        raw[-1] ^= 1
        try:
            candidate = SignedRevocationList.from_bytes(bytes(raw))
        except Exception:
            assert _latest(directory).version == 2
            return
    roots = [issuer.public_key] if failure == 'untrusted' else [issuer.public_key, other.public_key]
    with pytest.raises(Exception):
        import_srl(candidate, directory, roots)
    assert _latest(directory).to_bytes() == current.to_bytes()


@pytest.mark.parametrize('failure', ['missing', 'corrupt', 'symlink', 'wrong_filename', 'rollback'])
def test_configured_store_fails_closed_on_missing_invalid_or_rolled_back_data(setup, failure):
    tmp, issuer, holder, warrant, directory, empty = setup
    store = RevocationStore(directory)
    guard = HermesGuard(warrant, holder, trusted_roots=[issuer.public_key], revocation_store=store)
    assert guard.pre_tool_call('read_file', {}, session_id='a') is None
    current = directory / '00000000000000000001.srl'
    if failure == 'missing':
        current.unlink()
    elif failure == 'corrupt':
        current.write_bytes(b'bad CBOR')
    elif failure == 'symlink':
        original = tmp / 'original.srl'
        current.rename(original)
        current.symlink_to(original)
    elif failure == 'wrong_filename':
        current.rename(directory / '00000000000000000002.srl')
    else:
        newer = SignedRevocationList.builder().version(2).build(issuer)
        import_srl(newer, directory, [issuer.public_key])
        assert guard.pre_tool_call('read_file', {}, session_id='a') is None
        (directory / '00000000000000000002.srl').unlink()
    assert guard.pre_tool_call('read_file', {}, session_id='a')['action'] == 'block'


def test_other_grant_still_authorizes_and_revocation_does_not_leak_between_profiles(setup):
    tmp, issuer, holder, warrant, directory, empty = setup
    revoked = SignedRevocationList.builder().from_existing(empty).version(2).revoke(str(warrant.id)).build(issuer)
    import_srl(revoked, directory, [issuer.public_key])
    second = Warrant.mint_builder().holder(holder.public_key).capability('read_file').ttl(600).mint(issuer)
    for w in (warrant, second):
        attach_encoded_warrant(w.to_base64(), 'a', tmp / 'sessions')
    guard = SessionGuard(tmp / 'sessions', signing_key=holder, trusted_roots=[issuer.public_key],
                         revocation_store=RevocationStore(directory))
    assert guard.pre_tool_call('read_file', {}, session_id='a') is None
    other = tmp / 'other-profile-revocations'
    import_srl(empty, other, [issuer.public_key])
    other_guard = HermesGuard(warrant, holder, trusted_roots=[issuer.public_key], revocation_store=RevocationStore(other))
    assert other_guard.pre_tool_call('read_file', {}, session_id='a') is None


def test_decoded_show_and_list_expose_ids_capabilities_and_revocation(setup, capsys):
    tmp, issuer, holder, warrant, directory, empty = setup
    encoded = tmp / 'read.warrant'
    encoded.write_text(warrant.to_base64())
    public = keyfile(tmp / 'issuer.pub', issuer)
    sessions = tmp / 'sessions'
    for session in ('a', 'b'):
        attach_encoded_warrant(warrant.to_base64(), session, sessions)
    result = cli('warrants', 'list', '--directory', sessions, '--trusted-root', public, '--revocations-dir', directory)
    row = json.loads(result.stdout)['published'][0]
    assert row['warrant_id'] == str(warrant.id)
    assert set(row['attached_sessions']) == {'a', 'b'}
    assert row['revoked'] is False
    for target in (str(warrant.id), encoded):
        result = cli('warrants', 'show', target, '--directory', sessions, '--trusted-root', public, '--revocations-dir', directory)
        view = json.loads(result.stdout)
        assert view['capabilities'] == {'read_file': {}}
        assert view['holder_public_key'] == base64.b64encode(holder.public_key.to_bytes()).decode()
        assert view['signature_valid'] is True and view['issuer_trusted'] is True
        assert 'built-in method' not in view['expires_at']
    revoked = SignedRevocationList.builder().from_existing(empty).version(2).revoke(str(warrant.id)).build(issuer)
    import_srl(revoked, directory, [issuer.public_key])
    result = cli('warrants', 'show', encoded, '--trusted-root', public, '--revocations-dir', directory)
    assert json.loads(result.stdout)['revoked'] is True


def test_newer_snapshot_semantics_and_signer_trust_follow_core(setup):
    _, issuer, _, warrant, directory, empty = setup
    current = SignedRevocationList.builder().version(2).revoke(str(warrant.id)).build(issuer)
    import_srl(current, directory, [issuer.public_key])
    # Core treats a newer signed SRL as an authoritative replacement snapshot.
    # --from retains entries when using our CLI, but imports do not invent a
    # different SRL format or forbid updates accepted by the trusted authorizer.
    other_trusted_signer = SigningKey.generate()
    newer = SignedRevocationList.builder().version(3).build(other_trusted_signer)
    import_srl(newer, directory, [issuer.public_key, other_trusted_signer.public_key])
    assert _latest(directory).version == 3
    assert not _latest(directory).is_revoked(str(warrant.id))


def test_revoked_gated_warrant_does_not_generate_human_approval_request(setup):
    from hermes_tenuo.operation_approvals import OperationApprovalStore
    tmp, issuer, holder, _, directory, empty = setup
    approver = SigningKey.generate()
    warrant = (Warrant.mint_builder().holder(holder.public_key).capability('restart_service')
        .approval_gates({'restart_service': None}).required_approvers([approver.public_key]).ttl(600).mint(issuer))
    revoked = SignedRevocationList.builder().version(2).revoke(str(warrant.id)).build(issuer)
    import_srl(revoked, directory, [issuer.public_key])
    operation = OperationApprovalStore(tmp / 'requests', tmp / 'responses')
    guard = HermesGuard(warrant, holder, trusted_roots=[issuer.public_key],
                         revocation_store=RevocationStore(directory), operation_approval_store=operation)
    result = guard.pre_tool_call('restart_service', {}, session_id='a')
    assert 'revoked' in result['message'].lower()
    assert not operation.requests.exists()


def test_revoked_parent_denies_delegated_child_using_core_chain_verification(setup):
    tmp, issuer, holder, parent, directory, empty = setup
    child_holder = SigningKey.generate()
    builder = parent.attenuate_builder()
    builder.inherit_all()
    builder.with_holder(child_holder.public_key)
    builder.with_ttl(120)
    child = builder.delegate(holder)
    revoked = SignedRevocationList.builder().version(2).revoke(str(parent.id)).build(issuer)
    import_srl(revoked, directory, [issuer.public_key])
    guard = HermesGuard(trusted_roots=[issuer.public_key], revocation_store=RevocationStore(directory))
    guard.set_session_warrant('child', child, signing_key=child_holder, parent_warrant=parent)
    assert guard.pre_tool_call('read_file', {}, session_id='child')['action'] == 'block'


def test_inspection_still_decodes_when_revocation_data_is_unavailable(setup):
    tmp, issuer, _, warrant, directory, _ = setup
    encoded = tmp / 'read.warrant'
    encoded.write_text(warrant.to_base64())
    (directory / '00000000000000000001.srl').unlink()
    root = keyfile(tmp / 'issuer.pub', issuer)
    result = cli('warrants', 'show', encoded, '--trusted-root', root, '--revocations-dir', directory)
    data = json.loads(result.stdout)
    assert data['warrant_id'] == str(warrant.id) and data['capabilities'] == {'read_file': {}}
    assert data['revoked'] is None and data['revocation_error']


def test_configured_revocation_never_allows_observe_mode_or_unconfigured_guard(tmp_path, monkeypatch):
    from hermes_tenuo import _config
    from hermes_tenuo._guard import build_plugin_guard, WarrantLoadError
    entry = {'revocations_dir': str(tmp_path / 'srls')}
    monkeypatch.setattr(_config, '_get_plugin_entry', lambda ctx: entry)
    monkeypatch.setattr(_config, 'resolve_warrant_text', lambda ctx: (None, 'none'))
    with pytest.raises(WarrantLoadError, match='requires a warrant'):
        build_plugin_guard(None)
    entry['revocations_dir'] = ''
    with pytest.raises(WarrantLoadError, match='nonempty'):
        build_plugin_guard(None)
    with pytest.raises(ValueError, match='on_denial: block'):
        HermesGuard(revocation_store=RevocationStore(tmp_path / 'srls'), on_denial='log')


def test_malformed_manifest_is_reported_without_hiding_other_warrants(setup):
    tmp, issuer, holder, warrant, _, _ = setup
    from hermes_tenuo.warrant_inventory import published
    sessions = tmp / 'sessions'
    attach_encoded_warrant(warrant.to_base64(), 'good', sessions)
    (sessions / 'bad.json').write_text('bad JSON')
    entries, errors = published(sessions)
    assert str(warrant.id) in entries and len(errors) == 1
