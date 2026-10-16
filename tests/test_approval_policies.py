"""Declarative local approval policies freeze keys into requests and warrants."""
import argparse
import base64
import copy
import json

import pytest
from tenuo import SigningKey, Warrant

from hermes_tenuo import policy as p
from hermes_tenuo import authority_requests as ar
from hermes_tenuo import operation_approvals as op
from hermes_tenuo.cli import cmd_mint


def write_key(path, key, private=False):
    path.write_text(base64.b64encode(key.secret_key_bytes() if private else key.public_key.to_bytes()).decode())
    return path


@pytest.fixture
def scope(tmp_path):
    operator = SigningKey.generate()
    folder = tmp_path / 'policies'
    folder.mkdir()
    write_key(folder / 'operator.pub', operator)
    raw = {'version': 2, 'name': 'service-maintenance', 'ttl': '20m',
           'capabilities': {'get_service_status': {'service': {'exact': 'example'}},
                            'restart_service': {'service': {'exact': 'example'}}},
           'approvals': {'keys': ['./operator.pub'], 'gates': {'restart_service': {'always': True}}}}
    path = folder / 'policy.yaml'
    path.write_text(json.dumps(raw))
    return path, raw, operator


def test_relative_keys_and_inspection_are_independent_of_shell_cwd(scope, tmp_path, monkeypatch, capsys):
    path, raw, operator = scope
    monkeypatch.chdir(tmp_path)
    loaded = p.load_policy(path)
    resolved = p.resolve_policy_approvals(loaded, path)
    assert resolved['public_keys'] == [base64.b64encode(operator.public_key.to_bytes()).decode()]
    assert p.cmd_policy(argparse.Namespace(path=path, policy_command='validate')) == 0
    capsys.readouterr()
    assert p.cmd_policy(argparse.Namespace(path=path, policy_command='show')) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown['resolved_approval_keys'][0]['fingerprint'] == op.fingerprint(operator.public_key)


@pytest.mark.parametrize('mutation', ['threshold', 'empty_keys', 'empty_gates', 'unknown_tool',
                                     'conditional', 'always_false', 'always_integer', 'private_key_field', 'v1'])
def test_invalid_or_unsupported_rules_never_silently_become_ungated(scope, mutation):
    _, raw, _ = scope
    data = copy.deepcopy(raw)
    approval = data['approvals']
    if mutation == 'threshold':
        approval['threshold'] = 1
    elif mutation == 'empty_keys':
        approval['keys'] = []
    elif mutation == 'empty_gates':
        approval['gates'] = {}
    elif mutation == 'unknown_tool':
        approval['gates'] = {'delete_service': {'always': True}}
    elif mutation == 'conditional':
        approval['gates']['restart_service'] = {'exempt': {'amount': {'range': {'min': 1, 'max': 5000}}}}
    elif mutation == 'always_false':
        approval['gates']['restart_service'] = {'always': False}
    elif mutation == 'always_integer':
        approval['gates']['restart_service'] = {'always': 1}
    elif mutation == 'private_key_field':
        approval['private_key'] = './operator.key'
    elif mutation == 'v1':
        data['version'] = 1
    with pytest.raises(p.PolicyError):
        p.validate_policy(data)


def test_key_files_must_exist_be_valid_and_represent_distinct_keys(scope, tmp_path):
    path, raw, operator = scope
    raw['approvals']['keys'] = ['missing.pub']
    with pytest.raises(p.PolicyError, match='cannot load'):
        p.resolve_policy_approvals(raw, path)
    raw['approvals']['keys'] = ['bad.pub']
    (path.parent / 'bad.pub').write_text('not a public key')
    with pytest.raises(p.PolicyError, match='cannot load'):
        p.resolve_policy_approvals(raw, path)
    write_key(path.parent / 'duplicate.pub', operator)
    raw['approvals']['keys'] = ['operator.pub', 'duplicate.pub']
    with pytest.raises(p.PolicyError, match='distinct'):
        p.resolve_policy_approvals(raw, path)


def test_policy_mint_embeds_rules_and_keys_once(scope, tmp_path, monkeypatch):
    path, _, operator = scope
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    issuer_path = write_key(tmp_path / 'issuer.key', issuer, True)
    holder_path = write_key(tmp_path / 'holder.pub', holder)
    args = argparse.Namespace(policy=str(path), allow=None, ttl=None, issuer_key=issuer_path,
        holder_public_key=holder_path, out=tmp_path / 'issued.warrant', session_id='example',
        require_approval=None, approver=None, approver_public_key=None)
    assert cmd_mint(args) == 0
    warrant = Warrant.from_base64(args.out.read_text().strip())
    assert warrant.approval_threshold() == 1
    assert warrant.required_approvers()[0].to_bytes() == operator.public_key.to_bytes()
    assert warrant.approval_requirement('restart_service', {'service': 'example'}).requires_approval()
    assert not warrant.approval_requirement('get_service_status', {'service': 'example'}).requires_approval()
    write_key(path.parent / 'operator.pub', SigningKey.generate())
    path.unlink()
    assert warrant.required_approvers()[0].to_bytes() == operator.public_key.to_bytes()
    assert warrant.verify(issuer.public_key.to_bytes())


def test_gated_policy_cannot_fall_back_to_legacy_mint_or_merge_cli_settings(scope, tmp_path):
    path, _, _ = scope
    args = argparse.Namespace(policy=str(path), allow=None, ttl=None, output='env')
    assert cmd_mint(args) == 1
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    args.issuer_key = write_key(tmp_path / 'issuer.key', issuer, True)
    args.holder_public_key = write_key(tmp_path / 'holder.pub', holder)
    args.out = tmp_path / 'issued.warrant'
    args.require_approval = ['restart_service']
    assert cmd_mint(args) == 1
    assert not args.out.exists()


def test_portable_issuance_request_preserves_gates_without_following_paths_on_control_side(scope, tmp_path):
    path, _, operator = scope
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    holder_pub = write_key(tmp_path / 'holder.pub', holder)
    requested = tmp_path / 'authority.request.json'
    args = argparse.Namespace(policy=path, allow=None, ttl=None, holder_public_key=holder_pub,
        session='example', description='Maintain one example service', out=requested)
    assert ar.cmd_request_create(args) == 0
    request = ar.load_request(requested)
    assert request['version'] == 2
    assert 'keys' not in request['approvals']
    assert request['approvals']['public_keys'] == [base64.b64encode(operator.public_key.to_bytes()).decode()]
    write_key(path.parent / 'operator.pub', SigningKey.generate())
    path.unlink()
    warrant = ar.approve_request(request, issuer, tmp_path / 'issued.warrant')
    assert warrant.required_approvers()[0].to_bytes() == operator.public_key.to_bytes()
    assert warrant.approval_requirement('restart_service', {'service': 'example'}).requires_approval()
    for version in (1, 2):
        broken = copy.deepcopy(request)
        broken['version'] = version
        if version == 2:
            broken['approvals']['public_keys'] = ['./operator.pub']
        with pytest.raises(ValueError):
            ar.validate_request(broken)


def test_direct_key_signing_needs_no_registered_name(scope, tmp_path):
    from tenuo_core import py_compute_request_hash
    from tenuo.approval import ApprovalRequest
    from hermes_tenuo.issuance import mint_for_holder
    path, raw, operator = scope
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    snapshot = p.resolve_policy_approvals(raw, path)
    warrant = mint_for_holder(issuer, holder.public_key, p.compile_capabilities(raw['capabilities']),
                              600, 'example', **p.approval_mint_kwargs(snapshot))
    arguments = {'service': 'example'}
    request = ApprovalRequest.for_warrant_gate('restart_service', arguments, warrant,
        py_compute_request_hash(str(warrant.id), 'restart_service', arguments, holder.public_key),
        holder_key=holder.public_key)
    req_path = tmp_path / 'operation.json'
    req_path.write_text(json.dumps(op.request_document(request, warrant, 'example')))
    out = tmp_path / 'response.json'
    args = argparse.Namespace(request=req_path, trusted_root=write_key(tmp_path / 'issuer.pub', issuer),
        approvals_command='sign', key=write_key(tmp_path / 'operator.key', operator, True),
        ttl='5m', yes=True, out=out)
    assert op.cmd_approvals(args) == 0
    signed = op.response_approval(op._load(out), request, warrant)
    assert signed.approver_key.to_bytes() == operator.public_key.to_bytes()
    assert signed.verify().external_id == ''


def test_any_listed_key_can_approve_without_configurable_threshold(scope, tmp_path):
    from tenuo._enforcement import enforce_tool_call
    from tenuo.approval import sign_approval
    from hermes_tenuo.issuance import mint_for_holder
    path, raw, first = scope
    second = SigningKey.generate()
    write_key(path.parent / 'second.pub', second)
    raw['approvals']['keys'].append('./second.pub')
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    snapshot = p.resolve_policy_approvals(raw, path)
    warrant = mint_for_holder(issuer, holder.public_key, p.compile_capabilities(raw['capabilities']),
                              600, 'example', **p.approval_mint_kwargs(snapshot))
    assert warrant.approval_threshold() == 1
    for signer in (first, second):
        result = enforce_tool_call(tool_name='restart_service', tool_args={'service': 'example'},
            bound_warrant=warrant.bind(holder), trusted_roots=[issuer.public_key],
            approval_handler=lambda request: sign_approval(request, signer, ttl_seconds=60))
        assert result.allowed


def test_issuance_review_displays_approval_key_fingerprints(scope):
    path, raw, operator = scope
    snapshot = p.resolve_policy_approvals(raw, path)
    holder = SigningKey.generate()
    request = ar.new_request(holder.public_key, 'example', raw['capabilities'], '20m',
                             'Maintain an example service', approvals=snapshot)
    text = ar.review_text(request)
    assert 'Approval keys (SHA256):' in text
    assert op.fingerprint(operator.public_key) in text
