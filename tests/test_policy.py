"""Policies compile to ordinary Tenuo constraints, never ambient authority."""
import argparse
import base64
import json

import pytest

from hermes_tenuo.policy import (
    PolicyError, capabilities_from_allow, compile_capabilities, load_policy, validate_policy,
)


@pytest.mark.parametrize('text', [
    'version: 1\nversion: 1\ncapabilities: {read_file: {}}',
    'version: 1\ncapabilities: {read_file: {path: {exact: a, exact: b}}}',
    'version: 1\ncapabilities: &caps {read_file: {}}',
    'version: 1\ncapabilities: *caps',
    '!!python/object/apply:os.system [echo unsafe]',
    'version: true\ncapabilities: {read_file: {}}',
    'version: 2\ncapabilities: {read_file: {}}',
    'version: 1\nissuer_key: /secret\ncapabilities: {read_file: {}}',
    'version: 1\ncapabilities: {}',
    'version: 1\nttl: 0m\ncapabilities: {read_file: {}}',
    'version: 1\nttl: 20\ncapabilities: {read_file: {}}',
    'version: 1\nttl: inf\ncapabilities: {read_file: {}}',
    'version: 1\ncapabilities: {read_file: {path: {unknown: x}}}',
    'version: 1\ncapabilities: {read_file: {path: {exact: x, wildcard: true}}}',
    'version: 1\ncapabilities: {read_file: {path: {subpath: ~/reports}}}',
    'version: 1\ncapabilities: {checkout: {amount: {range: {min: true, max: 10}}}}',
    'version: 1\ncapabilities: {checkout: {amount: {range: {min: 20, max: 10}}}}',
    'version: 1\ncapabilities: {checkout: {amount: {range: {min: 0, max: .inf}}}}',
    'version: 1\ncapabilities: {checkout: {amount: {range: {min: 0, max: 9007199254740992}}}}',
    'version: 1\ncapabilities: {tool: {x: {one_of: []}}}',
    'version: 1\ncapabilities: {tool: {x: {exact: 12}}}',
    'version: 1\ncapabilities: {tool: {x: {wildcard: false}}}',
])
def test_reject_malformed(tmp_path, text):
    path = tmp_path / 'policy.yaml'
    path.write_text(text)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_size_limit(tmp_path):
    path = tmp_path / 'policy.yaml'
    path.write_text(' ' * (1024 * 1024 + 1))
    with pytest.raises(PolicyError, match='1 MiB'):
        load_policy(path)


def test_cli_canonical_roundtrip():
    specs = ['read_file:path=/data/reports', 'web_search:query=example*',
             'checkout:amount=0..100', 'git:action=status|diff', 'tool:x=*,y=literal']
    caps = capabilities_from_allow(specs)
    compiled = compile_capabilities(json.loads(json.dumps(caps)))
    from hermes_tenuo.cli import parse_allow
    for spec in specs:
        tool, constraints, _ = parse_allow(spec)
        for arg, constraint in constraints.items():
            assert repr(compiled[tool][arg]) == repr(constraint)
    with pytest.raises(PolicyError, match='duplicate tool'):
        capabilities_from_allow(['read_file', 'read_file:path=/data'])


def test_policy_scope_enforced(tmp_path, capsys):
    from hermes_tenuo.cli import cmd_mint
    from hermes_tenuo.hermes_guard import HermesGuard
    from tenuo import PublicKey, SigningKey, Warrant
    path = tmp_path / 'policy.yaml'
    path.write_text('''version: 1
name: report-reader
ttl: 20m
capabilities:
  read_file:
    path: {subpath: /data/reports}
  checkout:
    amount: {range: {min: 0, max: 100}}
''')
    assert cmd_mint(argparse.Namespace(policy=str(path), allow=None, ttl=None, output='env')) == 0
    env = dict(line[7:].split('=', 1) for line in capsys.readouterr().out.splitlines() if line.startswith('export '))
    guard = HermesGuard(
        warrant=Warrant.from_bytes(base64.b64decode(env['TENUO_WARRANT'])),
        signing_key=SigningKey.from_bytes(base64.b64decode(env['TENUO_SIGNING_KEY'])),
        trusted_roots=[PublicKey.from_bytes(base64.b64decode(env['TENUO_TRUSTED_ROOT']))],
    )
    assert guard.pre_tool_call('read_file', {'path': '/data/reports/month.txt'}, session_id='s') is None
    assert guard.pre_tool_call('checkout', {'amount': 100}, session_id='s') is None
    for tool, args in [('read_file', {'path': '/etc/passwd'}), ('read_file', {'path': '/data/reports/../secret'}),
                       ('checkout', {'amount': 101}), ('checkout', {'amount': '50'}), ('write_file', {})]:
        assert guard.pre_tool_call(tool, args, session_id='s')['action'] == 'block'


def test_policy_commands_and_exclusive_scope(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.cli import main
    path = tmp_path / 'policy.yaml'
    path.write_text('version: 1\ncapabilities: {web_search: {}}')
    for command in ('validate', 'show'):
        monkeypatch.setattr('sys.argv', ['hermes-tenuo', 'policy', command, str(path)])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        output = capsys.readouterr().out
        assert ('Policy valid' if command == 'validate' else 'capabilities') in output
    monkeypatch.setattr('sys.argv', ['hermes-tenuo', 'mint', '--policy', str(path), '--allow', 'web_search'])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_canonical_no_interpolation_and_copy():
    raw = {'version': 1, 'capabilities': {'tool': {'x': {'exact': '${SECRET}'}}}}
    policy = validate_policy(raw)
    raw['capabilities']['tool'].clear()
    assert policy['capabilities']['tool']['x']['exact'] == '${SECRET}'


@pytest.mark.parametrize(('policy_ttl', 'override', 'expected'), [
    ('20m', None, 1200), ('20m', '10m', 600), (None, None, 86400),
])
def test_policy_ttl_precedence(tmp_path, capsys, policy_ttl, override, expected):
    from hermes_tenuo.cli import cmd_mint
    from tenuo import Warrant
    path = tmp_path / 'scope.json'
    policy = {'version': 1, 'capabilities': {'web_search': {}}}
    if policy_ttl:
        policy['ttl'] = policy_ttl
    path.write_text(json.dumps(policy))
    assert cmd_mint(argparse.Namespace(policy=str(path), allow=None, ttl=override, output='env')) == 0
    env = dict(line[7:].split('=', 1) for line in capsys.readouterr().out.splitlines() if line.startswith('export '))
    warrant = Warrant.from_bytes(base64.b64decode(env['TENUO_WARRANT']))
    assert expected - 5 <= warrant.ttl_seconds() <= expected


@pytest.mark.parametrize('kind,value', [('exact', 1), ('exact', True), ('one_of', ['x', 1])])
def test_unsupported_scalar_types_rejected(kind, value):
    with pytest.raises(PolicyError):
        validate_policy({'version': 1, 'capabilities': {'tool': {'arg': {kind: value}}}})


def test_cli_duplicate_argument_rejected():
    with pytest.raises(ValueError, match='duplicate argument'):
        capabilities_from_allow(['read_file:path=/data,path=/etc'])


def test_policy_separate_issuance(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.cli import cmd_mint
    from tenuo import SigningKey, Warrant
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    issuer_path, holder_path = tmp_path / 'issuer.key', tmp_path / 'holder.pub'
    issuer_path.write_text(base64.b64encode(issuer.secret_key_bytes()).decode())
    holder_path.write_text(base64.b64encode(holder.public_key.to_bytes()).decode())
    scope = tmp_path / 'scope.yaml'
    scope.write_text('version: 1\nttl: 20m\ncapabilities: {read_file: {path: {subpath: /data/reports}}}')
    monkeypatch.setenv('TENUO_SIGNING_KEY', 'not-a-valid-key')
    out = tmp_path / 'reports.warrant'
    args = argparse.Namespace(policy=str(scope), allow=None, ttl='10m', issuer_key=str(issuer_path),
                              holder_public_key=str(holder_path), out=str(out), session_id='session-1')
    assert cmd_mint(args) == 0
    warrant = Warrant.from_base64(out.read_text().strip())
    assert 595 <= warrant.ttl_seconds() <= 600
    assert warrant.holder_key.to_bytes() == holder.public_key.to_bytes()
    assert 'TENUO_SIGNING_KEY' not in capsys.readouterr().out


def test_arbitrary_precision_range_rejected():
    with pytest.raises(PolicyError):
        validate_policy({'version': 1, 'capabilities': {'tool': {'x': {'range': {'min': 0, 'max': 10 ** 1000}}}}})
