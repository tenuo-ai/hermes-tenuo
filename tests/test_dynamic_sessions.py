"""Real SDK checks for operator-published dynamic session authority."""
import base64
import json
import time

import pytest
from tenuo import Exact, SigningKey, Warrant

from hermes_tenuo.session_guard import SessionGuard
from hermes_tenuo.session_store import attach_warrant, detach_warrant, _path


def issue(tmp_path, issuer, holder, tool='read_file', constraints=None, ttl=60, session=None):
    builder = Warrant.mint_builder().holder(holder.public_key).ttl(ttl).capability(tool, **(constraints or {}))
    if session is not None:
        builder = builder.session_id(session)
    warrant = builder.mint(issuer)
    path = tmp_path / f'{warrant.id}.warrant'
    path.write_text(base64.b64encode(warrant.to_bytes()).decode())
    return path, str(warrant.id)


def test_live_attach_multiple_detach_and_isolation(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    events = []
    directory = tmp_path / 'membership'
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key], audit_callback=events.append)
    invoked = []
    def dispatch(tool='read_file', args=None, session='session-a'):
        denial = guard.pre_tool_call(tool, args or {}, session_id=session)
        if denial is None:
            invoked.append(tool)
        return denial
    assert dispatch() and not invoked
    first, first_id = issue(tmp_path, issuer, holder, constraints={'path': Exact('/reports/a')})
    attach_warrant(first, 'session-a', directory)
    assert dispatch(args={'path': '/reports/a'}) is None
    assert dispatch(args={'path': '/reports/a'}, session='session-b')
    assert dispatch(args={'path': '/reports/b'})
    second, second_id = issue(tmp_path, issuer, holder, tool='get_status')
    attach_warrant(second, 'session-a', directory)
    assert dispatch('get_status') is None
    guard.on_session_end('session-a')
    assert dispatch(args={'path': '/reports/a'}) is None
    detach_warrant('session-a', first_id, directory)
    assert dispatch(args={'path': '/reports/a'})
    assert dispatch('get_status') is None
    assert events[-1].warrant_id == second_id
    assert len(events) == 8
    assert invoked == ['read_file', 'get_status', 'read_file', 'get_status']


def test_no_union_and_bad_candidate_does_not_shadow(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / 'membership'
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    for a, b in [('a', 'one'), ('b', 'two')]:
        path, _ = issue(tmp_path, issuer, holder, constraints={'path': Exact(a), 'mode': Exact(b)})
        attach_warrant(path, 's', directory)
    assert guard.pre_tool_call('read_file', {'path': 'a', 'mode': 'two'}, session_id='s')
    manifest_path = _path('s', directory)
    manifest = json.loads(manifest_path.read_text())
    manifest['warrants'].insert(0, 'corrupt')
    manifest_path.write_text(json.dumps(manifest))
    assert guard.pre_tool_call('read_file', {'path': 'a', 'mode': 'one'}, session_id='s') is None
    manifest_path.write_text('invalid')
    assert guard.pre_tool_call('read_file', {'path': 'a', 'mode': 'one'}, session_id='s')


def test_expiry_issuer_holder_and_session_binding(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / 'membership'
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    for control, agent in [(SigningKey.generate(), holder), (issuer, SigningKey.generate())]:
        path, _ = issue(tmp_path, control, agent)
        attach_warrant(path, 's', directory)
        assert guard.pre_tool_call('read_file', {}, session_id='s')
    short, _ = issue(tmp_path, issuer, holder, ttl=1)
    attach_warrant(short, 's', directory)
    assert guard.pre_tool_call('read_file', {}, session_id='s') is None
    time.sleep(1.1)
    assert guard.pre_tool_call('read_file', {}, session_id='s')
    scoped, _ = issue(tmp_path, issuer, holder, session='other')
    with pytest.raises(ValueError, match='another session'):
        attach_warrant(scoped, 's', directory)


def test_replace_is_atomic_and_symlink_rejected(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / 'membership'
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    path, identifier = issue(tmp_path, issuer, holder)
    attach_warrant(path, '../opaque-session', directory)
    replacement, _ = issue(tmp_path, issuer, holder, tool='get_status')
    attach_warrant(replacement, '../opaque-session', directory, replace_id=identifier)
    assert guard.pre_tool_call('read_file', {}, session_id='../opaque-session')
    assert guard.pre_tool_call('get_status', {}, session_id='../opaque-session') is None
    _path('evil', directory).symlink_to(_path('../opaque-session', directory))
    assert guard.pre_tool_call('get_status', {}, session_id='evil')


def test_plugin_builds_empty_dynamic_guard_and_reloads_without_restart(tmp_path, monkeypatch):
    from hermes_tenuo import _config
    from hermes_tenuo._guard import build_plugin_guard
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / 'membership'
    monkeypatch.setattr(_config, '_get_plugin_entry', lambda ctx: {
        'session_warrants_dir': str(directory), 'audit_log': False,
        'warrant': 'invalid-static-warrant-must-not-be-read',
    })
    monkeypatch.setattr(_config, 'get_signing_key', lambda ctx: holder)
    monkeypatch.setattr(_config, 'get_trusted_roots', lambda ctx: [issuer.public_key])
    guard = build_plugin_guard(None)
    assert guard.has_warrant
    assert guard.pre_tool_call_hook('read_file', {}, session_id='s')
    path, _ = issue(tmp_path, issuer, holder)
    attach_warrant(path, 's', directory)
    assert guard.pre_tool_call_hook('read_file', {}, session_id='s') is None
    guard.on_session_end_hook(session_id='s')
    assert guard.pre_tool_call_hook('read_file', {}, session_id='s') is None
    assert guard.pre_tool_call_hook('read_file', {}, session_id='new')


def test_cli_attach_status_and_detach(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.cli import main
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    path, identifier = issue(tmp_path, issuer, holder)
    directory = tmp_path / 'membership'
    def run(*arguments):
        monkeypatch.setattr('sys.argv', ['hermes-tenuo', *arguments, '--session', 'example', '--directory', str(directory)])
        with pytest.raises(SystemExit) as result:
            main()
        assert result.value.code == 0
    run('attach', str(path))
    assert 'Published' in capsys.readouterr().out
    run('sessions')
    assert identifier in capsys.readouterr().out
    run('detach', identifier)
    run('sessions')
    assert '"published": []' in capsys.readouterr().out


def test_registered_hooks_reload_same_instance(tmp_path, monkeypatch):
    import hermes_tenuo
    from hermes_tenuo import _config
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / 'membership'
    monkeypatch.setattr(_config, '_get_plugin_entry', lambda ctx: {
        'session_warrants_dir': str(directory), 'audit_log': False,
    })
    monkeypatch.setattr(_config, 'get_signing_key', lambda ctx: holder)
    monkeypatch.setattr(_config, 'get_trusted_roots', lambda ctx: [issuer.public_key])
    class Context:
        hooks = {}
        def register_hook(self, name, function):
            self.hooks[name] = function
    ctx = Context()
    hermes_tenuo.register(ctx)
    calls = []
    def dispatch():
        if ctx.hooks['pre_tool_call']('read_file', {}, session_id='conversation') is None:
            calls.append('handler')
    dispatch()
    assert calls == []
    path, identifier = issue(tmp_path, issuer, holder)
    attach_warrant(path, 'conversation', directory)
    dispatch()
    assert calls == ['handler']
    ctx.hooks['on_session_end'](session_id='conversation')
    dispatch()
    assert calls == ['handler', 'handler']
    detach_warrant('conversation', identifier, directory)
    dispatch()
    assert calls == ['handler', 'handler']


def test_attach_reviewed_bytes_does_not_reread_agent_file(tmp_path):
    from hermes_tenuo.session_store import attach_encoded_warrant
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    path, _ = issue(tmp_path, issuer, holder)
    reviewed = path.read_text()
    path.write_text('untrusted replacement')
    directory = tmp_path / 'membership'
    attach_encoded_warrant(reviewed, 's', directory)
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    assert guard.pre_tool_call('read_file', {}, session_id='s') is None


def test_session_mode_requires_explicit_roots_even_if_sdk_global_has_roots(tmp_path, monkeypatch):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    path, _ = issue(tmp_path, issuer, holder)
    directory = tmp_path / 'membership'
    attach_warrant(path, 's', directory)
    monkeypatch.setattr('tenuo.config.resolve_trusted_roots', lambda _: [issuer.public_key])
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=None)
    assert guard.pre_tool_call('read_file', {}, session_id='s')


def test_runtime_rejects_wrong_signed_session_even_if_manifest_is_injected(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / 'membership'
    directory.mkdir()
    path, _ = issue(tmp_path, issuer, holder, session='intended-session')
    _path('another-session', directory).write_text(json.dumps({
        'version': 1, 'session_id': 'another-session', 'warrants': [path.read_text()],
    }))
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    assert guard.pre_tool_call('read_file', {}, session_id='another-session')


@pytest.mark.parametrize('command', ['doctor', 'status'])
def test_dynamic_diagnostics_accept_empty_authority_without_static_warrant(tmp_path, monkeypatch, capsys, command):
    import argparse
    from hermes_tenuo import cli
    from hermes_tenuo import _config, _home
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    entry = {'session_warrants_dir': str(tmp_path / 'membership')}
    monkeypatch.setattr(_config, '_get_plugin_entry', lambda ctx: entry)
    monkeypatch.setattr(_config, 'get_signing_key', lambda ctx: holder)
    monkeypatch.setattr(_config, 'get_trusted_roots', lambda ctx: [issuer.public_key])
    monkeypatch.setattr(_home, 'load_hermes_config', lambda: {'plugins': {
        'enabled': ['hermes-tenuo'], 'entries': {'hermes-tenuo': entry}}})
    assert getattr(cli, 'cmd_' + command)(argparse.Namespace()) == 0
    output = capsys.readouterr().out
    assert 'dynamic session warrants' in output
    assert 'deny until' in output
    assert 'pass through' not in output
    assert 'plugin configured (warrant)' not in output
    assert base64.b64encode(holder.secret_key_bytes()).decode() not in output
    monkeypatch.setattr(_config, 'get_trusted_roots', lambda ctx: None)
    assert getattr(cli, 'cmd_' + command)(argparse.Namespace()) == 1
    assert 'calls block' in capsys.readouterr().out


@pytest.mark.parametrize('failure', ['issuer', 'holder', 'expired'])
def test_invalid_replacement_preserves_working_grant(tmp_path, failure):
    from hermes_tenuo.session_store import read_session
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / 'membership'
    old_path, old_id = issue(tmp_path, issuer, holder)
    attach_warrant(old_path, 's', directory)
    before = read_session('s', directory)
    candidate, _ = issue(tmp_path,
        SigningKey.generate() if failure == 'issuer' else issuer,
        SigningKey.generate() if failure == 'holder' else holder,
        ttl=1 if failure == 'expired' else 60)
    if failure == 'expired':
        time.sleep(1.1)
    with pytest.raises(ValueError):
        attach_warrant(candidate, 's', directory, replace_id=old_id)
    assert read_session('s', directory) == before
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    assert guard.pre_tool_call('read_file', {}, session_id='s') is None
