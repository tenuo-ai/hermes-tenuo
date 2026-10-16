"""Exercise operator commands across fresh processes and a live session guard."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys

from tenuo import SigningKey, Warrant

from hermes_tenuo.session_guard import SessionGuard
from hermes_tenuo.session_store import read_session


def test_external_operator_cli_journey(tmp_path):
    source = Path(__file__).resolve().parents[1]
    operator, agent, home = (tmp_path / name for name in ('operator', 'agent', 'hermes-home'))
    for directory in (operator, agent, home):
        directory.mkdir()
    session_store = tmp_path / 'operator-published-sessions'
    (home / 'config.yaml').write_text(json.dumps({'plugins': {'entries': {'hermes-tenuo': {
        'session_warrants_dir': str(session_store),
    }}}}))
    environment = {key: value for key, value in os.environ.items() if not key.startswith('TENUO_')}
    environment.update(PYTHONPATH=str(source), HERMES_HOME=str(home))
    transcript = []

    def cli(*args, cwd=operator):
        # The operator process never receives the holder secret in its environment.
        assert 'TENUO_SIGNING_KEY' not in environment
        completed = subprocess.run([sys.executable, '-m', 'hermes_tenuo.cli', *map(str, args)],
                                   cwd=cwd, env=environment, capture_output=True, text=True, timeout=15)
        transcript.append(completed.stdout + completed.stderr)
        assert completed.returncode == 0, (args, completed.stdout, completed.stderr)
        return completed.stdout

    cli('keygen', '--private-key', 'holder.key', '--public-key', 'holder.pub', cwd=agent)
    cli('keygen', '--private-key', 'issuer.key', '--public-key', 'issuer.pub')
    # Transfer only the public recipient identity into the operator environment.
    public_holder = operator / 'holder.pub'
    public_holder.write_bytes((agent / 'holder.pub').read_bytes())
    holder = SigningKey.from_bytes(base64.b64decode((agent / 'holder.key').read_text()))
    issuer_public = SigningKey.from_bytes(base64.b64decode((operator / 'issuer.key').read_text())).public_key
    guard = SessionGuard(session_store, signing_key=holder, trusted_roots=[issuer_public])
    allowed_args = {'path': '/data/reports/summary.txt'}
    assert guard.pre_tool_call('read_file', allowed_args, session_id='session-a')['action'] == 'block'

    # Ad hoc issuance and explicit attachment need no policy file or gateway restart.
    cli('mint', '--issuer-key', 'issuer.key', '--holder-public-key', 'holder.pub',
        '--ttl', '20m', '--allow', 'read_file:path=/data/reports', '--session-id', 'session-a',
        '--out', 'read.warrant')
    cli('attach', 'read.warrant', '--session', 'session-a', '--directory', session_store)
    assert guard.pre_tool_call('read_file', allowed_args, session_id='session-a') is None
    guard.on_session_end('session-a')
    assert guard.pre_tool_call('read_file', allowed_args, session_id='session-a') is None
    assert guard.pre_tool_call('read_file', allowed_args, session_id='session-b')['action'] == 'block'

    # Policy minting works through the same public-recipient issuance path.
    policy = operator / 'search.yaml'
    policy.write_text("version: 1\nttl: 20m\ncapabilities:\n  web_search:\n    query: {pattern: 'example*'}\n")
    cli('policy', 'validate', policy)
    cli('policy', 'show', policy)
    cli('mint', '--issuer-key', 'issuer.key', '--holder-public-key', 'holder.pub',
        '--policy', policy, '--session-id', 'session-a', '--out', 'policy.warrant')
    policy_grant = Warrant.from_base64((operator / 'policy.warrant').read_text().strip())
    assert policy_grant.ttl_seconds() == 1200

    # A request remains inert until approval; configured-directory publication is automatic.
    request = operator / 'search.request.json'
    cli('request', 'create', '--holder-public-key', 'holder.pub', '--session', 'session-a',
        '--description', 'Research example documentation', '--policy', policy, '--out', request)
    reviewed = cli('request', 'show', request)
    assert 'session-a' in reviewed and 'web_search' in reviewed
    assert guard.pre_tool_call('web_search', {'query': 'example docs'}, session_id='session-a')['action'] == 'block'
    cli('approve', request, '--issuer-key', 'issuer.key', '--yes', '--attach')
    assert len(read_session('session-a', session_store)) == 2
    assert guard.pre_tool_call('read_file', allowed_args, session_id='session-a') is None
    assert guard.pre_tool_call('web_search', {'query': 'example docs'}, session_id='session-a') is None
    assert guard.pre_tool_call('web_search', {'query': 'unrelated'}, session_id='session-a')['action'] == 'block'
    assert guard.pre_tool_call('write_file', allowed_args, session_id='session-a')['action'] == 'block'

    # Explicit publication directory works too; detachment affects the already-running guard.
    request_two = operator / 'status.request.json'
    cli('request', 'create', '--holder-public-key', 'holder.pub', '--session', 'session-a',
        '--description', 'Inspect repository status', '--allow', 'git:action=status', '--out', request_two)
    cli('approve', request_two, '--issuer-key', 'issuer.key', '--yes', '--attach', '--directory', session_store)
    assert len(read_session('session-a', session_store)) == 3
    assert guard.pre_tool_call('git', {'action': 'status'}, session_id='session-a') is None
    read_grant = Warrant.from_base64((operator / 'read.warrant').read_text().strip())
    cli('detach', str(read_grant.id), '--session', 'session-a', '--directory', session_store)
    assert guard.pre_tool_call('read_file', allowed_args, session_id='session-a')['action'] == 'block'
    assert guard.pre_tool_call('web_search', {'query': 'example docs'}, session_id='session-a') is None
    assert len(read_session('session-a', session_store)) == 2
    assert len(json.loads(cli('sessions', '--session', 'session-a', '--directory', session_store))['published']) == 2

    # Neither issuance nor approval outputs disclose either private key.
    all_output = '\n'.join(transcript)
    assert (agent / 'holder.key').read_text().strip() not in all_output
    assert (operator / 'issuer.key').read_text().strip() not in all_output
    assert not (operator / 'holder.key').exists()


def test_request_tool_uses_trusted_dispatch_context(tmp_path, monkeypatch):
    from hermes_tenuo.authority_requests import load_request
    from hermes_tenuo.request_tools import register_request_tool
    holder = SigningKey.generate()
    monkeypatch.setattr('hermes_tenuo._config._get_plugin_entry', lambda _: {
        'requests_dir': str(tmp_path / 'requests'),
        'session_warrants_dir': str(tmp_path / 'sessions'),
    })
    monkeypatch.setattr('hermes_tenuo._config.get_signing_key', lambda _: holder)

    class Context:
        def register_tool(self, **definition):
            self.handler = definition['handler']

    context = Context()
    assert register_request_tool(context)
    arguments = {'allow': ['read_file:path=/data/reports'], 'ttl': '20m', 'description': 'Read reports'}
    spoofed = json.loads(context.handler({**arguments, 'session_id': 'other-session'}, session_id='real-session'))
    assert 'error' in spoofed
    no_context = json.loads(context.handler(arguments))
    assert 'error' in no_context
    response = json.loads(context.handler(arguments, session_id='real-session'))
    assert response['status'] == 'pending_external_approval'
    request = load_request(response['request'])
    assert request['session_id'] == 'real-session'
    assert request['holder_public_key'] == base64.b64encode(holder.public_key.to_bytes()).decode()
    assert not list(tmp_path.rglob('*.warrant'))


def test_request_parser_dispatches_all_public_commands(monkeypatch):
    import pytest
    import hermes_tenuo.authority_requests as requests
    from hermes_tenuo.cli import main
    cases = [
        (['request', 'create', '--holder-public-key', 'holder.pub', '--session', 'session-a',
          '--description', 'Read reports', '--allow', 'read_file:path=/data/reports', '--out', 'request.json'],
         'cmd_request_create'),
        (['request', 'show', 'request.json'], 'cmd_request_show'),
        (['approve', 'request.json', '--issuer-key', 'issuer.key', '--yes', '--attach'], 'cmd_approve'),
    ]
    for arguments, handler_name in cases:
        seen = []
        monkeypatch.setattr(requests, handler_name, lambda args: seen.append(args) or 17)
        monkeypatch.setattr(sys, 'argv', ['hermes-tenuo', *arguments])
        with pytest.raises(SystemExit) as result:
            main()
        assert result.value.code == 17
        assert len(seen) == 1
