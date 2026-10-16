"""Run the portable approval journey through real Hermes dispatch hooks."""
import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip('hermes_cli.plugins')

DRIVER = textwrap.dedent(r'''
import base64, json, os, subprocess, sys
from pathlib import Path
from tenuo import SigningKey
from hermes_tenuo.session_store import attach_encoded_warrant
home = Path(os.environ['HERMES_HOME'])
home.mkdir()
operator = home.parent / 'operator'
operator.mkdir()
def cli(*args):
    result = subprocess.run([sys.executable, '-m', 'hermes_tenuo.cli', *map(str,args)],
        capture_output=True, text=True)
    assert result.returncode == 0, (result.stdout, result.stderr)
issuer, holder, alice = [SigningKey.generate() for _ in range(3)]
(home / 'holder.key').write_text(base64.b64encode(holder.secret_key_bytes()).decode())
(home / 'issuer.pub').write_text(base64.b64encode(issuer.public_key.to_bytes()).decode())
(operator / 'issuer.key').write_text(base64.b64encode(issuer.secret_key_bytes()).decode())
(operator / 'holder.pub').write_text(base64.b64encode(holder.public_key.to_bytes()).decode())
(operator / 'alice.key').write_text(base64.b64encode(alice.secret_key_bytes()).decode())
(operator / 'alice.pub').write_text(base64.b64encode(alice.public_key.to_bytes()).decode())
store = home.parent / 'sessions'
responses = operator / 'responses'
requests = home / 'requests'
(home / 'config.yaml').write_text('plugins:\n  enabled: [hermes-tenuo]\n  entries:\n    hermes-tenuo:\n'
    + '      signing_key_file: holder.key\n      trusted_root_file: issuer.pub\n'
    + '      session_warrants_dir: ' + str(store) + '\n'
    + '      operation_requests_dir: ' + str(requests) + '\n'
    + '      operation_approvals_dir: ' + str(responses) + '\n')
policy_path = operator / 'maintenance.yaml'
policy_path.write_text('version: 2\nttl: 10m\ncapabilities:\n  example_restart: {}\napprovals:\n'
    + '  keys: [./alice.pub]\n  gates:\n    example_restart: {always: true}\n')
cli('mint', '--policy', policy_path, '--issuer-key', operator/'issuer.key',
    '--holder-public-key', operator/'holder.pub', '--session-id', 'session-a', '--out', operator/'restart.warrant')
attach_encoded_warrant((operator/'restart.warrant').read_text().strip(), 'session-a', store)
from hermes_cli.plugins import get_plugin_manager
manager = get_plugin_manager()
manager.discover_and_load()
loaded = next(p for p in manager.list_plugins() if p['name'] == 'hermes-tenuo')
assert not loaded.get('error'), loaded
from tools.registry import registry
calls = []
def handler(args, **kwargs):
    calls.append(args)
    return json.dumps({'status': 'restarted'})
registry.register(name='example_restart', toolset='example', schema={
    'name': 'example_restart', 'description': 'Restart an example resource',
    'parameters': {'type': 'object', 'properties': {'resource': {'type': 'string'}},
                   'required': ['resource']}}, handler=handler, check_fn=lambda: True)
from model_tools import handle_function_call
counter = 0
def call(args, session='session-a'):
    global counter
    counter += 1
    return handle_function_call('example_restart', args, session_id=session,
        tool_call_id='operation-' + str(counter))
blocked = call({'resource': 'example'})
assert 'Human approval required' in blocked and calls == [], blocked
request = next(requests.rglob('*.operation.json'))
recipient = operator / 'recipient'
recipient.mkdir()
copy = recipient / 'request.json'
copy.write_bytes(request.read_bytes())
response = recipient / 'response.json'
cli('approvals', 'sign', copy, '--key', operator/'alice.key', '--trusted-root', home/'issuer.pub', '--out', response, '--yes')
call({'resource':'example'})
assert calls == []  # A remote signature is inert until explicitly imported.
cli('approvals', 'import', request, '--response', response, '--trusted-root', home/'issuer.pub')
assert json.loads(call({'resource':'example'}))['status'] == 'restarted'
assert len(calls) == 1
call({'resource':'different'})
call({'resource':'example'}, session='session-b')
assert len(calls) == 1
rows = [json.loads(line) for line in (home/'tenuo/audit.jsonl').read_text().splitlines()]
assert any(r['decision']=='DENY' and 'Human approval required' in r['reason'] for r in rows)
from hermes_tenuo.operation_approvals import fingerprint
assert any(r['decision']=='ALLOW' and r.get('approvers', [{}])[0].get('fingerprint')==fingerprint(alice.public_key) for r in rows)
print('LIVE_OPERATION_APPROVAL_OK')
''')


def test_real_dispatch_blocks_handler_until_signed_response_import(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith('TENUO_')}
    env.update(HERMES_HOME=str(tmp_path / 'agent'), HERMES_MANAGED_DIR=str(tmp_path / 'no-managed'))
    result = subprocess.run([sys.executable, '-c', DRIVER], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert 'LIVE_OPERATION_APPROVAL_OK' in result.stdout
