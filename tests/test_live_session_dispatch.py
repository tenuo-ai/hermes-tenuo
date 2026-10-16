"""Exercise real Hermes loader/dispatcher in an isolated subprocess, without inference."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("hermes_cli.plugins")

DRIVER = textwrap.dedent(r'''
import base64, json, os, subprocess, sys
from pathlib import Path
from tenuo import SigningKey
home = Path(os.environ['HERMES_HOME'])
home.mkdir()
control = home.parent / 'operator'
control.mkdir()
issuer, holder = SigningKey.generate(), SigningKey.generate()
issuer_path = control / 'issuer.key'
issuer_path.write_text(base64.b64encode(issuer.secret_key_bytes()).decode())
(home / 'holder.key').write_text(base64.b64encode(holder.secret_key_bytes()).decode())
(home / 'issuer.pub').write_text(base64.b64encode(issuer.public_key.to_bytes()).decode())
store = home.parent / 'published'
(home / 'config.yaml').write_text('plugins:\n  enabled: [hermes-tenuo]\n  entries:\n    hermes-tenuo:\n'
    + '      signing_key_file: holder.key\n      trusted_root_file: issuer.pub\n'
    + '      session_warrants_dir: ' + str(store) + '\n'
    + '      requests_dir: ' + str(home / 'requests') + '\n')
from hermes_cli.plugins import get_plugin_manager, invoke_hook
pm = get_plugin_manager()
pm.discover_and_load()
loaded = next(p for p in pm.list_plugins() if p['name'] == 'hermes-tenuo')
assert not loaded.get('error'), loaded
from tools.registry import registry
calls = []
def handler(args, **kwargs):
    calls.append(args)
    return json.dumps({'status': 'ok'})
registry.register(name='example_status', toolset='example', schema={
    'name': 'example_status', 'description': 'Inspect an example resource',
    'parameters': {'type': 'object', 'properties': {'resource': {'type': 'string'}},
                   'required': ['resource']}}, handler=handler, check_fn=lambda: True)
from model_tools import handle_function_call
counter = 0
def call(name, args, session='session-a'):
    global counter
    counter += 1
    return handle_function_call(name, args, session_id=session,
        tool_call_id='integration-' + str(counter))
def approve(resource):
    request = json.loads(call('tenuo_request_authority', {
        'allow': ['example_status:resource=' + resource], 'ttl': '10m',
        'description': 'Inspect a public example resource'}))
    assert request['status'] == 'pending_external_approval', request
    operator_env = {k:v for k,v in os.environ.items() if not k.startswith('TENUO_')}
    approved = subprocess.run([sys.executable, '-m', 'hermes_tenuo.cli', 'approve', request['request'],
        '--issuer-key', str(issuer_path), '--yes', '--attach', '--directory', str(store)],
        env=operator_env, capture_output=True, text=True)
    assert approved.returncode == 0, (approved.stdout, approved.stderr)
    return Path(request['request']).with_suffix('.warrant')
assert call('example_status', {'resource':'public'}) and calls == []
first = approve('public')
assert json.loads(call('example_status', {'resource':'public'}))['status'] == 'ok'
assert len(calls) == 1
call('example_status', {'resource':'private'})
call('example_status', {'resource':'public'}, session='session-b')
assert len(calls) == 1
invoke_hook('on_session_end', session_id='session-a')
assert json.loads(call('example_status', {'resource':'public'}))['status'] == 'ok'
second = approve('summary')
assert json.loads(call('example_status', {'resource':'summary'}))['status'] == 'ok'
assert len(calls) == 3
from hermes_tenuo.session_store import detach_warrant
from tenuo import Warrant
old = Warrant.from_base64(first.read_text().strip())
detach_warrant('session-a', str(old.id), store)
call('example_status', {'resource':'public'})
assert len(calls) == 3
assert json.loads(call('example_status', {'resource':'summary'}))['status'] == 'ok'
rows = [json.loads(line) for line in (home / 'tenuo/audit.jsonl').read_text().splitlines()]
assert any(r['decision']=='ALLOW' and r.get('warrant_id') for r in rows)
assert any(r['decision']=='DENY' for r in rows)
assert not (home / 'issuer.key').exists()
print('LIVE_SESSION_JOURNEY_OK')
''')


def test_real_loader_dispatcher_request_approval_and_live_session_loading(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("TENUO_")}
    env.update(HERMES_HOME=str(tmp_path / "agent"), HERMES_MANAGED_DIR=str(tmp_path / "no-managed"))
    result = subprocess.run([sys.executable, "-c", DRIVER], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "LIVE_SESSION_JOURNEY_OK" in result.stdout
