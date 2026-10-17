"""Load the common-file adapter through Hermes' real plugin and dispatch paths."""
import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("hermes_cli.plugins")

DRIVER = textwrap.dedent(r'''
import json, os, shutil, subprocess, sys
from pathlib import Path
from tenuo.local_cli.files import publish, update_revocations, write_yaml
from tenuo.local_cli.workspace import Workspace

home = Path(os.environ['HERMES_HOME'])
home.mkdir()
operator = Workspace(home.parent / 'controller')
operator.initialize(dev=True)
runtime = home / 'tenuo'
runtime.mkdir()
(runtime / 'keys').mkdir()
for relative in ['config.yaml', 'revocations.srl', 'keys/agent.key', 'keys/agent.pub']:
    publish(runtime / relative, (operator.path / relative).read_bytes())
shutil.copytree(operator.path / 'trust', runtime / 'trust')
policy = home.parent / 'orders.yaml'
write_yaml(policy, {'version': 2, 'ttl': '30m', 'capabilities': {'get_order': {'order_id': 'A-1001'}}})
def cli(*args):
    result = subprocess.run([sys.executable, '-m', 'tenuo.local_cli', '--home', str(operator.path),
        '--json', *map(str, args)], capture_output=True, text=True)
    assert result.returncode == 0, (result.stdout, result.stderr)
    return json.loads(result.stdout)
issued = cli('warrant', 'issue', '--template', policy, '--holder', 'agent')
wid = issued['warrant']['id']
grant = operator.path / 'warrants' / (wid + '.warrant')
write_yaml(home / 'config.yaml', {'plugins': {'enabled': ['hermes-tenuo'], 'entries': {
    'hermes-tenuo': {'local_home': str(runtime)}}}})
from hermes_cli.plugins import get_plugin_manager
manager = get_plugin_manager()
manager.discover_and_load()
loaded = next(p for p in manager.list_plugins() if p['name'] == 'hermes-tenuo')
assert not loaded.get('error'), loaded
from tools.registry import registry
calls = []
def handler(args, **kwargs):
    calls.append(dict(args))
    return json.dumps({'status': 'ready'})
registry.register(name='get_order', toolset='example', schema={
    'name': 'get_order', 'description': 'Read an example order',
    'parameters': {'type': 'object', 'properties': {'order_id': {'type': 'string'}},
                   'required': ['order_id']}}, handler=handler, check_fn=lambda: True)
from model_tools import handle_function_call
counter = 0
def call(order, session='chat-a'):
    global counter
    counter += 1
    return handle_function_call('get_order', {'order_id': order}, session_id=session,
        tool_call_id='call-' + str(counter))
first = call('A-1001')
assert calls == [] and 'chat-a' in first, first
cli('session', 'attach', '--session', 'chat-a', '--file', grant)
for directory in ['warrants', 'sessions']:
    shutil.copytree(operator.path / directory, runtime / directory, dirs_exist_ok=True)
call('A-1001')
assert calls == [{'order_id': 'A-1001'}], calls
decisions = manager.invoke_hook('pre_tool_call', tool_name='memory', args={'action': 'add', 'content': 'example'},
    session_id='chat-a', tool_call_id='builtin-memory')
assert any(isinstance(d, dict) and d.get('action') == 'block' for d in decisions), decisions
call('OTHER')
call('A-1001', session='chat-b')
assert len(calls) == 1, calls
update_revocations(operator.path / 'revocations.srl', operator.signing_key('issuer'), [wid])
publish(runtime / 'revocations.srl', (operator.path / 'revocations.srl').read_bytes(), replace=True)
denied = call('A-1001')
assert len(calls) == 1 and 'revoked' in denied.lower(), denied
assert not (runtime / 'keys/issuer.key').exists()
assert not (runtime / 'keys/approver.key').exists()
assert (runtime / 'receipts.jsonl').read_text().strip()
print('LIVE_SHARED_CLI_OK')
''')


def test_shared_cli_real_plugin_load_and_dispatch(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("TENUO_")}
    env.update(HERMES_HOME=str(tmp_path / "agent"), HERMES_MANAGED_DIR=str(tmp_path / "no-managed"))
    env.pop("HERMES_PROFILE", None)
    result = subprocess.run([sys.executable, "-c", DRIVER], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "LIVE_SHARED_CLI_OK" in result.stdout
