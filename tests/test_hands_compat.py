"""Real HTTP sessions with a pinned, separately imported previous Hands checkout."""
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hermes_tenuo.hands import device
from tests import test_hands as shared
from tests.test_hands import sandboxed, run

hub = shared.hub
folder = shared.folder
_no_inherited_proxy = shared._no_inherited_proxy
BASELINE = os.environ.get('HANDS_COMPAT_SOURCE')
pytestmark = pytest.mark.skipif(not BASELINE, reason='set HANDS_COMPAT_SOURCE to the pinned previous checkout')

PEER = '''
import json, sys, time
sys.path.insert(0, sys.argv[1])
from hermes_tenuo.hands import wire
wire.POLL_SECONDS = 1
if sys.argv[2] == 'hub':
    from hermes_tenuo.hands.hub import Hub
    h = Hub(state_dir=sys.argv[3]); h.listen('127.0.0.1:0')
    print(json.dumps({'invite': h.invite()}), flush=True)
    try:
        for line in sys.stdin:
            req = json.loads(line)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not h.sessions():
                time.sleep(.05)
            print(json.dumps(h.run(h.pick('compat'), req['cmd'], timeout=10, stdin=None, login=False)), flush=True)
    finally:
        h.close()
else:
    from hermes_tenuo.hands.device import Device
    d = Device(sys.argv[3], sys.argv[4], 120, name='compat', say=lambda _: None)
    import signal
    signal.signal(signal.SIGTERM, d.stop)
    d.serve()
'''


def peer(role, *args):
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    return subprocess.Popen([sys.executable, '-u', '-c', PEER, str(Path(BASELINE).resolve()), role, *map(str, args)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env)


def reply(process):
    ready, _, _ = select.select([process.stdout], [], [], 20)
    assert ready, 'previous Hands process did not reply within 20 seconds'
    line = process.stdout.readline()
    assert line, 'previous Hands process exited without replying'
    return json.loads(line)


@sandboxed
def test_current_device_previous_server(folder, tmp_path):
    old = peer('hub', tmp_path / 'old-hub')
    running = None
    try:
        invite = reply(old)['invite']
        running = shared.Running(device.Device(invite, str(folder), 120, name='compat', say=lambda _: None))
        old.stdin.write(json.dumps({'cmd': "printf 'compatible'; printf 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"}) + '\n')
        old.stdin.flush()
        output, code = reply(old)
        assert code == 0 and 'compatible' in output
        assert 'ghp_' not in output and '[redacted]' in output
    finally:
        if running:
            running.stop()
        old.stdin.close()
        try:
            old.wait(timeout=15)
        except subprocess.TimeoutExpired:
            old.kill()
            old.wait()
        if running:
            running.thread.join(5)


@sandboxed
def test_previous_device_current_server(hub, folder):
    old = peer('device', hub.invite(), folder)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not hub.sessions():
            time.sleep(.05)
        output, code = run(hub, 'echo previous-client', name='compat')
        assert code == 0 and 'previous-client' in output
        output, code = run(hub, 'echo persisted > compatibility.txt && cat compatibility.txt', name='compat')
        assert code == 0 and 'persisted' in output
    finally:
        old.terminate()
        try:
            old.wait(timeout=15)
        except subprocess.TimeoutExpired:
            old.kill()
            old.wait()
