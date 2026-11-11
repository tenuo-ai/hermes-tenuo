"""First-session behavior, including ownership and no-grant preflight failures."""
import os
import shlex
import subprocess
import sys
from types import SimpleNamespace

import pytest

from hermes_tenuo.hands import chat, device, sandbox
from tests import test_hands as shared
from tests.test_hands import up, sandboxed

hub = shared.hub
folder = shared.folder
_no_inherited_proxy = shared._no_inherited_proxy


def test_setup_is_registered_without_a_listener(monkeypatch):
    from hermes_tenuo import hands
    commands, prompts = {}, {}
    ctx = SimpleNamespace(register_hook=lambda *a: None, register_command=lambda name, fn, **kw: commands.update({name: fn}),
                          register_system_prompt_section=lambda name, text: prompts.update({name: text}))
    monkeypatch.setattr(hands, 'settings', lambda _: {})
    monkeypatch.setattr(chat, 'get_hub', lambda: None)
    assert hands.register(ctx) is False
    assert 'Hands is off' in commands['hands']('setup')
    assert 'hands' in prompts


@pytest.mark.parametrize('choice, flag', [('read', '--read-only'), ('edit', None), ('online', '--network')])
def test_setup_presets_produce_local_commands_without_pairing(hub, monkeypatch, choice, flag):
    monkeypatch.setattr(chat, 'get_hub', lambda: hub)
    monkeypatch.setattr(chat, '_owner', lambda: 'telegram:alice')
    monkeypatch.setattr(chat, '_conversation', lambda: 'origin')
    response = chat.command('setup ' + choice)
    argv = shlex.split(next(line.strip() for line in response.splitlines() if line.startswith('  uvx')))
    assert argv[:4] == ['uvx', 'hermes-tenuo', 'hands', 'up']
    assert argv[argv.index('--for') + 1] == '1h'
    if flag:
        assert flag in argv
    else:
        assert '--network' not in argv and '--read-only' not in argv
    assert not hub.sessions()


def test_choices_and_unknown_sender_do_not_mint_invites(hub, monkeypatch):
    monkeypatch.setattr(chat, 'get_hub', lambda: hub)
    monkeypatch.setattr(hub, 'invite', lambda *a: pytest.fail('must not create an invite'))
    for args in ('setup', 'setup typo', 'setup edit extra'):
        assert 'Choose what' in chat.command(args)
    monkeypatch.setattr(chat, '_owner', lambda: chat.NOBODY)
    assert 'nothing was changed' in chat.command('setup edit')


@sandboxed
def test_verify_reports_real_folder_without_writing(hub, folder, monkeypatch):
    monkeypatch.setattr(chat, 'get_hub', lambda: hub)
    monkeypatch.setattr(chat, '_owner', lambda: '')
    monkeypatch.setattr(chat, '_conversation', lambda: 'verify-chat')
    monkeypatch.setattr(chat, '_wanted', {'verify-chat': 'laptop'})
    before = sorted(str(p) for p in folder.rglob('*'))
    running = up(hub, folder, read_only=True)
    try:
        response = chat.command('verify')
        assert 'Shared folder verified: ' + os.path.realpath(folder) in response
        assert 'read-only' in response and 'internet off' in response
        assert sorted(str(p) for p in folder.rglob('*')) == before
        context = chat.before_turn()['context']
        assert 'laptop' in context and 'read-only' in context
        monkeypatch.setattr(chat, '_owner', lambda: chat.NOBODY)
        assert 'nothing was changed' in chat.command('verify')
    finally:
        running.stop()


def test_context_does_not_disclose_another_owners_folder(hub, folder, monkeypatch):
    invite = hub.invite('telegram:alice')
    device.Device(invite, str(folder), 60, name='private', allow_unsandboxed=True).pair()
    monkeypatch.setattr(chat, 'get_hub', lambda: hub)
    monkeypatch.setattr(chat, '_owner', lambda: 'telegram:bob')
    monkeypatch.setattr(chat, '_conversation', lambda: 'other')
    monkeypatch.setattr(chat, '_wanted', {'other': 'private'})
    text = chat.before_turn()['context']
    assert str(folder) not in text and 'unavailable' in text
    monkeypatch.setattr(hub, 'run', lambda *a, **kw: pytest.fail('must not execute'))
    assert 'Shared folder verified' not in chat.command('verify')


def test_cli_preflight_failure_creates_no_device(hub, folder, monkeypatch, capsys):
    from hermes_tenuo.cli import cmd_hands
    monkeypatch.setattr(sandbox, '_probe', [None])
    monkeypatch.setattr(device, 'Device', lambda *a, **kw: pytest.fail('must not create device'))
    args = SimpleNamespace(hands_command='up', invite=hub.invite(), dir=str(folder), ttl='1h',
                           read_only=False, network=False, no_sandbox=False, plain_http=False)
    assert cmd_hands(args) == 1
    assert 'Nothing was paired' in capsys.readouterr().out
    assert not hub.sessions() and not (device.home() / 'device.key').exists()


def test_preflight_checks_protocol_without_consuming_invite(hub, folder, monkeypatch):
    monkeypatch.setattr(sandbox, '_probe', ['sandbox-exec'])
    invite = hub.invite()
    assert all(ok is not False for ok, _ in device.check(invite, str(folder)))
    assert not hub.sessions()
    monkeypatch.setattr(hub, 'hello', lambda body: {'protocol': 2})
    assert any(ok is False and 'mismatch' in msg for ok, msg in device.check(invite, str(folder)))


@sandboxed
def test_reconnect_preserves_scope_without_invite(hub, folder):
    invite = hub.invite()
    dev = device.Device(invite, str(folder), 123, name='my laptop', read_only=True, allow_unsandboxed=True)
    args = shlex.split(dev.reconnect_command())
    assert invite not in dev.reconnect_command()
    assert args[args.index('--dir') + 1] == os.path.realpath(folder)
    assert args[args.index('--for') + 1] == '123s'
    assert args[args.index('--name') + 1] == 'my laptop'
    assert '--read-only' in args and '--network' not in args


def test_demo_is_disposable_and_has_a_real_fix(tmp_path, monkeypatch):
    from hermes_tenuo.hands import onboarding
    monkeypatch.setenv('TENUO_HANDS_HOME', str(tmp_path / 'state'))
    target = tmp_path / 'practice'
    target.mkdir()
    monkeypatch.setattr(onboarding.tempfile, 'mkdtemp', lambda **kw: str(target))
    assert 'Nothing was paired' in onboarding.create_demo()
    def run():
        return subprocess.run([sys.executable, '-m', 'unittest', '-v'], cwd=target,
                              capture_output=True, text=True)
    assert run().returncode != 0
    source = target / 'invoice.py'
    source.write_text(source.read_text().replace('subtotal * discount', 'subtotal * (1 - discount)'))
    assert run().returncode == 0
    assert not (device.home() / 'server.json').exists()


@sandboxed
def test_cli_preflight_success_keeps_the_invite_for_pairing(hub, folder, monkeypatch):
    import signal
    from hermes_tenuo.cli import cmd_hands
    monkeypatch.setattr(signal, 'signal', lambda *a: None)
    monkeypatch.setattr(device.Device, 'serve', lambda self: self.pair() or 0)
    args = SimpleNamespace(hands_command='up', invite=hub.invite(), dir=str(folder), ttl='1h',
                           name='practice', read_only=True, network=False, no_sandbox=False,
                           plain_http=False, read_home=False, read=None)
    assert cmd_hands(args) == 0
    session = hub.sessions()[0]
    assert session.mode == 'read-only' and session.network == 'off'


def test_plain_public_preflight_does_not_contact_server(hub, folder, monkeypatch):
    monkeypatch.setattr(device.wire, 'plain_and_public', lambda url: True)
    monkeypatch.setattr(device.urllib.request, 'urlopen', lambda *a, **kw: pytest.fail('must not contact plaintext host'))
    assert any(ok is False for ok, _ in device.check(hub.invite(), str(folder)))


def test_read_only_does_not_downgrade_without_sandbox(hub, folder, monkeypatch):
    monkeypatch.setattr(sandbox, '_probe', [None])
    assert any(ok is False for ok, _ in device.check(hub.invite(), str(folder), read_only=True,
                                                    allow_unsandboxed=True))


@pytest.mark.parametrize('whole_profile', [False, True])
def test_verification_and_unavailable_guidance_match_routing(hub, folder, monkeypatch, whole_profile):
    monkeypatch.setattr(chat, 'get_hub', lambda: hub)
    monkeypatch.setattr(chat, '_whole_profile', lambda: whole_profile)
    monkeypatch.setattr(chat, '_owner', lambda: '')
    monkeypatch.setattr(chat, '_conversation', lambda: 'guidance')
    monkeypatch.setattr(chat, '_wanted', {'guidance': 'laptop'})
    offline = chat.before_turn()['context']
    session = SimpleNamespace(name='laptop', folder=str(folder), mode='sandboxed', network='off', expires=10**10)
    monkeypatch.setattr(hub, 'pick', lambda *a: session)
    monkeypatch.setattr(hub, 'run', lambda *a, **kw: (str(folder), 0))
    verified = chat.command('verify')
    for text in (offline, verified):
        if whole_profile:
            assert "Change this profile's terminal backend" in text
            assert '/hands off cannot switch' in text
            assert '/hands off switches' not in text
        else:
            assert '/hands off switches this conversation to the server' in text
            assert 'Change this profile' not in text


def test_reconnect_uses_original_identity_from_a_fresh_shell(hub, folder, tmp_path, monkeypatch):
    import json
    state = tmp_path / 'original state with spaces'
    monkeypatch.setenv('TENUO_HANDS_HOME', str(state))
    original = device.Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    original.pair()
    args = shlex.split(original.reconnect_command())
    assert args[:2] == ['env', 'TENUO_HANDS_HOME=' + str(state.resolve())]
    # A command-local assignment is gone in the next shell. Inherit a different
    # state directory and verify the printed prefix restores the original pair.
    monkeypatch.setenv('TENUO_HANDS_HOME', str(tmp_path / 'different-state'))
    script = ('import json,sys; from hermes_tenuo.hands.device import Device; '
              'd=Device(None,sys.argv[1],60,allow_unsandboxed=True); d.pair(); '
              'print(json.dumps([d.url,d.me]))')
    done = subprocess.run(args[:2] + [sys.executable, '-c', script, str(folder)],
                          capture_output=True, text=True, timeout=20)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == [original.url, original.me]
    assert not (tmp_path / 'different-state').exists()
