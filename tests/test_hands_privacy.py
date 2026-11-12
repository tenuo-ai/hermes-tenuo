"""Privacy at the real device/HTTP/sandbox boundary, not only formatting helpers."""
import json
import os
import shlex
from types import SimpleNamespace

import pytest

from hermes_tenuo.cli import cmd_hands
from hermes_tenuo.hands import device, privacy, wire
from tests import test_hands as shared
from tests.test_hands import run, sandboxed, up

hub = shared.hub
folder = shared.folder
_no_inherited_proxy = shared._no_inherited_proxy


@pytest.fixture(autouse=True)
def personal_config(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    monkeypatch.setattr(wire, 'POLL_SECONDS', 1)


def rules(text):
    path = privacy.policy_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_preview_never_connects_runs_commands_or_creates_identity(hub, folder, monkeypatch, capsys):
    (folder / 'private').mkdir()
    rules('private\n')
    monkeypatch.setattr(device, '_post', lambda *a, **k: pytest.fail('network'))
    monkeypatch.setattr(device.subprocess, 'Popen', lambda *a, **k: pytest.fail('process'))
    args = SimpleNamespace(hands_command='up', preview=True, invite=hub.invite(), dir=str(folder),
                           ttl='1h', read_only=True, network=False, no_sandbox=False, read_home=False, read=None)
    assert cmd_hands(args) == 0
    output = capsys.readouterr().out
    assert 'Excluded:' in output and 'private' in output
    assert 'model provider' in output and '3600 seconds' in output
    assert args.invite not in output
    assert not device.home().exists()
    assert not hub.sessions()


@pytest.mark.parametrize('rule', ['missing', '*.pem', '!private', '../project'])
def test_invalid_rules_fail_before_key_creation(hub, folder, rule):
    rules(rule)
    with pytest.raises(ValueError):
        device.Device(hub.invite(), str(folder), 60)
    assert not device.home().exists()


def test_exclusions_cannot_be_silently_disabled(hub, folder):
    rules('README.md')
    with pytest.raises(device.HandsError, match='require a sandbox'):
        device.Device(hub.invite(), str(folder), 60, allow_unsandboxed=True)
    assert not device.home().exists()


@sandboxed
def test_exclusions_hold_for_shell_reads_writes_links_and_parent_moves(hub, folder):
    secret = folder / 'private' / 'nested'
    secret.mkdir(parents=True)
    (secret / 'note').write_text('DO_NOT_SHARE_THIS')
    (folder / 'alias').symlink_to(secret, target_is_directory=True)
    rules('private/nested\n')
    running = up(hub, folder)
    try:
        out, code = run(hub, 'cat private/nested/note; cat alias/note; echo changed > private/nested/note')
        assert 'DO_NOT_SHARE_THIS' not in out and code != 0
        out, code = run(hub, 'mv private renamed && cat renamed/nested/note')
        assert code != 0 and 'DO_NOT_SHARE_THIS' not in out
        out, code = run(hub, 'ln private/nested/note copied && cat copied')
        assert code != 0 and 'DO_NOT_SHARE_THIS' not in out
        assert (secret / 'note').read_text() == 'DO_NOT_SHARE_THIS'
        out, code = run(hub, 'echo normal > normal.txt && cat normal.txt')
        assert code == 0 and 'normal' in out
    finally:
        running.stop()
        running.thread.join(5)


@sandboxed
def test_file_exclusion_overrides_extra_read(hub, folder):
    (folder / 'private.txt').write_text('PRIVATE_FILE_CONTENT')
    rules('private.txt')
    running = up(hub, folder, read=[str(folder)])
    try:
        out, code = run(hub, 'cat private.txt; echo bad > private.txt')
        assert 'PRIVATE_FILE_CONTENT' not in out and code != 0
        assert (folder / 'private.txt').read_text() == 'PRIVATE_FILE_CONTENT'
    finally:
        running.stop()
        running.thread.join(5)


@sandboxed
def test_results_redacted_before_server_and_local_log(hub, folder, monkeypatch):
    value = 'test-secret-value-0123456789'
    monkeypatch.setenv('TEST_API_KEY', value)
    dotenv = 'dotenv-value-9876543210'
    (folder / '.env').write_text('PASSWORD=' + dotenv)
    token = 'ghp_' + 'a' * 36
    running = up(hub, folder)
    try:
        out, code = run(hub, 'printf %s ' + shlex.quote(value + ' ' + token) + '; cat .env')
        assert code == 0
        assert all(v not in out for v in (value, token, dotenv))
        assert '[redacted]' in out and 'redacted on the device' in out
        log = (device.home() / 'log.jsonl').read_text()
        assert value not in log and token not in log
        assert all(json.loads(line) for line in log.splitlines())
        assert (folder / '.env').read_text() == 'PASSWORD=' + dotenv
    finally:
        running.stop()
        running.thread.join(5)


def test_redaction_refreshes_dotenv_and_preserves_ordinary_output(folder):
    redactor = privacy.Redactor(str(folder))
    assert redactor.clean('build passed: 123456 tests') == 'build passed: 123456 tests'
    (folder / '.env.local').write_text('export API_KEY="rotated-value-12345"')
    assert redactor.clean('rotated-value-12345') == '[redacted]'
    (folder / '.env.fifo').touch()
    (folder / '.env.fifo').unlink()
    os.mkfifo(folder / '.env.fifo')
    assert redactor.clean('normal') == 'normal'


def test_file_transport_redacts_encoded_sample_and_adjacent_markers(folder):
    import base64
    token = 'ghp_' + 'a' * 36
    marker = '__HERMES_RF_0123456789abcdef__'
    page = 'diagnostic ' + token
    encoded = base64.b64encode(page.encode()).decode()
    raw = '50\n' + marker + '\n' + encoded + '\n' + marker + '\n' + page + marker + '\n0\n'
    result = privacy.Redactor(str(folder)).clean(raw)
    assert token not in result and encoded not in result
    parts = result.split(marker)
    assert len(parts) == 4
    assert base64.b64decode(parts[1]).decode() == 'diagnostic [redacted]'
    assert parts[2] == '\ndiagnostic [redacted]'


def test_reconnect_preserves_personal_policy_location(hub, folder, monkeypatch, tmp_path):
    rules('README.md')
    original = device.Device(hub.invite(), str(folder), 60)
    config = privacy.policy_file().parent.parent.resolve()
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'different-config'))
    args = shlex.split(original.reconnect_command())
    assert 'XDG_CONFIG_HOME=' + str(config) in args[:args.index('uvx')]


def test_preflight_refuses_invalid_rules_before_contacting_server(hub, folder, monkeypatch):
    rules('missing-private-file')
    monkeypatch.setattr(device.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('network'))
    found = device.check(hub.invite(), str(folder))
    assert any(ok is False and 'never-share path does not exist' in text for ok, text in found)
    assert not device.home().exists()


def test_redaction_preserves_cwd_routing_metadata(folder):
    (folder / '.env').write_text('SECRET_WORKSPACE=' + str(folder))
    marker = '__HERMES_CWD_0123456789abcdef__'
    result = privacy.Redactor(str(folder)).clean('content ' + str(folder) + '\n' + marker + str(folder) + marker)
    assert result.startswith('content [redacted]\n')
    assert marker + str(folder) + marker in result


def test_redaction_leaves_ordinary_code_and_non_secret_settings(folder):
    (folder / '.env').write_text(
        'LOG_LEVEL=warning\nAPP_NAME=shopfront\nHOST=localhost\nNODE_ENV=development\n'
        'API_TOKEN=tok_opaque_123456\nDATABASE_URL=postgres://u:hunter2hunter2@h/db\n')
    r = privacy.Redactor(str(folder))
    # A dotenv holds ordinary settings too; their plain-word values are not redacted
    # wherever they happen to appear in output or files.
    for benign in ('run at LOG_LEVEL warning on localhost', 'the app is called shopfront',
                   'listening on PORT 8000 in development mode'):
        assert r.clean(benign) == benign, benign
    # Unquoted values are bare expressions or references, not credential literals, and a
    # quoted value that is a file path is not a secret: these are left as is.
    for code in ('TOKEN_TTL = timedelta(minutes=15)', 'password_ok = len(password) >= 12',
                 'return {"access_token": token}', 'credentials_path = "config/credentials.json"'):
        assert r.clean(code) == code, code
    # A quoted string literal under a secret-named field is redacted, even when it reads like
    # a word or contains brackets (a credential literal must not slip through).
    for secret in ('PASSWORD = "correcthorsebatterystaple"', 'password = "aB3x(K9mNp2Qr7)"',
                   'api_secret: "swordfish"', 'SECRET_KEY = "aB3xK9mNp2Qr7"'):
        assert '[redacted]' in r.clean(secret), secret
    # And the other matchers still apply: a secret-keyed dotenv value, a url credential,
    # and a recognized token format.
    assert '[redacted]' in r.clean('calling with tok_opaque_123456')
    assert r.clean('db at postgres://u:hunter2hunter2@h/db') == 'db at postgres://[redacted]@h/db'
    assert '[redacted]' in r.clean('tok = ghp_' + 'a' * 36)


@sandboxed
@pytest.mark.parametrize('mutation', ['rm .env', "printf 'PASSWORD=replacement-value' > .env"])
def test_initial_dotenv_secret_survives_first_command_mutation(hub, folder, mutation):
    secret = 'first-command-secret-98765'
    (folder / '.env').write_text('PASSWORD=' + secret)
    running = up(hub, folder)
    try:
        output, code = run(hub, 'printf %s ' + shlex.quote(secret) + '; ' + mutation)
        assert code == 0 and secret not in output and '[redacted]' in output
        assert secret not in (device.home() / 'log.jsonl').read_text()
    finally:
        running.stop()
        running.thread.join(5)


def framed_sample(page):
    import base64
    marker = '__HERMES_RF_0123456789abcdef__'
    encoded = base64.b64encode(page.encode()).decode()
    return marker, f'{len(page)}\n{marker}\n{encoded}\n{marker}\n{page}{marker}\n0\n'


@pytest.mark.parametrize('secret', ['secret', 'secret7', 'secret12', 'secret123'])
def test_short_encoded_samples_redact_supported_secrets(folder, monkeypatch, secret):
    import base64
    monkeypatch.setenv('TEST_API_KEY', secret)
    marker, raw = framed_sample(secret)
    result = privacy.Redactor(str(folder)).clean(raw)
    assert base64.b64decode(result.split(marker)[1]).decode() == '[redacted]'
    assert result.split(marker)[2] == '\n[redacted]'


def test_encoded_samples_remain_valid_when_encoded_bytes_match_secret(folder, monkeypatch):
    import base64
    monkeypatch.setenv('TEST_API_KEY', 'cGFzc3dv')
    marker, raw = framed_sample('password1234')
    redactor = privacy.Redactor(str(folder))
    result = redactor.clean(raw)
    assert base64.b64decode(result.split(marker)[1], validate=False).decode() == 'password1234'
    assert result == raw
    # A real plaintext secret that happens to be base64 is still redacted.
    assert redactor.clean('cGFzc3dv') == '[redacted]'


@sandboxed
@pytest.mark.parametrize('read_home', [False, True])
def test_exclusions_inside_existing_private_overlay_do_not_break_commands(hub, folder, monkeypatch, read_home):
    import tempfile
    from pathlib import Path
    from hermes_tenuo.hands import sandbox
    # Use a synthetic private directory in home: /tmp overlays are deliberately
    # exempt from the final read-only remount, so they would miss this regression.
    with tempfile.TemporaryDirectory(prefix='.hands-privacy-test-', dir=Path.home()) as hidden:
        excluded_file = Path(hidden) / 'credential'
        excluded_file.write_text('NEVER_SEND_THIS_CREDENTIAL')
        original = sandbox._private_paths()
        monkeypatch.setattr(sandbox, '_private_paths', lambda: [*original, hidden])
        rules(str(excluded_file))
        running = up(hub, folder, read_home=read_home)
        try:
            output, code = run(hub, 'echo ordinary-command; cat ' + shlex.quote(str(excluded_file)))
            assert 'ordinary-command' in output
            assert 'NEVER_SEND_THIS_CREDENTIAL' not in output
            assert excluded_file.read_text() == 'NEVER_SEND_THIS_CREDENTIAL'
        finally:
            running.stop()
            running.thread.join(5)
