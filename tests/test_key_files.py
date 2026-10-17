"""Runtime keys can live in operator-selected files without fallback ambiguity."""
import base64

import pytest
from tenuo import SigningKey, Warrant

from hermes_tenuo import _config
from hermes_tenuo._guard import WarrantLoadError, build_plugin_guard


def setup_keys(tmp_path, monkeypatch):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().holder(holder.public_key).capability('get_status').ttl(60).mint(issuer)
    (tmp_path / 'holder.key').write_text(base64.b64encode(holder.secret_key_bytes()).decode())
    (tmp_path / 'issuer.pub').write_text(base64.b64encode(issuer.public_key.to_bytes()).decode())
    entry = {'signing_key_file': 'holder.key', 'trusted_root_file': 'issuer.pub',
             'warrant': warrant.to_base64(), 'audit_log': False}
    monkeypatch.setattr(_config, '_get_plugin_entry', lambda _: entry)
    monkeypatch.setattr('hermes_tenuo._home.hermes_home', lambda: tmp_path)
    monkeypatch.delenv('TENUO_SIGNING_KEY', raising=False)
    monkeypatch.delenv('TENUO_TRUSTED_ROOT', raising=False)
    return entry, issuer, holder


def test_file_keys_authorize_real_guard(tmp_path, monkeypatch):
    setup_keys(tmp_path, monkeypatch)
    guard = build_plugin_guard(None)
    assert guard.pre_tool_call_hook('get_status', {}, session_id='conversation') is None
    assert guard.pre_tool_call_hook('other_tool', {}, session_id='conversation')


@pytest.mark.parametrize('alias', [False, True])
def test_trust_file_cannot_point_to_private_key(tmp_path, monkeypatch, alias):
    entry, _, _ = setup_keys(tmp_path, monkeypatch)
    path = tmp_path / 'holder.key'
    if alias:
        link = tmp_path / 'alias.pub'
        link.symlink_to(path)
        path = link
    entry['trusted_root_file'] = str(path)
    with pytest.raises(WarrantLoadError):
        build_plugin_guard(None)


@pytest.mark.parametrize('filename', ['holder.key', 'issuer.pub'])
@pytest.mark.parametrize('failure', ['missing', 'bad', 'oversize'])
def test_bad_file_never_falls_back_even_without_warrant(tmp_path, monkeypatch, filename, failure):
    entry, _, _ = setup_keys(tmp_path, monkeypatch)
    entry.pop('warrant')
    path = tmp_path / filename
    if failure == 'missing':
        path.unlink()
    else:
        path.write_text('x' * 65537 if failure == 'oversize' else 'not-a-key')
    with pytest.raises(WarrantLoadError):
        build_plugin_guard(None)


@pytest.mark.parametrize('field,value', [('trusted_root', 'inline'), ('signing_key_env', 'OTHER_KEY')])
def test_conflicting_explicit_settings_fail_closed(tmp_path, monkeypatch, field, value):
    entry, _, _ = setup_keys(tmp_path, monkeypatch)
    entry[field] = value
    with pytest.raises(WarrantLoadError):
        build_plugin_guard(None)


@pytest.mark.parametrize('variable', ['TENUO_SIGNING_KEY', 'TENUO_TRUSTED_ROOT'])
def test_file_and_env_secret_conflict(tmp_path, monkeypatch, variable):
    setup_keys(tmp_path, monkeypatch)
    monkeypatch.setenv(variable, 'unrelated-key')
    with pytest.raises(WarrantLoadError):
        build_plugin_guard(None)


def test_relative_paths_follow_active_profile(tmp_path, monkeypatch):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    _, _, holder1 = setup_keys(first, monkeypatch)
    _, _, holder2 = setup_keys(second, monkeypatch)
    assert _config.get_signing_key(None).public_key.to_bytes() == holder2.public_key.to_bytes()
    monkeypatch.setattr('hermes_tenuo._home.hermes_home', lambda: first)
    assert _config.get_signing_key(None).public_key.to_bytes() == holder1.public_key.to_bytes()


def test_status_and_doctor_use_file_sources(tmp_path, monkeypatch, capsys):
    import argparse
    from hermes_tenuo.cli import cmd_status, cmd_doctor
    entry, _, _ = setup_keys(tmp_path, monkeypatch)
    monkeypatch.setattr('hermes_tenuo._home.load_hermes_config', lambda: {'plugins': {'entries': {'hermes-tenuo': entry}}})
    cmd_status(argparse.Namespace())
    status = capsys.readouterr().out
    assert 'signing_key_file' in status
    assert 'trusted_root_file' in status
    cmd_doctor(argparse.Namespace())
    doctor = capsys.readouterr().out
    assert '✓  signing key matches warrant holder' in doctor
    assert '✓  trusted_root set and loadable' in doctor
