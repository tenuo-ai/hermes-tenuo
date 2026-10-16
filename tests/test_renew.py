"""Renewal authenticates the previous grant and preserves its scope."""
import argparse
import base64
import time

from tenuo import SigningKey, Subpath, Warrant


def prepare(tmp_path, ttl=120):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    old = Warrant.mint_builder().holder(holder.public_key).capability('read_file', path=Subpath('/data')).ttl(ttl).session_id('session-a').mint(issuer)
    (tmp_path / 'issuer.key').write_text(base64.b64encode(issuer.secret_key_bytes()).decode())
    (tmp_path / 'old.warrant').write_text(old.to_base64())
    args = argparse.Namespace(from_path=str(tmp_path / 'old.warrant'), issuer_key=str(tmp_path / 'issuer.key'), ttl='10m', out=str(tmp_path / 'new.warrant'))
    return args, old, issuer, holder


def test_renew_preserves_scope_without_holder_secret(tmp_path, monkeypatch):
    from hermes_tenuo.cli import cmd_renew
    args, old, issuer, holder = prepare(tmp_path)
    monkeypatch.setenv('TENUO_SIGNING_KEY', 'invalid')
    assert cmd_renew(args) == 0
    new = Warrant.from_base64((tmp_path / 'new.warrant').read_text().strip())
    assert new.verify(issuer.public_key.to_bytes())
    assert new.holder_key.to_bytes() == holder.public_key.to_bytes()
    assert new.session_id == old.session_id
    assert repr(new.capabilities) == repr(old.capabilities)
    assert 595 <= new.ttl_seconds() <= 600
    assert new.id != old.id


def test_renew_authenticates_expired_warrant(tmp_path):
    from hermes_tenuo.cli import cmd_renew
    args, old, _, _ = prepare(tmp_path, ttl=1)
    time.sleep(1.05)
    assert old.is_expired()
    args.ttl = "1m"
    assert cmd_renew(args) == 0
    new = Warrant.from_base64((tmp_path / 'new.warrant').read_text().strip())
    assert 55 <= new.ttl_seconds() <= 60


def test_renew_rejects_wrong_issuer_and_corruption(tmp_path):
    from hermes_tenuo.cli import cmd_renew
    args, _, _, _ = prepare(tmp_path)
    (tmp_path / 'issuer.key').write_text(base64.b64encode(SigningKey.generate().secret_key_bytes()).decode())
    assert cmd_renew(args) == 1
    (tmp_path / 'old.warrant').write_text('not-a-warrant')
    assert cmd_renew(args) == 1
    assert not (tmp_path / 'new.warrant').exists()


def test_renew_rejects_approval_gates_instead_of_dropping_them(tmp_path):
    from hermes_tenuo.cli import cmd_renew
    args, _, issuer, holder = prepare(tmp_path)
    old = Warrant.mint_builder().holder(holder.public_key).capability('read_file').approval_gates({'read_file': None}).ttl(120).mint(issuer)
    (tmp_path / 'old.warrant').write_text(old.to_base64())
    assert cmd_renew(args) == 1
    assert not (tmp_path / 'new.warrant').exists()


def test_renew_rejects_tampered_signature(tmp_path):
    from hermes_tenuo.cli import cmd_renew
    args, old, _, _ = prepare(tmp_path)
    encoded = bytearray(old.to_bytes())
    encoded[-1] ^= 1
    (tmp_path / 'old.warrant').write_text(base64.b64encode(encoded).decode())
    assert cmd_renew(args) == 1
    assert not (tmp_path / 'new.warrant').exists()


def test_renew_and_replace_in_running_session_retains_other_grants(tmp_path):
    from hermes_tenuo.cli import cmd_renew
    from hermes_tenuo.session_guard import SessionGuard
    from hermes_tenuo.session_store import attach_warrant, read_session
    args, old, issuer, holder = prepare(tmp_path, ttl=2)
    directory = tmp_path / 'sessions'
    other = Warrant.mint_builder().holder(holder.public_key).capability('web_search').ttl(60).mint(issuer)
    other_path = tmp_path / 'other.warrant'
    other_path.write_text(other.to_base64())
    attach_warrant(tmp_path / 'old.warrant', 'session-a', directory)
    attach_warrant(other_path, 'session-a', directory)
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    assert guard.pre_tool_call('read_file', {'path': '/data/report.txt'}, session_id='session-a') is None
    time.sleep(2.1)
    assert guard.pre_tool_call('read_file', {'path': '/data/report.txt'}, session_id='session-a')
    assert guard.pre_tool_call('web_search', {}, session_id='session-a') is None
    assert cmd_renew(args) == 0
    attach_warrant(args.out, 'session-a', directory, replace_id=str(old.id))
    assert guard.pre_tool_call('read_file', {'path': '/data/report.txt'}, session_id='session-a') is None
    assert guard.pre_tool_call('web_search', {}, session_id='session-a') is None
    assert len(read_session('session-a', directory)) == 2
    assert guard.pre_tool_call('read_file', {'path': '/data/report.txt'}, session_id='session-b')
