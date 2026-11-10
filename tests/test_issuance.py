"""Separate issuance never needs a holder secret."""
import argparse
import base64
import stat

from tenuo import SigningKey, Warrant

from hermes_tenuo.cli import cmd_mint


def test_explicit_issuance_ignores_holder_secret(tmp_path, monkeypatch, capsys):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    issuer_path, public_path, output = (tmp_path / n for n in ('issuer.key', 'holder.pub', 'grant.warrant'))
    issuer_path.write_text(base64.b64encode(issuer.secret_key_bytes()).decode())
    public_path.write_text(base64.b64encode(holder.public_key.to_bytes()).decode())
    monkeypatch.setenv('TENUO_SIGNING_KEY', 'deliberately-invalid-secret')
    args = argparse.Namespace(ttl='20m', allow=['read_file:path=/data'], output='full',
                              issuer_key=str(issuer_path), holder_public_key=str(public_path),
                              out=str(output), session_id='conversation-123')
    assert cmd_mint(args) == 0
    warrant = Warrant.from_base64(output.read_text().strip())
    assert warrant.verify(issuer.public_key.to_bytes())
    assert warrant.holder_key.to_bytes() == holder.public_key.to_bytes()
    assert warrant.session_id == 'conversation-123'
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    text = capsys.readouterr().out
    assert base64.b64encode(holder.secret_key_bytes()).decode() not in text
    assert base64.b64encode(issuer.secret_key_bytes()).decode() not in text


def test_keygen_writes_safe_files(tmp_path, capsys):
    from hermes_tenuo.cli import cmd_keygen
    args = argparse.Namespace(private_key=str(tmp_path / 'identity.key'), public_key=str(tmp_path / 'identity.pub'))
    assert cmd_keygen(args) == 0
    secret = (tmp_path / 'identity.key').read_text().strip()
    assert secret not in capsys.readouterr().out
    assert stat.S_IMODE((tmp_path / 'identity.key').stat().st_mode) == 0o600
    assert cmd_keygen(args) == 1  # never accidentally rotate an existing identity


def test_keygen_does_not_strand_private_key_when_public_write_fails(tmp_path, monkeypatch):
    from hermes_tenuo import issuance
    from hermes_tenuo.cli import cmd_keygen

    private_path = tmp_path / 'identity.key'
    public_path = tmp_path / 'identity.pub'
    original_write = issuance.write_private_file
    writes = 0

    def fail_public_write(path, text, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("public destination unavailable")
        return original_write(path, text, **kwargs)

    monkeypatch.setattr(issuance, 'write_private_file', fail_public_write)
    args = argparse.Namespace(private_key=str(private_path), public_key=str(public_path))

    assert cmd_keygen(args) == 1
    assert not private_path.exists()
    assert not public_path.exists()


def test_explicit_issuance_requires_both_keys_and_output(tmp_path):
    for fields in ({'issuer_key': 'issuer.key'}, {'holder_public_key': 'holder.pub'},
                   {'issuer_key': 'issuer.key', 'holder_public_key': 'holder.pub'}):
        args = argparse.Namespace(ttl='1h', allow=['web_search'], output='full', **fields)
        assert cmd_mint(args) == 1


def test_nonfinite_ttl_is_a_normal_cli_error(capsys):
    from hermes_tenuo.cli import _parse_ttl
    import pytest
    for ttl in ('inf', 'infs', '1e999h', 'nan'):
        with pytest.raises(ValueError, match='expected a duration'):
            _parse_ttl(ttl)
        args = argparse.Namespace(ttl=ttl, allow=['web_search'], output='env')
        assert cmd_mint(args) == 1
    assert 'error:' in capsys.readouterr().err


def _identity_files(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    issuer_path, public_path = tmp_path / 'issuer.key', tmp_path / 'holder.pub'
    issuer_path.write_text(base64.b64encode(issuer.secret_key_bytes()).decode())
    public_path.write_text(base64.b64encode(holder.public_key.to_bytes()).decode())
    return issuer, holder, issuer_path, public_path


def test_task_warrant_can_be_signed_by_the_operator_issuer(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.kanban import task_warrant_path

    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'h'))
    issuer, holder, issuer_path, public_path = _identity_files(tmp_path)
    args = argparse.Namespace(ttl='2h', allow=['read_file:path=/data/card'], output='full', task='card-7',
                              issuer_key=str(issuer_path), holder_public_key=str(public_path),
                              out=None, session_id=None)
    assert cmd_mint(args) == 0
    path = task_warrant_path('card-7')
    warrant = Warrant.from_base64(path.read_text().strip())
    assert warrant.verify(issuer.public_key.to_bytes())
    assert warrant.holder_key.to_bytes() == holder.public_key.to_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert f'Warrant saved: {path}' in capsys.readouterr().out
    # Re-issuing a task replaces its warrant.
    first = path.read_text()
    assert cmd_mint(args) == 0
    assert path.read_text() != first


def test_task_and_out_together_are_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'h'))
    _issuer, _holder, issuer_path, public_path = _identity_files(tmp_path)
    args = argparse.Namespace(ttl='2h', allow=['read_file'], output='full', task='card-7',
                              issuer_key=str(issuer_path), holder_public_key=str(public_path),
                              out=str(tmp_path / 'x.warrant'), session_id=None)
    assert cmd_mint(args) == 1
    assert 'do not pass --out' in capsys.readouterr().err
    assert not (tmp_path / 'x.warrant').exists()


def test_task_id_must_not_be_a_path(tmp_path, monkeypatch, capsys):
    from hermes_tenuo.kanban import task_warrant_path

    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'h'))
    _issuer, _holder, issuer_path, public_path = _identity_files(tmp_path)
    for task in ('../../escaped', 'a/b', '..'):
        local = argparse.Namespace(ttl='1h', allow=['read_file'], output='env', task=task)
        assert cmd_mint(local) == 1
        separate = argparse.Namespace(ttl='1h', allow=['read_file'], output='full', task=task,
                                      issuer_key=str(issuer_path), holder_public_key=str(public_path),
                                      out=None, session_id=None)
        assert cmd_mint(separate) == 1
        assert 'not a path' in capsys.readouterr().err
    assert not (tmp_path / 'h' / 'escaped.warrant').exists()
    assert not task_warrant_path('x').parent.exists()
