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
