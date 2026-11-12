"""hermes-tenuo a2a: pairing key, revocation lists and the readiness check."""

from __future__ import annotations

import base64
from types import SimpleNamespace

from tenuo import SignedRevocationList, SigningKey

from hermes_tenuo import a2a_cli


def _pub(key):
    return base64.b64encode(key.public_key.to_bytes()).decode()


def _configure(tmp_path, monkeypatch, *, srl_path=None):
    root, peer = SigningKey.generate(), SigningKey.generate()
    home = tmp_path / "hermes-home"
    home.mkdir(exist_ok=True)
    srl_line = f"\n        revocation_list: {srl_path}" if srl_path else ""
    (home / "config.yaml").write_text(f"""plugins:
  entries:
    hermes-tenuo:
      a2a_ingress:
        enabled: true
        peers: {{agent-a: "{_pub(peer)}"}}
        trusted_roots: ["{_pub(root)}"]{srl_line}
""")
    monkeypatch.setenv("HERMES_HOME", str(home))
    return root


def test_key_creates_a_private_key_once_and_prints_the_public_half(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    assert a2a_cli.cmd_key(None) == 0
    first = capsys.readouterr().out
    assert a2a_cli.cmd_key(None) == 0
    assert capsys.readouterr().out == first  # the same key, not a new one
    key_file = tmp_path / "hermes-home" / "tenuo" / "a2a.key"
    assert oct(key_file.stat().st_mode & 0o777) == "0o600"
    assert key_file.read_text().strip() not in first


def test_revoke_signs_and_extends_a_list_the_receiver_accepts(tmp_path, monkeypatch, capsys):
    srl = tmp_path / "srl.b64"
    root = _configure(tmp_path, monkeypatch, srl_path=srl)
    key_file = tmp_path / "root.key"
    key_file.write_text(base64.b64encode(root.secret_key_bytes()).decode())
    args = SimpleNamespace(ids=["tnu_wrt_a"], root_key=str(key_file), list=str(srl))
    assert a2a_cli.cmd_revoke(args) == 0
    assert a2a_cli.cmd_revoke(SimpleNamespace(**{**vars(args), "ids": ["tnu_wrt_b"]})) == 0
    loaded = SignedRevocationList.from_bytes(base64.b64decode(srl.read_text()))
    assert loaded.version == 2 and set(loaded.revoked_ids) == {"tnu_wrt_a", "tnu_wrt_b"}
    capsys.readouterr()
    assert a2a_cli.cmd_check(None) == 0
    assert "version 2, 2 revoked" in capsys.readouterr().out


def test_check_reports_a_list_that_cannot_be_used(tmp_path, monkeypatch, capsys):
    _configure(tmp_path, monkeypatch, srl_path=tmp_path / "missing.b64")
    assert a2a_cli.cmd_check(None) == 1
    assert "every delegation is refused" in capsys.readouterr().err


def test_check_reports_an_unusable_ingress_block(tmp_path, monkeypatch, capsys):
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "config.yaml").write_text("plugins:\n  entries:\n    hermes-tenuo:\n      a2a_ingress: {enabled: true}\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert a2a_cli.cmd_check(None) == 1
    assert "every inbound A2A message would be dropped" in capsys.readouterr().err
