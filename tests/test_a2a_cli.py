"""hermes-tenuo a2a: pairing key, revocation lists and the readiness check."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
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
    monkeypatch.delenv("A2A_BEARER_TOKEN", raising=False)
    (home / ".env").write_text("A2A_PEER_TOKENS=agent-a:example-token\n")
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
    srl = tmp_path / "revocations.srl"
    root = _configure(tmp_path, monkeypatch, srl_path=srl)
    key_file = tmp_path / "root.key"
    key_file.write_text(base64.b64encode(root.secret_key_bytes()).decode())
    args = SimpleNamespace(ids=["tnu_wrt_a"], root_key=str(key_file), list=str(srl))
    assert a2a_cli.cmd_revoke(args) == 0
    assert a2a_cli.cmd_revoke(SimpleNamespace(**{**vars(args), "ids": ["tnu_wrt_b"]})) == 0
    loaded = SignedRevocationList.from_bytes(srl.read_bytes())  # raw bytes, shared with the MCP wrapper
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


@pytest.mark.parametrize(("env", "message"), [
    ("A2A_BEARER_TOKEN=shared\nA2A_PEER_TOKENS=agent-a:example-token", "Unset A2A_BEARER_TOKEN"),
    ("A2A_PEER_TOKENS=agent-a:example-token,agent-b:second-token", "exactly one sender identity"),
    ("A2A_PEER_TOKENS=agent-b:example-token", "must match the sole entry"),
    ("A2A_PEER_TOKENS=agent-a:", "name:token format"),
    ("A2A_PEER_TOKENS=", "exactly one sender identity"),
])
def test_check_refuses_unsafe_receiver_authentication(tmp_path, monkeypatch, capsys, env, message):
    _configure(tmp_path, monkeypatch)
    (tmp_path / "hermes-home" / ".env").write_text(env)
    assert a2a_cli.cmd_check(None) == 1
    error = capsys.readouterr().err
    assert message in error and "example-token" not in error and "second-token" not in error


def test_misconfigured_receiver_drops_a2a_dispatch(tmp_path, monkeypatch):
    from hermes_tenuo import _register_a2a_ingress
    from hermes_tenuo import _config

    _configure(tmp_path, monkeypatch)
    env = {"A2A_PEER_TOKENS": "agent-a:example-token,agent-b:second-token"}
    monkeypatch.setattr(_config, "_env_secret", env.get)
    hooks = {}
    assert _register_a2a_ingress(SimpleNamespace(register_hook=hooks.__setitem__)) is None
    hook = hooks["pre_gateway_dispatch"]
    assert hook(SimpleNamespace(source=SimpleNamespace(platform="a2a")))["action"] == "skip"
    assert hook(SimpleNamespace(source=SimpleNamespace(platform="telegram"))) is None


def test_revocation_list_bytes_are_read_raw_or_as_base64():
    from hermes_tenuo.a2a_ingress import srl_bytes

    raw = bytes(range(256)) + b"  \n"  # binary that ends in whitespace bytes stays intact
    assert srl_bytes(raw) == raw
    assert srl_bytes(base64.b64encode(b"abc") + b"\n") == b"abc"


@pytest.mark.parametrize("token", [None, "", "example-token"])
def test_sender_readiness_requires_each_peer_token(tmp_path, monkeypatch, capsys, token):
    from hermes_tenuo.a2a_delegate import Peer, SenderConfig

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("PEER_TEST_TOKEN", raising=False)
    if token is not None:
        (tmp_path / ".env").write_text(f"PEER_TEST_TOKEN={token}\n")
    monkeypatch.setattr("hermes_tenuo.a2a_ingress.load_ingress", lambda *a, **kw: None)
    monkeypatch.setattr("hermes_tenuo.a2a_delegate.load_sender_config", lambda ctx: SenderConfig(
        peers={"peer": Peer("peer", "http://peer:9900", "unused", "PEER_TEST_TOKEN")}))
    assert a2a_cli.cmd_check(None) == (0 if token else 1)
    output = capsys.readouterr()
    assert "example-token" not in output.out + output.err
    if not token:
        assert "PEER_TEST_TOKEN" in output.err
