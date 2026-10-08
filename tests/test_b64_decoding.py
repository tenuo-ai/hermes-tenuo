"""Warrant, signing key and trusted root load regardless of base64 variant."""

import base64

import pytest
from tenuo import SigningKey, Warrant

from hermes_tenuo._config import _b64_to_bytes, get_signing_key, get_trusted_roots, load_warrant


def _variants(raw: bytes):
    std = base64.b64encode(raw).decode()
    url = base64.urlsafe_b64encode(raw).decode()
    return {
        "standard+pad": std,
        "standard-nopad": std.rstrip("="),
        "urlsafe+pad": url,
        "urlsafe-nopad": url.rstrip("="),
    }


# A 32-byte key whose standard encoding uses both '+' and '/', so standard and
# url-safe forms actually differ.
_KEY_BYTES = bytes([0xFB, 0xFF, 0xBF, 0x3E] * 8)


@pytest.mark.parametrize("label,encoded", list(_variants(_KEY_BYTES).items()))
def test_decoder_accepts_every_variant(label, encoded):
    assert _b64_to_bytes(encoded) == _KEY_BYTES, label


@pytest.mark.parametrize("variant", ["standard+pad", "standard-nopad", "urlsafe+pad", "urlsafe-nopad"])
def test_signing_key_and_root_load_in_any_variant(variant, monkeypatch):
    agent, root = SigningKey.generate(), SigningKey.generate()
    key_v = _variants(agent.secret_key_bytes())[variant]
    root_v = _variants(root.public_key.to_bytes())[variant]
    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry",
                        lambda ctx: {"trusted_root": root_v, "signing_key_env": "TENUO_SIGNING_KEY"})
    monkeypatch.setenv("TENUO_SIGNING_KEY", key_v)
    k = get_signing_key(None)
    assert k is not None and bytes(k.public_key.to_bytes()) == bytes(agent.public_key.to_bytes())
    roots = get_trusted_roots(None)
    assert roots and bytes(roots[0].to_bytes()) == bytes(root.public_key.to_bytes())


@pytest.mark.parametrize("variant", ["standard+pad", "standard-nopad", "urlsafe+pad", "urlsafe-nopad"])
def test_warrant_loads_in_any_variant(variant):
    root, agent = SigningKey.generate(), SigningKey.generate()
    w = Warrant.mint_builder().holder(agent.public_key).capability("read").ttl(60).mint(root)
    loaded = load_warrant(_variants(w.to_bytes())[variant])
    assert loaded is not None
