"""Cloud receipts: a connect token plus tenuo[cloud] adds a CloudReceiptSink."""

import logging
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from hermes_tenuo import hermes_guard as hg


@pytest.fixture
def no_global_client():
    with patch("tenuo.control_plane.get_client", return_value=None):
        yield


@pytest.fixture
def fake_cloud(monkeypatch):
    mod = types.ModuleType("tenuo_cloud")
    mod.connect = MagicMock(name="tenuo_cloud.connect", return_value="cloud-client")
    mod.CloudReceiptSink = MagicMock(name="CloudReceiptSink", return_value="cloud-sink")
    monkeypatch.setitem(sys.modules, "tenuo_cloud", mod)
    return mod


def test_no_token_uses_plain_client(monkeypatch, no_global_client):
    monkeypatch.delenv("TENUO_CONNECT_TOKEN", raising=False)
    with patch("tenuo.control_plane.get_or_create", return_value=None) as plain, \
         patch("tenuo.control_plane.connect") as connect:
        assert hg._connect_control_plane() is None
    plain.assert_called_once()
    connect.assert_not_called()


def test_existing_client_is_reused(monkeypatch):
    monkeypatch.setenv("TENUO_CONNECT_TOKEN", "tenuo_ct_x")
    existing = object()
    with patch("tenuo.control_plane.get_client", return_value=existing), \
         patch("tenuo.control_plane.get_or_create", return_value=existing), \
         patch("tenuo.control_plane.connect") as connect:
        assert hg._connect_control_plane() is existing
    connect.assert_not_called()


def test_token_with_cloud_sdk_adds_receipt_sink(monkeypatch, no_global_client, fake_cloud):
    monkeypatch.setenv("TENUO_CONNECT_TOKEN", "tenuo_ct_x")
    client = MagicMock(name="ControlPlaneClient")
    with patch("tenuo.control_plane.connect", return_value=client) as connect, \
         patch("atexit.register") as at_exit:
        assert hg._connect_control_plane() is client
    fake_cloud.connect.assert_called_once_with(claim=False, apply_env=False)
    fake_cloud.CloudReceiptSink.assert_called_once_with("cloud-client")
    assert connect.call_args.kwargs["receipt_sink"] == "cloud-sink"
    assert connect.call_args.kwargs["on_receipt_error"] is hg._log_receipt_error
    at_exit.assert_called_once_with(hg._flush_receipts, client, hg._EXIT_FLUSH_SECS)


def test_token_without_cloud_sdk_warns_and_falls_back(monkeypatch, no_global_client, caplog):
    monkeypatch.setenv("TENUO_CONNECT_TOKEN", "tenuo_ct_x")
    monkeypatch.setitem(sys.modules, "tenuo_cloud", None)  # import raises ImportError
    plain = object()
    with patch("tenuo.control_plane.get_or_create", return_value=plain), \
         caplog.at_level(logging.WARNING, logger="hermes_tenuo"):
        assert hg._connect_control_plane() is plain
    assert "without signed receipts" in caplog.text


def test_cloud_setup_failure_falls_back(monkeypatch, no_global_client, fake_cloud, caplog):
    monkeypatch.setenv("TENUO_CONNECT_TOKEN", "tenuo_ct_x")
    fake_cloud.connect.side_effect = RuntimeError("bad token")
    plain = object()
    with patch("tenuo.control_plane.get_or_create", return_value=plain), \
         caplog.at_level(logging.WARNING, logger="hermes_tenuo"):
        assert hg._connect_control_plane() is plain
    assert "Cloud receipts unavailable" in caplog.text


def test_flush_is_bounded_and_never_raises(caplog):
    client = MagicMock()
    client.flush_receipts.return_value = False
    with caplog.at_level(logging.WARNING, logger="hermes_tenuo"):
        hg._flush_receipts(client, 2.0)
    client.flush_receipts.assert_called_once_with(timeout=2.0)
    assert "still pending" in caplog.text

    client.flush_receipts.side_effect = RuntimeError("boom")
    hg._flush_receipts(client, 2.0)  # logged, not raised
    hg._flush_receipts(object(), 2.0)  # no flush_receipts: no-op


def test_session_end_flushes_receipts():
    from tenuo import SigningKey, Warrant

    from hermes_tenuo.hermes_guard import HermesGuard

    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder().holder(agent_key.public_key)
        .capability("read_file").ttl(600).mint(root_key)
    )
    guard = HermesGuard(warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key])
    guard._control_plane = MagicMock()
    guard._control_plane.flush_receipts.return_value = True
    guard.on_session_end("s1")
    guard._control_plane.flush_receipts.assert_called_once_with(timeout=hg._SESSION_END_FLUSH_SECS)
