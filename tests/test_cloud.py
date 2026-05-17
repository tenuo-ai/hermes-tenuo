"""
Tests for hermes_tenuo._cloud — connect token parsing, trigger firing,
approval handler, and PluginGuard Cloud integration.
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# parse_connect_token
# ---------------------------------------------------------------------------

def _make_token(endpoint: str, api_key: str, agent_id: str = "", reg_token: str = "") -> str:
    payload = {"v": 1, "e": endpoint, "k": api_key}
    if agent_id:
        payload["a"] = agent_id
    if reg_token:
        payload["t"] = reg_token
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"tenuo_ct_{raw}"


class TestParseConnectToken:

    def test_parses_valid_token(self):
        from hermes_tenuo._cloud import parse_connect_token
        token = _make_token("https://api.tenuo.ai", "tc_test123", agent_id="agt_abc")
        creds = parse_connect_token(token)
        assert creds is not None
        assert creds.api_key == "tc_test123"
        assert creds.agent_id == "agt_abc"

    def test_normalizes_endpoint_with_v1(self):
        from hermes_tenuo._cloud import parse_connect_token
        token = _make_token("https://api.tenuo.ai", "tc_x")
        creds = parse_connect_token(token)
        assert creds.endpoint == "https://api.tenuo.ai/v1"

    def test_does_not_double_v1(self):
        from hermes_tenuo._cloud import parse_connect_token
        token = _make_token("https://api.tenuo.ai/v1", "tc_x")
        creds = parse_connect_token(token)
        assert creds.endpoint == "https://api.tenuo.ai/v1"

    def test_returns_none_for_invalid_token(self):
        from hermes_tenuo._cloud import parse_connect_token
        assert parse_connect_token("not-a-token") is None
        assert parse_connect_token("") is None
        assert parse_connect_token(None) is None

    def test_parses_token_without_prefix(self):
        """Token payload without tenuo_ct_ prefix is still parsed."""
        from hermes_tenuo._cloud import parse_connect_token
        payload = {"v": 1, "e": "https://api.tenuo.ai", "k": "tc_raw"}
        raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        creds = parse_connect_token(raw)
        assert creds is not None
        assert creds.api_key == "tc_raw"

    def test_includes_registration_token(self):
        from hermes_tenuo._cloud import parse_connect_token
        token = _make_token("https://api.tenuo.ai", "tc_x", reg_token="reg_abc")
        creds = parse_connect_token(token)
        assert creds.registration_token == "reg_abc"


# ---------------------------------------------------------------------------
# fire_trigger
# ---------------------------------------------------------------------------

def _make_warrant_b64() -> str:
    """Create a real warrant for testing (we need a real one for issuer extraction)."""
    from tenuo import SigningKey, Warrant, Wildcard
    k = SigningKey.generate()
    w = Warrant.mint_builder().holder(k.public_key).capability("web_search", query=Wildcard()).ttl(60).mint(k)
    return base64.b64encode(w.to_bytes()).decode()


class TestFireTrigger:

    def test_fires_trigger_and_returns_result(self):
        from hermes_tenuo._cloud import fire_trigger
        warrant_b64 = _make_warrant_b64()
        mock_resp = {"warrant": warrant_b64, "warrant_id": "wrt_123", "expires_at": "2026-06-01T00:00:00Z"}

        with patch("hermes_tenuo._cloud._api_request", return_value=mock_resp) as mock_req:
            result = fire_trigger(
                "trig_abc",
                api_key="tc_test",
                endpoint="https://api.tenuo.ai/v1",
            )

        mock_req.assert_called_once()
        args = mock_req.call_args
        assert args[0][0] == "POST"
        assert "triggers/trig_abc/fire" in args[0][1]
        assert result.warrant_b64 == warrant_b64
        assert result.warrant_id == "wrt_123"

    def test_extracts_trusted_root_from_warrant(self):
        from hermes_tenuo._cloud import fire_trigger
        warrant_b64 = _make_warrant_b64()
        mock_resp = {"warrant": warrant_b64, "warrant_id": "wrt_x"}

        with patch("hermes_tenuo._cloud._api_request", return_value=mock_resp):
            result = fire_trigger("trig_x", api_key="tc_x", endpoint="https://api.tenuo.ai/v1")

        assert result.trusted_root_b64 != ""  # issuer extracted from warrant

    def test_raises_on_missing_warrant_in_response(self):
        from hermes_tenuo._cloud import fire_trigger, CloudAPIError
        with patch("hermes_tenuo._cloud._api_request", return_value={"warrant_id": "x"}):
            with pytest.raises(CloudAPIError, match="missing 'warrant'"):
                fire_trigger("trig_x", api_key="tc_x", endpoint="https://api.tenuo.ai/v1")

    def test_passes_event_data(self):
        from hermes_tenuo._cloud import fire_trigger
        warrant_b64 = _make_warrant_b64()
        with patch("hermes_tenuo._cloud._api_request", return_value={"warrant": warrant_b64}) as mock_req:
            fire_trigger(
                "trig_x",
                api_key="tc_x",
                endpoint="https://api.tenuo.ai/v1",
                event_data={"session_id": "sess_abc"},
            )
        body = mock_req.call_args[1]["body"]
        assert body.get("event_data") == {"session_id": "sess_abc"}


# ---------------------------------------------------------------------------
# PluginGuard Cloud integration
# ---------------------------------------------------------------------------

class TestPluginGuardCloudIntegration:

    def _build_guard_with_cloud(self, connect_token, warrant_b64, agent_key_b64, trusted_root_b64):
        from hermes_tenuo._guard import build_plugin_guard
        entry = {
            "warrant": warrant_b64,
            "trusted_root": trusted_root_b64,
        }
        with patch("hermes_tenuo._config._get_plugin_entry", return_value=entry):
            with patch("hermes_tenuo._config.get_connect_token", return_value=connect_token):
                import os
                with patch.dict(os.environ, {"TENUO_SIGNING_KEY": agent_key_b64}):
                    with patch("tenuo.control_plane.connect"):
                        return build_plugin_guard(MagicMock())

    def test_cloud_approval_handler_wired_when_token_present(self):
        from tenuo import SigningKey, Warrant, Wildcard
        import base64

        root_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("web_search", query=Wildcard())
            .ttl(3600)
            .mint(root_key)
        )
        token = _make_token("https://api.tenuo.ai", "tc_test")
        agent_key_b64 = base64.b64encode(agent_key.secret_key_bytes()).decode()
        warrant_b64 = base64.b64encode(warrant.to_bytes()).decode()
        trusted_root_b64 = base64.b64encode(root_key.public_key.to_bytes()).decode()

        guard = self._build_guard_with_cloud(token, warrant_b64, agent_key_b64, trusted_root_b64)
        assert guard is not None
        assert guard._guard._approval_handler is not None

    def test_fire_session_warrant_calls_trigger(self):
        from tenuo import SigningKey, Warrant, Wildcard
        import base64

        root_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("web_search", query=Wildcard())
            .ttl(60)
            .mint(root_key)
        )
        warrant_b64 = base64.b64encode(warrant.to_bytes()).decode()

        from hermes_tenuo._cloud import ConnectTokenData, FireTriggerResult
        creds = ConnectTokenData(endpoint="https://api.tenuo.ai/v1", api_key="tc_x")
        trusted_root_b64 = base64.b64encode(root_key.public_key.to_bytes()).decode()

        from hermes_tenuo._guard import PluginGuard
        from hermes_tenuo.hermes_guard import HermesGuard
        inner = HermesGuard()
        pg = PluginGuard(inner, cloud_creds=creds)

        fire_result = FireTriggerResult(
            warrant_b64=warrant_b64,
            warrant_id="wrt_x",
            expires_at="",
            trusted_root_b64=trusted_root_b64,
        )
        with patch("hermes_tenuo._cloud.fire_trigger", return_value=fire_result):
            ok = pg.fire_session_warrant("sess_abc", "trig_xyz")

        assert ok is True
        with inner._session_lock:
            assert "sess_abc" in inner._session_warrants

    def test_fire_session_warrant_returns_false_without_creds(self):
        from hermes_tenuo._guard import PluginGuard
        from hermes_tenuo.hermes_guard import HermesGuard
        pg = PluginGuard(HermesGuard(), cloud_creds=None)
        assert pg.fire_session_warrant("sess_x", "trig_y") is False


# ---------------------------------------------------------------------------
# CLI --trigger
# ---------------------------------------------------------------------------

class TestMintTriggerCLI:

    def test_mint_trigger_requires_connect_token(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        import argparse, os
        args = argparse.Namespace(trigger="trig_x", output="env", connect_token=None)
        env = {k: v for k, v in os.environ.items() if k != "TENUO_CONNECT_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            result = cmd_mint(args)
        assert result == 1

    def test_mint_trigger_calls_fire_trigger(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        from hermes_tenuo._cloud import FireTriggerResult
        import argparse

        warrant_b64 = _make_warrant_b64()
        fire_result = FireTriggerResult(
            warrant_b64=warrant_b64,
            warrant_id="wrt_test",
            expires_at="2026-12-31T00:00:00Z",
            trusted_root_b64="dGVzdA==",
        )
        token = _make_token("https://api.tenuo.ai", "tc_test")
        args = argparse.Namespace(trigger="trig_abc", output="env", connect_token=token)

        with patch("hermes_tenuo._cloud.fire_trigger", return_value=fire_result):
            result = cmd_mint(args)

        assert result == 0
        out = capsys.readouterr().out
        assert f"TENUO_WARRANT={warrant_b64}" in out
