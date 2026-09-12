"""
Integration-level tests for hermes_tenuo._config and build_plugin_guard.

Covers the config → guard construction path that unit tests of HermesGuard alone
cannot reach, including trusted_roots loading, signing key loading, and the
guard being correctly wired up for real enforcement.
"""

import base64
import os
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def root_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def agent_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def basic_warrant(root_key, agent_key):
    from tenuo import Warrant, Wildcard, Subpath
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("web_search", query=Wildcard())
        .capability("read_file", path=Subpath("/data"))
        .ttl(3600)
        .mint(root_key)
    )


@pytest.fixture
def warrant_b64(basic_warrant):
    return base64.b64encode(basic_warrant.to_bytes()).decode()


@pytest.fixture
def agent_key_b64(agent_key):
    return base64.b64encode(agent_key.secret_key_bytes()).decode()


@pytest.fixture
def trusted_root_b64(root_key):
    return base64.b64encode(root_key.public_key.to_bytes()).decode()


class FakeCtx:
    """Minimal stand-in for Hermes PluginContext."""
    pass


# ---------------------------------------------------------------------------
# _config.py tests
# ---------------------------------------------------------------------------


class TestGetSigningKey:

    def test_loads_from_env_var(self, agent_key_b64):
        from hermes_tenuo._config import get_signing_key
        with patch.dict(os.environ, {"TENUO_SIGNING_KEY": agent_key_b64}):
            key = get_signing_key(FakeCtx())
        assert key is not None

    def test_returns_none_when_env_not_set(self):
        from hermes_tenuo._config import get_signing_key
        env = {k: v for k, v in os.environ.items() if k != "TENUO_SIGNING_KEY"}
        with patch.dict(os.environ, env, clear=True):
            key = get_signing_key(FakeCtx())
        assert key is None

    def test_custom_signing_key_env_name(self, agent_key_b64):
        from hermes_tenuo._config import get_signing_key
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={"signing_key_env": "MY_KEY"}):
            with patch.dict(os.environ, {"MY_KEY": agent_key_b64}):
                key = get_signing_key(FakeCtx())
        assert key is not None

    def test_returns_none_on_invalid_base64(self):
        from hermes_tenuo._config import get_signing_key
        with patch.dict(os.environ, {"TENUO_SIGNING_KEY": "not-valid-base64!!!"}):
            key = get_signing_key(FakeCtx())
        assert key is None


class TestGetTrustedRoots:

    def test_loads_from_env_var(self, trusted_root_b64):
        from hermes_tenuo._config import get_trusted_roots
        with patch.dict(os.environ, {"TENUO_TRUSTED_ROOT": trusted_root_b64}):
            roots = get_trusted_roots(FakeCtx())
        assert roots is not None
        assert len(roots) == 1

    def test_loads_multiple_comma_separated(self, trusted_root_b64):
        from hermes_tenuo._config import get_trusted_roots
        two_roots = f"{trusted_root_b64},{trusted_root_b64}"
        with patch.dict(os.environ, {"TENUO_TRUSTED_ROOT": two_roots}):
            roots = get_trusted_roots(FakeCtx())
        assert roots is not None
        assert len(roots) == 2

    def test_returns_none_when_not_set(self):
        from hermes_tenuo._config import get_trusted_roots
        env = {k: v for k, v in os.environ.items() if k != "TENUO_TRUSTED_ROOT"}
        with patch.dict(os.environ, env, clear=True):
            with patch("hermes_tenuo._config._get_plugin_entry", return_value={}):
                roots = get_trusted_roots(FakeCtx())
        assert roots is None

    def test_loads_from_config_entry(self, trusted_root_b64):
        from hermes_tenuo._config import get_trusted_roots
        env = {k: v for k, v in os.environ.items() if k != "TENUO_TRUSTED_ROOT"}
        with patch.dict(os.environ, env, clear=True):
            with patch("hermes_tenuo._config._get_plugin_entry", return_value={"trusted_root": trusted_root_b64}):
                roots = get_trusted_roots(FakeCtx())
        assert roots is not None
        assert len(roots) == 1


class TestEnvSecret:

    def test_falls_back_to_os_environ_without_secret_scope(self, monkeypatch):
        from hermes_tenuo._config import _env_secret
        monkeypatch.setenv("TENUO_WARRANT", "from-environ")
        import sys
        with patch.dict(sys.modules, {"agent": None, "agent.secret_scope": None}):
            assert _env_secret("TENUO_WARRANT") == "from-environ"

    def test_uses_get_secret_when_available(self):
        from hermes_tenuo._config import _env_secret

        class _Scope:
            UnscopedSecretError = RuntimeError

            @staticmethod
            def get_secret(name, default=None):
                return {"TENUO_SIGNING_KEY": "from-scope"}.get(name, default)

        import sys
        from types import ModuleType
        agent_mod = ModuleType("agent")
        scope_mod = ModuleType("agent.secret_scope")
        scope_mod.UnscopedSecretError = _Scope.UnscopedSecretError
        scope_mod.get_secret = _Scope.get_secret
        with patch.dict(sys.modules, {"agent": agent_mod, "agent.secret_scope": scope_mod}):
            assert _env_secret("TENUO_SIGNING_KEY") == "from-scope"

    def test_unscoped_multiplex_does_not_read_os_environ(self, monkeypatch):
        from hermes_tenuo._config import _env_secret
        monkeypatch.setenv("TENUO_SIGNING_KEY", "launch-profile-token")

        class UnscopedSecretError(RuntimeError):
            pass

        def _raise(name, default=None):
            raise UnscopedSecretError(name)

        import sys
        from types import ModuleType
        agent_mod = ModuleType("agent")
        scope_mod = ModuleType("agent.secret_scope")
        scope_mod.UnscopedSecretError = UnscopedSecretError
        scope_mod.get_secret = _raise
        with patch.dict(sys.modules, {"agent": agent_mod, "agent.secret_scope": scope_mod}):
            assert _env_secret("TENUO_SIGNING_KEY") is None


class TestLoadWarrant:

    def test_loads_valid_warrant(self, warrant_b64):
        from hermes_tenuo._config import load_warrant
        w = load_warrant(warrant_b64)
        assert w is not None

    def test_returns_none_for_none(self):
        from hermes_tenuo._config import load_warrant
        assert load_warrant(None) is None

    def test_returns_none_for_invalid_data(self):
        from hermes_tenuo._config import load_warrant
        assert load_warrant("notvalidbase64!!!") is None


class TestGetRequireSessionWarrant:

    def test_auto_when_unset(self):
        from hermes_tenuo._config import get_require_session_warrant
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={}):
            assert get_require_session_warrant(FakeCtx()) is None

    def test_true_from_config(self):
        from hermes_tenuo._config import get_require_session_warrant
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={"require_session_warrant": True}):
            assert get_require_session_warrant(FakeCtx()) is True

    def test_false_from_env(self):
        from hermes_tenuo._config import get_require_session_warrant
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={}):
            with patch.dict(os.environ, {"TENUO_REQUIRE_SESSION_WARRANT": "false"}):
                assert get_require_session_warrant(FakeCtx()) is False


# ---------------------------------------------------------------------------
# build_plugin_guard integration tests
# ---------------------------------------------------------------------------


class TestBuildPluginGuard:

    def test_returns_none_when_no_warrant(self):
        from hermes_tenuo._guard import build_plugin_guard
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={}):
            env = {k: v for k, v in os.environ.items()
                   if k != "TENUO_WARRANT"}
            with patch.dict(os.environ, env, clear=True):
                guard = build_plugin_guard(FakeCtx())
        assert guard is None

    def test_builds_guard_when_warrant_configured(
        self, warrant_b64, agent_key_b64, trusted_root_b64
    ):
        from hermes_tenuo._guard import build_plugin_guard
        entry = {
            "warrant": warrant_b64,
            "trusted_root": trusted_root_b64,
        }
        with patch("hermes_tenuo._config._get_plugin_entry", return_value=entry):
            with patch.dict(os.environ, {"TENUO_SIGNING_KEY": agent_key_b64}):
                guard = build_plugin_guard(FakeCtx())
        assert guard is not None
        assert guard.has_warrant

    def test_built_guard_enforces_correctly(
        self, warrant_b64, agent_key_b64, trusted_root_b64
    ):
        from hermes_tenuo._guard import build_plugin_guard
        entry = {
            "warrant": warrant_b64,
            "trusted_root": trusted_root_b64,
        }
        with patch("hermes_tenuo._config._get_plugin_entry", return_value=entry):
            with patch.dict(os.environ, {"TENUO_SIGNING_KEY": agent_key_b64}):
                guard = build_plugin_guard(FakeCtx())

        guard._guard._primary_session_id = "s1"

        # Authorized
        assert guard.pre_tool_call_hook("web_search", {"query": "test"}, session_id="s1") is None
        assert guard.pre_tool_call_hook("read_file", {"path": "/data/x"}, session_id="s1") is None

        # Blocked
        result = guard.pre_tool_call_hook("terminal", {"command": "ls"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"

    def test_builds_without_optional_control_plane_connect(
        self, warrant_b64, agent_key_b64, trusted_root_b64
    ):
        from hermes_tenuo._guard import build_plugin_guard
        entry = {"warrant": warrant_b64, "trusted_root": trusted_root_b64}
        with patch("hermes_tenuo._config._get_plugin_entry", return_value=entry):
            with patch.dict(os.environ, {"TENUO_SIGNING_KEY": agent_key_b64}):
                guard = build_plugin_guard(FakeCtx())
        assert guard is not None


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestMintCLI:

    def test_mint_outputs_config(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        import argparse
        args = argparse.Namespace(ttl="1h", allow=["web_search"], output="full")
        result = cmd_mint(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "warrant:" in out
        assert "trusted_root:" in out
        assert "TENUO_SIGNING_KEY" in out

    def test_mint_env_output(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        import argparse
        args = argparse.Namespace(ttl="30m", allow=["terminal"], output="env")
        cmd_mint(args)
        out = capsys.readouterr().out
        assert "export TENUO_WARRANT=" in out
        assert "export TENUO_SIGNING_KEY=" in out
        assert "export TENUO_TRUSTED_ROOT=" in out

    def test_mint_with_multiple_tools(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        import argparse
        args = argparse.Namespace(ttl="1h", allow=["read_file", "web_search"], output="env")
        result = cmd_mint(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "export TENUO_WARRANT=" in out

    def test_parse_ttl(self):
        from hermes_tenuo.cli import _parse_ttl
        assert _parse_ttl("1h") == 3600
        assert _parse_ttl("30m") == 1800
        assert _parse_ttl("7d") == 604800
        assert _parse_ttl("90s") == 90
        with pytest.raises(ValueError):
            _parse_ttl("abc")
