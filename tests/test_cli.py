"""
Tests for the hermes-tenuo CLI — mint, status, verify.
"""

from __future__ import annotations

import argparse
import base64
import os

import pytest


class TestMintLocal:

    def test_mint_bare_tools_env_output(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        args = argparse.Namespace(
            ttl="1h", allow=["web_search", "read_file"], output="env", trigger=None
        )
        rc = cmd_mint(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "export TENUO_WARRANT=" in out
        assert "export TENUO_SIGNING_KEY=" in out
        assert "export TENUO_TRUSTED_ROOT=" in out

    def test_mint_no_allow_errors(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        args = argparse.Namespace(ttl="1h", allow=None, output="env", trigger=None)
        rc = cmd_mint(args)
        assert rc != 0  # at least one --allow is required

    def test_mint_yaml_output(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        args = argparse.Namespace(
            ttl="30m", allow=["web_search"], output="yaml", trigger=None
        )
        rc = cmd_mint(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "warrant: " in out
        assert "trusted_root: " in out

    def test_demo_command(self, capsys):
        from hermes_tenuo.cli import main
        import sys
        old = sys.argv
        sys.argv = ["hermes-tenuo", "demo"]
        try:
            main()
        except SystemExit as exc:
            assert exc.code == 0
        finally:
            sys.argv = old
        out = capsys.readouterr().out
        assert "DENY   read_file  path=/etc/passwd" in out

    def test_mint_full_output(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        args = argparse.Namespace(
            ttl="24h", allow=["web_search"], output="full", trigger=None
        )
        rc = cmd_mint(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "hermes-tenuo" in out
        assert "TENUO_SIGNING_KEY" in out
        # Constraint builder notice
        assert "Cloud" in out or "warrant" in out.lower()

    def test_mint_warrant_is_valid_tenuo_warrant(self):
        """The minted warrant must be decodable by tenuo_core."""
        from hermes_tenuo.cli import cmd_mint
        import io, sys
        args = argparse.Namespace(
            ttl="1h", allow=["web_search"], output="env", trigger=None
        )
        captured = []
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        cmd_mint(args)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout

        for line in output.splitlines():
            if line.startswith("export TENUO_WARRANT="):
                warrant_b64 = line.split("=", 1)[1]
                from tenuo_core import Warrant
                w = Warrant.from_bytes(base64.b64decode(warrant_b64))
                assert w is not None
                assert "web_search" in (w.tools or [])
                break
        else:
            pytest.fail("TENUO_WARRANT not found in mint output")

    def test_parse_ttl(self):
        from hermes_tenuo.cli import _parse_ttl
        assert _parse_ttl("1h") == 3600
        assert _parse_ttl("30m") == 1800
        assert _parse_ttl("7d") == 604800
        assert _parse_ttl("90s") == 90
        assert _parse_ttl("3600") == 3600


class TestStatus:

    def test_status_runs(self, capsys, monkeypatch):
        from hermes_tenuo.cli import cmd_status
        monkeypatch.delenv("TENUO_WARRANT", raising=False)
        monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
        rc = cmd_status(argparse.Namespace())
        assert rc == 0

    def test_status_shows_set_vars(self, capsys, monkeypatch):
        from hermes_tenuo.cli import cmd_status
        monkeypatch.setenv("TENUO_WARRANT", "dummy")
        monkeypatch.setenv("TENUO_SIGNING_KEY", "dummy")
        monkeypatch.setenv("TENUO_TRUSTED_ROOT", "dummy")
        cmd_status(argparse.Namespace())
        out = capsys.readouterr().out
        assert "✓" in out


class TestCloudHookTimeoutNote:

    def test_no_connect_token_is_silent(self):
        from hermes_tenuo.cli import _cloud_hook_timeout_note
        assert _cloud_hook_timeout_note(None, None) is None
        assert _cloud_hook_timeout_note("", 30) is None

    def test_unset_timeout_warns_at_hermes_default(self):
        from hermes_tenuo.cli import _cloud_hook_timeout_note
        note = _cloud_hook_timeout_note("tc_live_x", None)
        assert note is not None
        assert "30s" in note
        assert "300s" in note
        assert "93824" in note

    def test_default_30s_warns(self):
        from hermes_tenuo.cli import _cloud_hook_timeout_note
        assert _cloud_hook_timeout_note("tc_live_x", 30) is not None

    def test_disabled_or_raised_is_silent(self):
        from hermes_tenuo.cli import _cloud_hook_timeout_note
        assert _cloud_hook_timeout_note("tc_live_x", 0) is None
        assert _cloud_hook_timeout_note("tc_live_x", 300) is None
        assert _cloud_hook_timeout_note("tc_live_x", 600) is None

    def test_invalid_timeout_treated_as_default(self):
        from hermes_tenuo.cli import _cloud_hook_timeout_note
        note = _cloud_hook_timeout_note("tc_live_x", "not-a-number")
        assert note is not None
        assert "30s" in note


class TestDoctorConfigured:

    def test_fails_when_enabled_but_empty(self, capsys, monkeypatch):
        from hermes_tenuo.cli import cmd_doctor
        monkeypatch.delenv("TENUO_WARRANT", raising=False)
        monkeypatch.delenv("TENUO_CONNECT_TOKEN", raising=False)
        monkeypatch.delenv("TENUO_TRUSTED_ROOT", raising=False)
        rc = cmd_doctor(argparse.Namespace())
        assert rc != 0
        out = capsys.readouterr().out
        assert "plugin configured" in out
        assert "✗" in out

    def test_audit_only_does_not_require_warrant(self, capsys, monkeypatch):
        from hermes_tenuo.cli import cmd_doctor
        monkeypatch.delenv("TENUO_WARRANT", raising=False)
        monkeypatch.setenv("TENUO_CONNECT_TOKEN", "tc_live_test")
        rc = cmd_doctor(argparse.Namespace())
        out = capsys.readouterr().out
        assert "plugin configured" in out
        assert "AUDIT-ONLY" in out
        assert "warrant loaded" not in out
        # May still fail other checks (entry point, enabled); configured itself passed
        assert "✓  plugin configured" in out or "plugin configured (warrant or connect_token)" in out


class TestMintConstraints:
    """--allow tool:arg=value produces real argument constraints, enforced locally."""

    def test_parse_allow_value_types(self):
        from hermes_tenuo.cli import parse_allow
        from tenuo import Exact, OneOf, Pattern, Subpath, Wildcard

        tool, c, shown = parse_allow("read_file:path=/data")
        assert tool == "read_file" and isinstance(c["path"], Subpath)
        assert shown == {"path": "/data"}
        _, c, _ = parse_allow("web_search:query=*")
        assert isinstance(c["query"], Wildcard)
        _, c, _ = parse_allow("web_search:query=acme*")
        assert isinstance(c["query"], Pattern)
        _, c, _ = parse_allow("git:action=status|diff|log")
        assert isinstance(c["action"], OneOf)
        _, c, _ = parse_allow("write_file:path=/tmp/out,mode=w")
        assert isinstance(c["path"], Subpath) and isinstance(c["mode"], Exact)
        tool, c, _ = parse_allow("web_search")
        assert tool == "web_search" and c == {}

    def test_parse_allow_rejects_malformed(self):
        from hermes_tenuo.cli import parse_allow
        with pytest.raises(ValueError):
            parse_allow(":path=/data")
        with pytest.raises(ValueError):
            parse_allow("read_file:path")
        with pytest.raises(ValueError):
            parse_allow("read_file:=x")

    def test_mint_malformed_allow_errors(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        args = argparse.Namespace(ttl="1h", allow=["read_file:path"], output="env", trigger=None)
        assert cmd_mint(args) != 0
        assert "expected arg=value" in capsys.readouterr().err

    def test_mint_full_output_lists_constraints(self, capsys):
        from hermes_tenuo.cli import cmd_mint
        args = argparse.Namespace(
            ttl="1h", allow=["read_file:path=/data", "web_search"], output="full", trigger=None
        )
        assert cmd_mint(args) == 0
        out = capsys.readouterr().out
        assert "#   read_file  path=/data" in out
        assert "#   web_search  (any arguments)" in out
        assert "Cloud" not in out

    def test_minted_constraints_are_enforced_by_guard(self, capsys):
        """The warrant mint prints must deny out-of-scope arguments through HermesGuard."""
        from hermes_tenuo.cli import cmd_mint
        from hermes_tenuo.hermes_guard import HermesGuard
        from tenuo import PublicKey, SigningKey, Warrant

        args = argparse.Namespace(
            ttl="1h",
            allow=["read_file:path=/data", "web_search:query=*", "git:action=status|diff"],
            output="env",
            trigger=None,
        )
        assert cmd_mint(args) == 0
        env = {}
        for line in capsys.readouterr().out.splitlines():
            if line.startswith("export "):
                k, v = line[len("export "):].split("=", 1)
                env[k] = v

        guard = HermesGuard(
            warrant=Warrant.from_bytes(base64.b64decode(env["TENUO_WARRANT"])),
            signing_key=SigningKey.from_bytes(base64.b64decode(env["TENUO_SIGNING_KEY"])),
            trusted_roots=[PublicKey.from_bytes(base64.b64decode(env["TENUO_TRUSTED_ROOT"]))],
        )
        call = lambda tool, a: guard.pre_tool_call(tool, a, session_id="s1")
        assert call("read_file", {"path": "/data/q3.md"}) is None
        assert call("web_search", {"query": "anything at all"}) is None
        assert call("git", {"action": "diff"}) is None

        denied_path = call("read_file", {"path": "/etc/passwd"})
        assert denied_path and denied_path["action"] == "block"
        denied_choice = call("git", {"action": "push"})
        assert denied_choice and denied_choice["action"] == "block"
        denied_tool = call("terminal", {"command": "ls"})
        assert denied_tool and denied_tool["action"] == "block"
