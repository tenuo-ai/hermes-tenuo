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
