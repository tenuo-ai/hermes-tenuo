"""
Tests for the hermes-tenuo CLI — primarily `init`, since `mint` paths are
covered indirectly via test_cloud.py.
"""

from __future__ import annotations

import argparse
import base64
import os
import stat
import sys
from pathlib import Path

import pytest


def _run_init(**kwargs) -> int:
    """Invoke cmd_init with a Namespace built from kwargs."""
    from hermes_tenuo.cli import cmd_init
    defaults = dict(dir=None, allow=None, ttl="24h", force=False, yes=False)
    defaults.update(kwargs)
    return cmd_init(argparse.Namespace(**defaults))


class TestInitHappyPath:

    def test_creates_keys_warrant_in_dir(self, tmp_path, capsys):
        target = tmp_path / "tenuo"
        rc = _run_init(
            dir=str(target),
            allow=["web_search", "read_file:path=/data"],
            ttl="1h",
            yes=True,
        )
        assert rc == 0
        assert (target / "control.key").exists()
        assert (target / "agent.key").exists()
        assert (target / "warrant").exists()

    def test_keys_are_loadable_and_round_trip(self, tmp_path):
        """The persisted keys + warrant must produce working enforcement."""
        from tenuo import SigningKey
        from tenuo_core import Warrant
        from hermes_tenuo.hermes_guard import HermesGuard

        target = tmp_path / "tenuo"
        _run_init(
            dir=str(target),
            allow=["web_search", "read_file:path=/data"],
            ttl="1h",
            yes=True,
        )

        agent_key = SigningKey.from_bytes(
            base64.b64decode((target / "agent.key").read_text().strip())
        )
        control_key = SigningKey.from_bytes(
            base64.b64decode((target / "control.key").read_text().strip())
        )
        warrant = Warrant.from_bytes(
            base64.b64decode((target / "warrant").read_text().strip())
        )

        guard = HermesGuard(
            warrant=warrant,
            signing_key=agent_key,
            trusted_roots=[control_key.public_key],
        )
        guard._primary_session_id = "s1"

        # Allowed
        assert guard.pre_tool_call("web_search", {"query": "x"}, session_id="s1") is None
        assert guard.pre_tool_call("read_file", {"path": "/data/x"}, session_id="s1") is None
        # Path constraint enforced
        r = guard.pre_tool_call("read_file", {"path": "/etc/passwd"}, session_id="s1")
        assert r is not None and r["action"] == "block"
        # Tool not in warrant
        r = guard.pre_tool_call("terminal", {"command": "ls"}, session_id="s1")
        assert r is not None and r["action"] == "block"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_secret_files_are_chmod_600(self, tmp_path):
        target = tmp_path / "tenuo"
        _run_init(
            dir=str(target),
            allow=["web_search"],
            ttl="1h",
            yes=True,
        )
        for name in ("control.key", "agent.key"):
            mode = stat.S_IMODE(os.stat(target / name).st_mode)
            assert mode == 0o600, f"{name} has mode {oct(mode)}"

    def test_prints_config_block_with_paths_and_pubkey(self, tmp_path, capsys):
        target = tmp_path / "tenuo"
        _run_init(
            dir=str(target),
            allow=["web_search"],
            ttl="1h",
            yes=True,
        )
        out = capsys.readouterr().out
        assert "hermes-tenuo:" in out
        assert str(target / "warrant") in out
        assert "trusted_root:" in out
        assert "signing_key_env: TENUO_SIGNING_KEY" in out
        assert "export TENUO_SIGNING_KEY=" in out


class TestInitGuards:

    def test_yes_without_allow_errors(self, tmp_path, capsys):
        rc = _run_init(dir=str(tmp_path / "x"), yes=True)
        assert rc == 1
        err = capsys.readouterr().err
        assert "--yes requires" in err

    def test_refuses_to_overwrite_without_force(self, tmp_path, capsys):
        target = tmp_path / "tenuo"
        _run_init(dir=str(target), allow=["web_search"], yes=True)
        rc = _run_init(dir=str(target), allow=["web_search"], yes=True)
        assert rc == 1
        err = capsys.readouterr().err
        assert "already contains" in err

    def test_force_overwrites(self, tmp_path):
        target = tmp_path / "tenuo"
        _run_init(dir=str(target), allow=["web_search"], yes=True)
        first_warrant = (target / "warrant").read_text()
        rc = _run_init(dir=str(target), allow=["web_search"], yes=True, force=True)
        assert rc == 0
        # New keys → new warrant signature, so contents differ
        assert (target / "warrant").read_text() != first_warrant
