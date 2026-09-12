"""Local JSONL audit log: written by the guard, readable without Cloud."""

from __future__ import annotations

import argparse
import base64
import json
import os
from unittest.mock import patch

import pytest

from tests.test_config import FakeCtx  # noqa: F401  (fixtures below reuse its module)


@pytest.fixture
def keys_and_warrant():
    from tenuo import SigningKey, Subpath, Warrant, Wildcard
    root, agent = SigningKey.generate(), SigningKey.generate()
    w = (
        Warrant.mint_builder()
        .holder(agent.public_key)
        .capability("read_file", path=Subpath("/data"))
        .capability("web_search", query=Wildcard())
        .ttl(600)
        .mint(root)
    )
    return root, agent, w


class TestLocalAuditLog:

    def test_guard_writes_allow_and_deny_records(self, tmp_path, keys_and_warrant):
        from hermes_tenuo.audit import LocalAuditLog, read_audit_log
        from hermes_tenuo.hermes_guard import HermesGuard
        root, agent, w = keys_and_warrant
        log_path = tmp_path / "audit.jsonl"
        guard = HermesGuard(
            warrant=w, signing_key=agent, trusted_roots=[root.public_key],
            audit_callback=LocalAuditLog(log_path),
        )
        assert guard.pre_tool_call("read_file", {"path": "/data/q3.md"}, session_id="s1", tool_call_id="c1") is None
        guard.post_tool_call("read_file", {"path": "/data/q3.md"}, "ok", session_id="s1", tool_call_id="c1", duration_ms=12)
        denied = guard.pre_tool_call("read_file", {"path": "/etc/passwd"}, session_id="s1", tool_call_id="c2")
        assert denied and denied["action"] == "block"

        lines = [json.loads(l) for l in log_path.read_text().splitlines()]
        assert [l["decision"] for l in lines] == ["ALLOW", "ALLOW", "DENY"]

        records = read_audit_log(log_path)
        assert [r["tool_call_id"] for r in records] == ["c1", "c2"]
        assert records[0]["decision"] == "ALLOW" and records[0]["duration_ms"] == 12
        assert records[1]["decision"] == "DENY" and "path" in records[1]["reason"].lower()

    def test_read_filters_and_tolerates_junk(self, tmp_path):
        from hermes_tenuo.audit import read_audit_log
        p = tmp_path / "audit.jsonl"
        p.write_text(
            json.dumps({"decision": "ALLOW", "tool": "a", "tool_call_id": "1"}) + "\n"
            + "not json\n"
            + json.dumps({"decision": "DENY", "tool": "b", "tool_call_id": "2"}) + "\n"
            + json.dumps({"decision": "DENY", "tool": "c"}) + "\n"
        )
        assert [r["tool"] for r in read_audit_log(p)] == ["a", "b", "c"]
        assert [r["tool"] for r in read_audit_log(p, denied_only=True)] == ["b", "c"]
        assert [r["tool"] for r in read_audit_log(p, last=1)] == ["c"]
        assert read_audit_log(tmp_path / "missing.jsonl") == []

    def test_write_failure_never_raises(self, tmp_path):
        from hermes_tenuo.audit import LocalAuditLog
        from hermes_tenuo.hermes_guard import HermesAuditEvent
        blocked = tmp_path / "file"
        blocked.write_text("x")  # a file where a directory is needed
        sink = LocalAuditLog(blocked / "audit.jsonl")
        sink(HermesAuditEvent(tool="t", args={}, decision="ALLOW", reason=""))  # must not raise


class TestAuditConfig:

    def test_default_path_when_unset(self):
        from hermes_tenuo._config import get_audit_log_path
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={}):
            env = {k: v for k, v in os.environ.items() if k != "TENUO_AUDIT_LOG"}
            with patch.dict(os.environ, env, clear=True):
                path = get_audit_log_path(FakeCtx())
        assert path is not None and path.name == "audit.jsonl"

    @pytest.mark.parametrize("value", [False, "false", "off", "0"])
    def test_disabled(self, value):
        from hermes_tenuo._config import get_audit_log_path
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={"audit_log": value}):
            assert get_audit_log_path(FakeCtx()) is None

    def test_custom_path(self, tmp_path):
        from hermes_tenuo._config import get_audit_log_path
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={"audit_log": str(tmp_path / "a.jsonl")}):
            assert get_audit_log_path(FakeCtx()) == tmp_path / "a.jsonl"

    def test_build_plugin_guard_wires_audit_log(self, tmp_path, keys_and_warrant):
        from hermes_tenuo._guard import build_plugin_guard
        root, agent, w = keys_and_warrant
        log_path = tmp_path / "audit.jsonl"
        entry = {
            "warrant": base64.b64encode(w.to_bytes()).decode(),
            "trusted_root": base64.b64encode(root.public_key.to_bytes()).decode(),
            "audit_log": str(log_path),
        }
        with patch("hermes_tenuo._config._get_plugin_entry", return_value=entry):
            with patch.dict(os.environ, {"TENUO_SIGNING_KEY": base64.b64encode(agent.secret_key_bytes()).decode()}):
                guard = build_plugin_guard(FakeCtx())
        assert guard is not None
        guard._guard._primary_session_id = "s1"
        assert guard.pre_tool_call_hook("terminal", {"command": "ls"}, session_id="s1", tool_call_id="c9")["action"] == "block"
        rec = json.loads(log_path.read_text().splitlines()[-1])
        assert rec["decision"] == "DENY" and rec["tool"] == "terminal"


class TestAuditCli:

    def test_audit_command_prints_table_and_json(self, tmp_path, capsys):
        from hermes_tenuo.cli import cmd_audit
        p = tmp_path / "audit.jsonl"
        p.write_text(
            json.dumps({"timestamp": "2026-09-12T10:00:00+00:00", "decision": "ALLOW", "tool": "read_file",
                        "args": {"path": "/data/q3.md"}, "reason": "", "tool_call_id": "1"}) + "\n"
            + json.dumps({"timestamp": "2026-09-12T10:00:01+00:00", "decision": "DENY", "tool": "terminal",
                          "args": {"command": "ls"}, "reason": "warrant does not authorize tool 'terminal'",
                          "tool_call_id": "2"}) + "\n"
        )
        assert cmd_audit(argparse.Namespace(path=str(p), last=None, denied=False, json=False)) == 0
        out = capsys.readouterr().out
        assert "ALLOW  read_file  path=/data/q3.md" in out
        assert "DENY   terminal  command=ls  — warrant does not authorize tool 'terminal'" in out
        assert "2 calls, 1 denied" in out

        assert cmd_audit(argparse.Namespace(path=str(p), last=None, denied=True, json=True)) == 0
        out = capsys.readouterr().out.strip().splitlines()
        assert len(out) == 1 and json.loads(out[0])["tool"] == "terminal"

    def test_audit_command_empty(self, tmp_path, capsys):
        from hermes_tenuo.cli import cmd_audit
        assert cmd_audit(argparse.Namespace(path=str(tmp_path / "none.jsonl"), last=None, denied=False, json=False)) == 0
        assert "No audit records" in capsys.readouterr().out
