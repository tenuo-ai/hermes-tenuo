"""Public-recipient issuance, immutable review and model request boundaries."""
import argparse
import base64
import json
from pathlib import Path

import pytest
from tenuo import SigningKey, Warrant

from hermes_tenuo.authority_requests import (
    approve_request, cmd_approve, load_request, new_request, save_request,
)
from hermes_tenuo.request_tools import register_request_tool


def sample(holder):
    return new_request(holder.public_key, "session-a", {"read_file": {"path": {"subpath": "/data/reports"}}},
                       "20m", "Read a report")


def test_issuer_signs_public_recipient_snapshot_without_holder_secret(tmp_path, monkeypatch):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    path, output = tmp_path / "request.json", tmp_path / "approved.warrant"
    original = sample(holder)
    save_request(path, original)
    reviewed = load_request(path)
    edited = {**original, "capabilities": {"terminal": {}}}
    path.write_text(json.dumps(edited))
    monkeypatch.setenv("TENUO_SIGNING_KEY", "invalid-unrelated-secret")
    approved = approve_request(reviewed, issuer, output)
    assert approved.verify(issuer.public_key.to_bytes())
    assert approved.authorized_holder.to_bytes() == holder.public_key.to_bytes()
    assert approved.session_id == "session-a"
    assert set(approved.capabilities) == {"read_file"}
    assert Warrant.from_bytes(base64.b64decode(output.read_text())).id == approved.id
    with pytest.raises(FileExistsError):
        approve_request(reviewed, issuer, output)


def test_request_rejects_paths_duplicates_and_unknown_fields(tmp_path):
    path = tmp_path / "request.json"
    request = sample(SigningKey.generate())
    path.write_text(json.dumps({**request, "output_path": "/unexpected"}))
    with pytest.raises(ValueError, match="exactly"):
        load_request(path)
    path.write_text('{"version":1,"version":1}')
    with pytest.raises(ValueError, match="duplicate"):
        load_request(path)
    path.write_bytes(b"x" * 65537)
    with pytest.raises(ValueError, match="64 KiB"):
        load_request(path)


def test_declining_approval_never_loads_signer(tmp_path, monkeypatch):
    request = tmp_path / "request.json"
    save_request(request, sample(SigningKey.generate()))
    monkeypatch.setattr("builtins.input", lambda _: "no")
    args = argparse.Namespace(request=str(request), issuer_key="does-not-exist", out=None,
                              yes=False, attach=False, directory=None)
    assert cmd_approve(args) == 1
    assert not request.with_suffix(".warrant").exists()


def test_runtime_request_uses_dispatcher_session_not_model_arguments(tmp_path, monkeypatch):
    holder = SigningKey.generate()
    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry", lambda _: {
        "requests_dir": str(tmp_path / "requests"), "session_warrants_dir": str(tmp_path / "sessions")})
    monkeypatch.setattr("hermes_tenuo._config.get_signing_key", lambda _: holder)

    class Context:
        def register_tool(self, **tool):
            self.handler = tool["handler"]

    ctx = Context()
    assert register_request_tool(ctx)
    args = {"allow": ["read_file:path=/data/reports"], "ttl": "20m", "description": "Read a report"}
    bad = json.loads(ctx.handler({**args, "session_id": "session-b"}, session_id="session-a"))
    assert "error" in bad
    result = json.loads(ctx.handler(args, session_id="session-a"))
    request = load_request(result["request"])
    assert request["session_id"] == "session-a"
    assert request["holder_public_key"] == base64.b64encode(holder.public_key.to_bytes()).decode()
    assert not list(tmp_path.rglob("*.warrant"))
    no_context = json.loads(ctx.handler(args))
    assert "error" in no_context
    assert Path(result["request"]).stat().st_mode & 0o777 == 0o600


def test_approve_attaches_reviewed_snapshot_and_session_guard_loads_live(tmp_path, monkeypatch):
    from hermes_tenuo.session_guard import SessionGuard
    from hermes_tenuo.session_store import read_session
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    issuer_file = tmp_path / "issuer.key"
    issuer_file.write_text(base64.b64encode(issuer.secret_key_bytes()).decode())
    request_file = tmp_path / "request.json"
    save_request(request_file, sample(holder))
    directory = tmp_path / "sessions"
    guard = SessionGuard(directory, signing_key=holder, trusted_roots=[issuer.public_key])
    assert guard.pre_tool_call("read_file", {"path": "/data/reports/q1.txt"}, session_id="session-a")
    args = argparse.Namespace(request=str(request_file), issuer_key=str(issuer_file), out=None,
                              yes=True, attach=True, directory=str(directory))
    # The writable output file can change after signing. Attachment must use memory.
    import hermes_tenuo.authority_requests as requests
    original = requests.approve_request
    def substituted_file(snapshot, issuer, output):
        warrant = original(snapshot, issuer, output)
        Path(output).write_text("invalid replacement")
        return warrant
    monkeypatch.setattr(requests, "approve_request", substituted_file)
    assert cmd_approve(args) == 0
    assert len(read_session("session-a", directory)) == 1
    assert guard.pre_tool_call("read_file", {"path": "/data/reports/q1.txt"}, session_id="session-a") is None
    assert guard.pre_tool_call("read_file", {"path": "/private/secret"}, session_id="session-a")["action"] == "block"
    assert guard.pre_tool_call("read_file", {"path": "/data/reports/q1.txt"}, session_id="session-b")["action"] == "block"


def test_plugin_control_tool_available_before_any_infrastructure_grant(tmp_path, monkeypatch):
    import sys
    from types import ModuleType, SimpleNamespace
    import hermes_tenuo
    holder, issuer = SigningKey.generate(), SigningKey.generate()
    monkeypatch.setattr("hermes_tenuo._config._get_plugin_entry", lambda _: {
        "requests_dir": str(tmp_path / "requests"), "session_warrants_dir": str(tmp_path / "sessions")})
    monkeypatch.setattr("hermes_tenuo._config.get_signing_key", lambda _: holder)
    monkeypatch.setattr("hermes_tenuo._config.get_trusted_roots", lambda _: [issuer.public_key])
    registry = ModuleType("tools.registry")
    registry.registry = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "tools.registry", registry)
    class Context:
        def __init__(self):
            self.hooks = {}
            self.tools = {}
        def register_hook(self, name, hook):
            self.hooks[name] = hook
        def register_tool(self, **tool):
            self.tools[tool["name"]] = tool["handler"]
    ctx = Context()
    hermes_tenuo.register(ctx)
    pre = ctx.hooks["pre_tool_call"]
    assert pre(tool_name="read_file", args={"path": "/data/reports/q1.txt"}, session_id="session-a")["action"] == "block"
    assert pre(tool_name="tenuo_request_authority", args={}, session_id="session-a") is None
    result = json.loads(ctx.tools["tenuo_request_authority"]({"allow": ["read_file:path=/data/reports"],
        "ttl": "20m", "description": "Read a report"}, session_id="session-a"))
    assert result["status"] == "pending_external_approval"
    assert pre(tool_name="read_file", args={"path": "/data/reports/q1.txt"}, session_id="session-a")["action"] == "block"


@pytest.mark.parametrize("duration", ["inf", "1e999h", "nan", "-5m"])
def test_invalid_request_duration_does_not_create_file(tmp_path, duration):
    request = sample(SigningKey.generate())
    request["ttl"] = duration
    with pytest.raises(ValueError):
        save_request(tmp_path / "invalid.json", request)
    assert not (tmp_path / "invalid.json").exists()
