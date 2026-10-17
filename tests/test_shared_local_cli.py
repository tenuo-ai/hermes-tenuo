"""The plugin consumes the SDK's common format without its own parser or signer."""
import pytest

from tenuo import SigningKey, WarrantTemplate
from tenuo.local_cli.approvals import sign_response
from tenuo.local_cli.files import load_yaml, update_revocations, write_yaml
from tenuo.local_cli.sessions import attach
from tenuo.local_cli.workspace import Workspace
from hermes_tenuo.local_guard import SharedLocalGuard


@pytest.fixture
def local(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    template = {"version": 2, "ttl": "30m", "capabilities": {
        "get_order": {"order_id": "A-1001"}}}
    warrant = WarrantTemplate(template).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    return workspace, template, warrant


def test_missing_attachment_reports_session_and_turn_end_preserves_it(local):
    workspace, _, warrant = local
    guard = SharedLocalGuard(workspace.path)
    args = {"order_id": "A-1001"}
    assert "chat-a" in guard.pre_tool_call("get_order", args, session_id="chat-a")["message"]
    attach(workspace, "chat-a", [warrant])
    assert guard.pre_tool_call("get_order", args, session_id="chat-a") is None
    guard.on_session_end("chat-a")
    assert guard.pre_tool_call("get_order", args, session_id="chat-a") is None
    assert guard.pre_tool_call("get_order", args, session_id="chat-b")["action"] == "block"
    assert guard.pre_tool_call("terminal", {"command": "anything"}, session_id="chat-a")["action"] == "block"


def test_argument_denial_and_live_revocation(local):
    workspace, _, warrant = local
    attach(workspace, "chat-a", [warrant])
    guard = SharedLocalGuard(workspace.path)
    assert guard.pre_tool_call("get_order", {"order_id": "OTHER"}, session_id="chat-a")["action"] == "block"
    assert guard.pre_tool_call("get_order", {"order_id": "A-1001"}, session_id="chat-a") is None
    update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [warrant.id])
    assert "revoked" in guard.pre_tool_call("get_order", {"order_id": "A-1001"}, session_id="chat-a")["message"]


def test_full_chain_and_file_approvals_use_only_shared_sdk(local):
    workspace, template, root = local
    template["approvals"] = {"keys": [str(workspace.path / "keys/approver.pub")], "required": {"get_order": "always"}}
    gated = WarrantTemplate(template).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    attach(workspace, "chat-a", [gated])
    guard = SharedLocalGuard(workspace.path)
    args = {"order_id": "A-1001"}
    pending = guard.pre_tool_call("get_order", args, session_id="chat-a")
    assert pending["code"] == "operation_approval_required"
    path = next((workspace.path / "requests").glob("*.yaml"))
    request = load_yaml(path)
    response = sign_response(request, workspace.authorizer(), workspace.signing_key("approver"))
    write_yaml(workspace.path / "approvals" / path.name, response)
    assert guard.pre_tool_call("get_order", args, session_id="chat-a") is None
    child = root.grant_builder().capability("get_order", **root.capabilities["get_order"]).holder(
        workspace.public_key("agent")).ttl(600).grant(workspace.signing_key("agent"))
    attach(workspace, "chat-b", [root, child])
    assert guard.pre_tool_call("get_order", args, session_id="chat-b") is None


def test_corrupt_grant_does_not_hide_independent_valid_grant(local):
    workspace, _, warrant = local
    other = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {
        "get_order": {"order_id": "OTHER"}}}).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    attach(workspace, "chat-a", [other])
    attach(workspace, "chat-a", [warrant])
    (workspace.path / "warrants" / (other.id + ".warrant")).write_text("broken")
    guard = SharedLocalGuard(workspace.path)
    assert guard.pre_tool_call("get_order", {"order_id": "A-1001"}, session_id="chat-a") is None
    (workspace.path / "revocations.srl").unlink()
    assert guard.pre_tool_call("get_order", {"order_id": "A-1001"}, session_id="chat-a")["action"] == "block"


def test_new_mode_does_not_use_legacy_identity_mutators(local):
    workspace, _, warrant = local
    guard = SharedLocalGuard(workspace.path)
    with pytest.raises(ValueError, match="session attach"):
        guard.set_session_warrant("chat-a", warrant)
    with pytest.raises(ValueError, match="trust"):
        guard.set_trusted_roots([SigningKey.generate().public_key])


def test_legacy_public_reader_rejects_private_file_and_symlink(local):
    from hermes_tenuo.issuance import read_public_key

    workspace, _, _ = local
    private = workspace.path / "keys/issuer.key"
    alias = workspace.path / "keys/pretend.pub"
    alias.symlink_to(private)
    for path in (private, alias):
        with pytest.raises(ValueError):
            read_public_key(path)


def test_shared_doctor_checks_attachments_not_just_plugin_loading(local, monkeypatch):
    from hermes_tenuo import _config
    from hermes_tenuo.session_diagnostics import report_dynamic_config

    workspace, _, warrant = local
    monkeypatch.setattr(_config, "_get_plugin_entry", lambda ctx: {"local_home": str(workspace.path)})
    assert report_dynamic_config() is False
    attach(workspace, "chat-a", [warrant])
    assert report_dynamic_config() is True
