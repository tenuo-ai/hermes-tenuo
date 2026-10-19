"""Refusals of an attached warrant are judged, and receipted, by the runtime's authorizer."""
import json
import time

import pytest

from tenuo import WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.files import update_revocations
from tenuo.local_cli.sessions import attach
from tenuo.local_cli.workspace import Workspace
from hermes_tenuo.local_guard import SharedLocalGuard

ARGS = {"order_id": "A-1001"}


@pytest.fixture
def workspace(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    return workspace


def mint(workspace, ttl="30m"):
    template = {"version": 2, "ttl": ttl, "capabilities": {"get_order": {"order_id": "A-1001"}}}
    return WarrantTemplate(template).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))


def receipts(workspace, capsys):
    path = workspace.path / workspace.config["audit"]["receipts"]
    if not path.exists() or not path.read_text().strip():
        return []
    capsys.readouterr()
    assert main(["--home", str(workspace.path), "--json", "audit", "list"]) == 0
    return [(r["decision"], r["warrant_id"], r["reason"]) for r in json.loads(capsys.readouterr().out)["decisions"]]


def test_revoked_attachment_is_receipted(workspace, capsys):
    warrant = mint(workspace)
    attach(workspace, "chat-a", [warrant])
    guard = SharedLocalGuard(workspace.path)
    update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [warrant.id])
    assert "revoked" in guard.pre_tool_call("get_order", ARGS, session_id="chat-a")["message"]
    assert receipts(workspace, capsys) == [("DENY", str(warrant.id), "warrant-revoked")]


def test_expired_attachment_is_receipted(workspace, capsys):
    warrant = mint(workspace, ttl="1s")
    attach(workspace, "chat-a", [warrant])
    guard = SharedLocalGuard(workspace.path)
    time.sleep(2.1)
    assert "expired" in guard.pre_tool_call("get_order", ARGS, session_id="chat-a")["message"]
    assert receipts(workspace, capsys) == [("DENY", str(warrant.id), "warrant-expired")]


def test_unattached_session_is_audited_without_a_receipt(workspace, capsys):
    events = []
    guard = SharedLocalGuard(workspace.path, audit_callback=events.append)
    assert guard.pre_tool_call("get_order", ARGS, session_id="nobody")["action"] == "block"
    # No warrant was presented, so the authorizer judged nothing and there is no receipt.
    assert receipts(workspace, capsys) == []
    assert [(e.decision, e.session_id) for e in events] == [("DENY", "nobody")]


def test_constraint_denial_is_receipted_once(workspace, capsys):
    warrant = mint(workspace)
    attach(workspace, "chat-a", [warrant])
    guard = SharedLocalGuard(workspace.path)
    assert guard.pre_tool_call("get_order", {"order_id": "OTHER"}, session_id="chat-a")["action"] == "block"
    assert receipts(workspace, capsys) == [("DENY", str(warrant.id), "constraint-violation")]
