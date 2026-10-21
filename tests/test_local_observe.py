"""local_home in observe mode: nothing is blocked and every call is recorded for drafting a warrant."""
import json

import pytest

from tenuo import WarrantTemplate
from tenuo.local_cli.sessions import attach
from tenuo.local_cli.workspace import Workspace

from hermes_tenuo.local_guard import SharedLocalGuard, report_shared_local_config

ORDERS = {"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "A-1001"}}}


@pytest.fixture
def observing(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    return workspace


def recorded(workspace):
    path = workspace.path / "observations.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def mint(workspace, template=ORDERS):
    return WarrantTemplate(template).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))


def test_observe_without_attachments_runs_and_records_under_the_session(observing):
    events = []
    guard = SharedLocalGuard(observing.path, audit_callback=events.append)
    assert guard.pre_tool_call("terminal", {"command": "ls"}, session_id="chat-a", tool_call_id="t1") is None
    line = recorded(observing)[0]
    assert (line["run"], line["step"], line["tool"], line["args"]) == ("chat-a", "hermes", "terminal", {"command": "ls"})
    assert (line["decision"], line["reason"], line["warrant_id"]) == (None, "no_warrant", None)
    assert events[0].decision == "ALLOW" and events[0].reason.startswith("observe: would deny")


def test_observe_with_an_attachment_records_what_enforcement_would_decide(observing):
    warrant = mint(observing)
    attach(observing, "chat-a", [warrant])
    guard = SharedLocalGuard(observing.path, step="support")
    for order in ("A-1001", "OTHER"):
        assert guard.pre_tool_call("get_order", {"order_id": order}, session_id="chat-a") is None
    lines = recorded(observing)
    assert [(line["decision"], line["warrant_id"], line["step"]) for line in lines] == [
        ("allow", str(warrant.id), "support"),
        ("deny", str(warrant.id), "support"),
    ]
    assert lines[1]["reason"]
    assert not (observing.path / "receipts.jsonl").read_text().strip()


def test_observe_records_approval_gates_without_writing_requests(observing):
    gated = dict(ORDERS, approvals={"keys": [str(observing.path / "keys/approver.pub")],
                                    "required": {"get_order": "always"}})
    attach(observing, "chat-a", [mint(observing, gated)])
    guard = SharedLocalGuard(observing.path)
    assert guard.pre_tool_call("get_order", {"order_id": "A-1001"}, session_id="chat-a") is None
    assert recorded(observing)[0]["reason"] == "approval_required"
    assert not list((observing.path / "requests").glob("*.yaml"))


def test_switching_the_workspace_to_enforce_blocks_on_the_next_call(observing):
    guard = SharedLocalGuard(observing.path)
    assert guard.pre_tool_call("terminal", {"command": "ls"}, session_id="chat-a") is None
    observing.set_mode("enforce")
    assert guard.pre_tool_call("terminal", {"command": "ls"}, session_id="chat-a")["action"] == "block"
    assert len(recorded(observing)) == 1


def test_local_home_refuses_on_denial_log_and_points_to_observe(observing, monkeypatch):
    from hermes_tenuo import _config
    from hermes_tenuo._guard import WarrantLoadError, build_plugin_guard

    entry = {"local_home": str(observing.path), "on_denial": "log"}
    monkeypatch.setattr(_config, "_get_plugin_entry", lambda ctx: entry)
    with pytest.raises(WarrantLoadError) as raised:
        build_plugin_guard(None)
    assert "tenuo-cli mode observe" in str(raised.value.__cause__)


def test_doctor_reports_observe_mode(observing, monkeypatch, capsys):
    from hermes_tenuo import _config

    monkeypatch.setattr(_config, "_get_plugin_entry", lambda ctx: {"local_home": str(observing.path)})
    assert report_shared_local_config() is True
    assert "observe" in capsys.readouterr().out
