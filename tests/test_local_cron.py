"""An unattended cron job needs one attachment for all of its runs, and only its own."""
import pytest

pytest.importorskip("tenuo.local_cli.observations", reason="needs the Tenuo SDK with the local CLI (tenuo-ai/tenuo#970)")

import json


from tenuo import WarrantTemplate
from tenuo.local_cli.sessions import attach
from tenuo.local_cli.workspace import Workspace

from hermes_tenuo.local_guard import SharedLocalGuard, cron_job

REPORTS = {"version": 2, "ttl": "30m", "capabilities": {"read_file": {"path": {"subpath": "/data/reports"}}}}


@pytest.fixture
def workspace(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    return workspace


def warrant(workspace):
    return WarrantTemplate(REPORTS).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))


def test_cron_job_key():
    assert cron_job("cron_nightly_20261020_020000") == "cron_nightly"
    assert cron_job("cron_a_b_20261020_020000") == "cron_a_b"
    for other in ("cron_nightly", "20261020_020000_ab12cd34", "chat-a", "", None):
        assert cron_job(other) is None


def test_one_job_attachment_covers_every_run_of_that_job_only(workspace):
    attach(workspace, "cron_nightly", [warrant(workspace)])
    guard = SharedLocalGuard(workspace.path)
    args = {"path": "/data/reports/q3.csv"}
    for run in ("cron_nightly_20261020_020000", "cron_nightly_20261021_020000"):
        assert guard.pre_tool_call("read_file", args, session_id=run) is None
    assert guard.pre_tool_call("read_file", {"path": "/etc/passwd"},
                               session_id="cron_nightly_20261021_020000")["action"] == "block"
    other = guard.pre_tool_call("read_file", args, session_id="cron_weekly_20261021_020000")
    assert other["action"] == "block" and "--session cron_weekly" in other["message"]
    assert "every run" in other["message"]
    assert guard.pre_tool_call("read_file", args, session_id="chat-a")["action"] == "block"


def test_a_runs_own_attachment_takes_precedence_over_its_jobs(workspace):
    attach(workspace, "cron_nightly", [warrant(workspace)])
    narrow = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {
        "read_file": {"path": "/data/reports/q3.csv"}}}).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    run = "cron_nightly_20261021_020000"
    attach(workspace, run, [narrow])
    guard = SharedLocalGuard(workspace.path)
    assert guard.pre_tool_call("read_file", {"path": "/data/reports/q3.csv"}, session_id=run) is None
    assert guard.pre_tool_call("read_file", {"path": "/data/reports/q2.csv"}, session_id=run)["action"] == "block"


def test_observe_records_each_cron_run_under_its_job_step(workspace):
    workspace.set_mode("observe")
    guard = SharedLocalGuard(workspace.path)
    guard.pre_tool_call("read_file", {"path": "/data/reports/q3.csv"}, session_id="cron_nightly_20261020_020000")
    guard.pre_tool_call("read_file", {"path": "/x"}, session_id="chat-a")
    lines = [json.loads(line) for line in (workspace.path / "observations.jsonl").read_text().splitlines()]
    assert [(line["run"], line["step"]) for line in lines] == [
        ("cron_nightly_20261020_020000", "cron_nightly"),
        ("chat-a", "hermes"),
    ]
