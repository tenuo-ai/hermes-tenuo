"""Jobs: named limits a parent gives a delegated helper, on top of what the parent may do."""
from __future__ import annotations

import sys
import types

import pytest

from hermes_tenuo import access
from hermes_tenuo.access import build_access_policy
from hermes_tenuo.hermes_guard import HermesGuard
from hermes_tenuo.jobs import JobsConfigError, delegation_provider, parse_jobs

tenuo = pytest.importorskip("tenuo")

ROLES = {
    "roles": {
        "ops": {"match": {"user": ["telegram:101"]}, "allow": {
            "terminal": {"command": {"patterns": [r"^\./checkoutctl (restart|logs)$"]}},
            "read_file": {"path": "/srv/**"},
            "delegate_task": {},
        }},
        "developer": {"match": {"user": ["telegram:202"]}, "allow": {
            "terminal": {"command": {"patterns": [r"^\./checkoutctl logs$"]}},
            "delegate_task": {},
        }},
    },
    "on_unmatched": "deny",
}
JOBS = {
    "log-reader": {"description": "Reads the checkout logs.",
                   "allow": {"terminal": {"command": {"patterns": [r"^\./checkoutctl logs$"]}}}},
    "restarter": {"description": "Restarts checkout, once.", "ttl_seconds": 120,
                  "allow": {"terminal": {"max_uses": 1, "command": {"patterns": [r"^\./checkoutctl restart$"]}}}},
    "config-reader": {"allow": {"read_file": {"path": "/srv/checkout/**"}}},
    "restarter-in-place": {"allow": {"terminal": {"workdir": "/srv/checkout/**",
                                                  "command": {"patterns": [r"^\./checkoutctl restart$"]}}}},
    "prefixed-restarter": {"allow": {"tool:terminal": {"max_uses": 1, "strict": True,
                                                       "command": {"patterns": [r"^\./checkoutctl restart$"]}}}},
    "log-lead": {"allow": {"terminal": {"command": {"patterns": [r"^\./checkoutctl logs$"]}}, "delegate_task": {}}},
    "lead": {"allow": {"terminal": {"command": {"patterns": [r"^\./checkoutctl (restart|logs)$"]}}, "delegate_task": {}}},
}
DANA = dict(user="telegram:101", chat="telegram:-1", platform="telegram")
SAM = dict(user="telegram:202", chat="telegram:-1", platform="telegram")


@pytest.fixture
def team(monkeypatch):
    key = tenuo.SigningKey.generate()
    policy = build_access_policy(ROLES, control_key=key, holder=key.public_key, signing_key=key)
    events = []
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy,
                        jobs=parse_jobs(JOBS), audit_callback=events.append)
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: (lambda task_id: None))
    guard.events = events
    return guard


def speaks(monkeypatch, who):
    monkeypatch.setattr(access, "current_sender", lambda: who)


def helper(guard, parent, child, job=None, goal=None, **task):
    goal = goal or f"work for {child}"
    spec = {"goal": goal, **task}
    if job:
        spec["job"] = job
    refused = guard.pre_tool_call("delegate_task", {"tasks": [spec]}, session_id=parent)
    if refused is None:
        guard.on_subagent_start(parent_session_id=parent, child_session_id=child, child_goal=goal)
    return refused


def run(guard, session, command):
    return guard.pre_tool_call("terminal", {"command": command}, session_id=session) is None


def test_a_helper_gets_only_its_job_not_everything_its_parent_has(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert run(team, "dana", "./checkoutctl restart")                    # Dana may restart
    assert helper(team, "dana", "h1", job="log-reader") is None
    assert run(team, "h1", "./checkoutctl logs")
    assert not run(team, "h1", "./checkoutctl restart")                  # her log-reader may not
    assert team.pre_tool_call("read_file", {"path": "/srv/x"}, session_id="h1") is not None   # not part of the job
    assert team.pre_tool_call("delegate_task", {"goal": "more"}, session_id="h1") is not None


def test_a_job_can_carry_a_use_limit(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "h1", job="restarter") is None
    assert not run(team, "h1", "./checkoutctl logs")
    assert run(team, "h1", "./checkoutctl restart")
    assert not run(team, "h1", "./checkoutctl restart")
    assert "use limit reached" in team.events[-1].reason


def test_a_helper_never_gets_more_than_the_person_who_asked(team, monkeypatch):
    speaks(monkeypatch, SAM)
    assert helper(team, "sam", "h1", job="restarter") is None            # the job exists, Sam cannot restart
    assert not run(team, "h1", "./checkoutctl restart")
    assert helper(team, "sam", "h2", job="log-reader", goal="read") is None
    assert run(team, "h2", "./checkoutctl logs")


def test_a_job_whose_tools_the_asker_lacks_is_refused(team, monkeypatch):
    speaks(monkeypatch, SAM)
    refused = helper(team, "sam", "h1", job="config-reader")             # Sam has no read_file
    assert refused is not None
    assert "job 'config-reader' uses read_file, which the person who asked may not use" in refused["message"]


def test_a_path_limit_narrows_a_path_limit(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "h1", job="config-reader") is None
    assert team.pre_tool_call("read_file", {"path": "/srv/checkout/app.yaml"}, session_id="h1") is None
    assert team.pre_tool_call("read_file", {"path": "/srv/billing/app.yaml"}, session_id="h1") is not None


def test_a_job_can_keep_a_helper_in_one_directory(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "h1", job="restarter-in-place") is None

    def restart(**more):
        return team.pre_tool_call("terminal", {"command": "./checkoutctl restart", **more}, session_id="h1") is None

    assert restart(workdir="/srv/checkout") and restart(workdir="/srv/checkout/app")
    assert not restart(workdir="/tmp/elsewhere") and not restart(workdir="/srv/checkout/../../tmp")
    assert not restart()                                                 # the directory must be named


def test_a_job_that_writes_a_tool_with_its_prefix_is_limited_the_same(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "h1", job="prefixed-restarter") is None
    assert not run(team, "h1", "./checkoutctl logs")                     # the job's command limit holds
    assert team.pre_tool_call("terminal", {"command": "./checkoutctl restart", "workdir": "/x"}, session_id="h1")  # strict
    assert run(team, "h1", "./checkoutctl restart") and not run(team, "h1", "./checkoutctl restart")   # and its use limit


def test_a_helper_of_a_helper_is_narrowed_again(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "lead", job="lead") is None
    assert run(team, "lead", "./checkoutctl restart")
    assert helper(team, "lead", "h2", job="log-reader", goal="read") is None
    assert run(team, "h2", "./checkoutctl logs") and not run(team, "h2", "./checkoutctl restart")
    assert helper(team, "lead", "h3", job="restarter", goal="restart") is None
    assert run(team, "h3", "./checkoutctl restart") and not run(team, "h3", "./checkoutctl restart")


def test_a_task_that_names_no_job_gets_the_default_job(monkeypatch):
    key = tenuo.SigningKey.generate()
    policy = build_access_policy(ROLES, control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy,
                        jobs=parse_jobs(JOBS, "log-reader"))
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: (lambda task_id: None))
    speaks(monkeypatch, DANA)
    assert helper(guard, "dana", "h1") is None
    assert run(guard, "h1", "./checkoutctl logs") and not run(guard, "h1", "./checkoutctl restart")


def test_without_a_default_a_task_with_no_job_inherits_as_before(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "h1") is None
    assert run(team, "h1", "./checkoutctl restart")


def test_an_unknown_job_is_refused(team, monkeypatch):
    speaks(monkeypatch, DANA)
    refused = helper(team, "dana", "h1", job="janitor")
    assert refused is not None and "no job named 'janitor'" in refused["message"]


def test_a_job_named_when_none_are_configured_is_refused():
    root, agent = tenuo.SigningKey.generate(), tenuo.SigningKey.generate()
    warrant = tenuo.Warrant.mint_builder().holder(agent.public_key).capability("delegate_task").ttl(600).mint(root)
    guard = HermesGuard(warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
    refused = guard.pre_tool_call("delegate_task", {"tasks": [{"goal": "x", "job": "log-reader"}]}, session_id="p")
    assert refused is not None and "no jobs are configured" in refused["message"]


# A refusal says whose limit it is.

def why(guard, session, command="./checkoutctl restart", tool="terminal", **args):
    refused = guard.pre_tool_call(tool, {"command": command} if tool == "terminal" else args, session_id=session)
    return refused["message"] if refused else None


def test_a_refusal_names_the_person_who_asked_when_the_limit_is_theirs(team, monkeypatch):
    speaks(monkeypatch, SAM)
    assert helper(team, "sam", "h1", job="restarter") is None
    message = why(team, "h1")
    assert message.startswith("tenuo: the person who asked may not do this, so a helper working for them may not either")
    assert "Constraint 'command' not satisfied" in message              # the check's own words stay
    assert team.events[-1].decision == "DENY" and "the person who asked may not do this" in team.events[-1].reason
    assert "the person who asked may not do this" in why(team, "h1", tool="read_file", path="/srv/x")


def test_a_refusal_names_the_job_when_the_limit_is_the_jobs(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "h1", job="log-reader") is None
    assert why(team, "h1").startswith("tenuo: this is outside this helper's job ('log-reader')")
    assert "outside this helper's job ('log-reader')" in why(team, "h1", tool="read_file", path="/srv/x")
    assert why(team, "h1", "./checkoutctl logs") is None


def test_a_refusal_names_the_helper_in_between_when_the_limit_is_its(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "lead", job="log-lead") is None
    assert helper(team, "lead", "h2", job="restarter", goal="restart") is None
    assert why(team, "h2").startswith("tenuo: the helper that delegated this task may not do this itself")


def test_a_refusal_two_helpers_down_still_names_the_person(team, monkeypatch):
    speaks(monkeypatch, SAM)
    assert helper(team, "sam", "lead", job="lead") is None
    assert helper(team, "lead", "h2", job="restarter", goal="restart") is None
    assert "the person who asked may not do this" in why(team, "h2")


def test_a_use_limit_refusal_keeps_its_own_words(team, monkeypatch):
    speaks(monkeypatch, DANA)
    assert helper(team, "dana", "h1", job="restarter") is None
    assert why(team, "h1") is None
    assert why(team, "h1") == "tenuo: use limit reached: this grant allows terminal 1 time"


def test_a_helper_without_a_job_is_told_about_the_person_too(monkeypatch):
    key = tenuo.SigningKey.generate()
    policy = build_access_policy(ROLES, control_key=key, holder=key.public_key, signing_key=key)
    guard = HermesGuard(signing_key=key, trusted_roots=[key.public_key], access_policy=policy)
    monkeypatch.setattr(access, "subagent_attribution_lookup", lambda: (lambda task_id: None))
    speaks(monkeypatch, SAM)
    assert helper(guard, "sam", "h1") is None
    assert "the person who asked may not do this" in why(guard, "h1")
    assert why(guard, "h1", "./checkoutctl logs") is None


def test_the_asker_is_refused_in_the_checks_own_words(team, monkeypatch):
    speaks(monkeypatch, SAM)
    assert why(team, "sam") == "Constraint 'command' not satisfied: value does not match constraint"


def _single(warrant_caps, jobs):
    root, agent = tenuo.SigningKey.generate(), tenuo.SigningKey.generate()
    builder = tenuo.Warrant.mint_builder().holder(agent.public_key).capability("delegate_task")
    for tool, caps in warrant_caps.items():
        builder = builder.capability(tool, **caps)
    return HermesGuard(warrant=builder.ttl(600).mint(root), signing_key=agent, trusted_roots=[root.public_key],
                       jobs=parse_jobs(jobs))


def test_with_one_warrant_a_job_limits_what_the_warrant_leaves_open():
    guard = _single({"terminal": {}}, {"lister": {"allow": {"terminal": {"command": {"patterns": [r"^ls -la$"]}}}}})
    assert helper(guard, "p", "h1", job="lister") is None
    assert run(guard, "h1", "ls -la") and not run(guard, "h1", "rm -rf /")
    assert run(guard, "p", "rm -rf /tmp/x")                               # the parent is as before


def test_with_one_warrant_a_job_tightens_a_path():
    guard = _single({"read_file": {"path": tenuo.Subpath("/data")}},
                    {"reports": {"allow": {"read_file": {"path": "/data/reports/**"}}}})
    assert helper(guard, "p", "h1", job="reports") is None
    assert guard.pre_tool_call("read_file", {"path": "/data/reports/q3"}, session_id="h1") is None
    assert guard.pre_tool_call("read_file", {"path": "/data/payroll"}, session_id="h1") is not None


def test_with_one_warrant_a_refusal_names_the_job_or_the_warrant():
    guard = _single({"read_file": {"path": tenuo.Subpath("/data")}},
                    {"reports": {"allow": {"read_file": {"path": "/data/reports/**"}}}})
    assert helper(guard, "p", "h1", job="reports") is None
    assert "outside this helper's job ('reports')" in why(guard, "h1", tool="read_file", path="/data/payroll")
    assert "this agent's own warrant does not allow this" in why(guard, "h1", tool="read_file", path="/etc/passwd")
    refused = helper(_single({}, {"reports": {"allow": {"read_file": {}}}}), "p", "h2", job="reports")
    assert "job 'reports' uses read_file, which the agent delegating it may not use" in refused["message"]


def test_a_job_that_cannot_be_combined_with_the_parents_limit_is_refused_not_widened():
    guard = _single({"read_file": {"path": tenuo.Subpath("/data")}},
                    {"odd": {"allow": {"read_file": {"path": {"patterns": [r"^/etc/.*$"]}}}}})
    refused = helper(guard, "p", "h1", job="odd")
    assert refused is not None and "delegation rejected" in refused["message"]


def test_jobs_and_a_delegation_plan_do_not_mix():
    from hermes_tenuo.delegation import parse_plan

    plan = parse_plan({"version": 1, "root": {"tools": {"web_search": {}, "delegate_task": {}}},
                       "levels": [{"ttl_seconds": 60, "tools": {"web_search": {}}}]})
    root, agent = tenuo.SigningKey.generate(), tenuo.SigningKey.generate()
    warrant = (tenuo.Warrant.mint_builder().holder(agent.public_key).capability("web_search")
               .capability("delegate_task").ttl(600).mint(root))
    guard = HermesGuard(warrant=warrant, signing_key=agent, trusted_roots=[root.public_key], delegation_plan=plan)
    refused = guard.pre_tool_call("delegate_task", {"tasks": [{"goal": "x", "job": "log-reader"}]}, session_id="p")
    assert refused is not None and "cannot be used with a delegation plan" in refused["message"]


@pytest.mark.parametrize("other", ["delegation_plan", "child_warrant"])
def test_jobs_cannot_be_set_with_a_plan_or_a_child_warrant(other):
    from hermes_tenuo.delegation import parse_plan

    root, agent = tenuo.SigningKey.generate(), tenuo.SigningKey.generate()
    warrant = (tenuo.Warrant.mint_builder().holder(agent.public_key).capability("terminal")
               .capability("delegate_task").ttl(600).mint(root))
    extra = {"delegation_plan": parse_plan({"version": 1, "root": {"tools": {"terminal": {}, "delegate_task": {}}},
                                            "levels": [{"ttl_seconds": 60, "tools": {"terminal": {}}}]})}
    if other == "child_warrant":
        extra = {"child_warrant": tenuo.Warrant.mint_builder().holder(agent.public_key).capability("terminal").ttl(60).mint(root)}
    with pytest.raises(JobsConfigError, match="jobs cannot be used together with"):
        HermesGuard(warrant=warrant, signing_key=agent, trusted_roots=[root.public_key],
                    jobs=parse_jobs({"lister": {"allow": ["terminal"]}}), **extra)


# The jobs block.

@pytest.mark.parametrize("block, default, message", [
    ("nope", None, "non-empty map"),
    ({"Bad Name": {"allow": ["terminal"]}}, None, "not a valid job name"),
    ({"a": {"allow": ["terminal"], "extra": 1}}, None, "unknown fields"),
    ({"a": {"allow": {}}}, None, "allow must be a non-empty map"),
    ({"a": {"allow": {"terminal": {"max_uses": 0}}}}, None, "max_uses must be a positive integer"),
    ({"a": {"allow": {"terminal": {"command": {"patterns": ["unanchored"]}}}}}, None, "anchored"),
    ({"a": {"allow": ["terminal"], "ttl_seconds": -5}}, None, "ttl_seconds must be a positive integer"),
    ({"a": {"allow": ["terminal"]}}, "b", "no job named 'b'"),
    ({"a": {"allow": {"terminal": {}, "tool:terminal": {"max_uses": 1}}}}, None, "terminal is listed twice"),
    ({"a": {"allow": ["tool:"]}}, None, "tool names must be non-empty"),
    ({"a": {"allow": ["terminal"], "extra": 1, 2: "bad"}}, None, "unknown fields"),
    ({"a": {"allow": {3: {}}}}, None, "tool names must be non-empty"),
    ({7: {"allow": ["terminal"]}}, None, "not a valid job name"),
])
def test_a_bad_jobs_block_is_refused(block, default, message):
    with pytest.raises(JobsConfigError, match=message):
        parse_jobs(block, default)


def test_the_agent_is_offered_the_jobs_by_name(monkeypatch):
    class DelegationProvider:
        def settings(self, config):
            return {}

    monkeypatch.setitem(sys.modules, "agent", types.ModuleType("agent"))
    monkeypatch.setitem(sys.modules, "agent.delegation_provider",
                        types.SimpleNamespace(DelegationProvider=DelegationProvider))
    provider = delegation_provider(parse_jobs(JOBS))
    assert provider.name == "tenuo"
    param = provider.task_parameters({})["job"]
    assert param["enum"] == sorted(JOBS) and "log-reader (Reads the checkout logs.)" in param["description"]
    assert provider.task_parameters({}) == provider.task_parameters({})          # stable for the prompt cache
    assert provider.route_task({"goal": "x", "job": "log-reader"}, {"model": "m", "service_tier": "fast"}) == {"model": "m"}


# Plugin startup: a jobs block that cannot be used blocks every call.

def _startup(tmp_path, monkeypatch, jobs):
    import hermes_tenuo._home as home
    from hermes_tenuo._guard import build_plugin_guard

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("TENUO_SIGNING_KEY", raising=False)
    entry = {"access": ROLES, "jobs": jobs}
    monkeypatch.setattr(home, "load_hermes_config",
                        lambda: {"plugins": {"enabled": ["hermes-tenuo"], "entries": {"hermes-tenuo": entry}}})
    return build_plugin_guard(None)


def test_startup_with_jobs(tmp_path, monkeypatch):
    assert sorted(_startup(tmp_path, monkeypatch, JOBS).jobs.jobs) == sorted(JOBS)


@pytest.mark.parametrize("jobs, message", [
    ({"a": {"allow": {}}}, "allow must be a non-empty map"),
    ({"a": {"allow": ["terminal"], "extra": 1, 2: "bad"}}, "unknown fields"),
])
def test_startup_blocks_everything_on_a_bad_jobs_block(tmp_path, monkeypatch, jobs, message):
    from hermes_tenuo._guard import WarrantLoadError

    with pytest.raises(WarrantLoadError, match=message):
        _startup(tmp_path, monkeypatch, jobs)


def test_startup_blocks_everything_when_jobs_cannot_be_read_at_all(tmp_path, monkeypatch):
    import hermes_tenuo.jobs as jobs_module
    from hermes_tenuo._guard import WarrantLoadError

    def broken(block, default=None):
        raise TypeError("unexpected")

    monkeypatch.setattr(jobs_module, "parse_jobs", broken)
    with pytest.raises(WarrantLoadError, match=r"jobs could not be read \(TypeError\)"):
        _startup(tmp_path, monkeypatch, JOBS)
