"""A delegate_task child that Hermes would run in another profile is outside this plugin's checks."""

import json
import sys
import types

import pytest
from tenuo import SigningKey, Warrant, Wildcard

from hermes_tenuo import routing
from hermes_tenuo.hermes_guard import HermesGuard


def _guard(**kwargs):
    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder().holder(agent_key.public_key)
        .capability("web_search", query=Wildcard())
        .capability("delegate_task")
        .ttl(3600).mint(root_key)
    )
    events = []
    guard = HermesGuard(warrant=warrant, signing_key=agent_key, trusted_roots=[root_key.public_key],
                        audit_callback=events.append, **kwargs)
    return guard, events


def _delegate(guard, args, session="s0"):
    return guard.pre_tool_call("delegate_task", args, session_id=session)


@pytest.mark.parametrize("args", [
    {"goal": "x", "profile": "worker"},
    {"tasks": [{"goal": "a"}, {"goal": "b", "profile": "worker"}]},
    {"tasks": json.dumps([{"goal": "a", "profile": "worker"}])},
    {"profile": "worker", "tasks": [{"goal": "a"}]},
])
def test_a_task_that_names_another_profile_is_refused(args):
    guard, events = _guard()
    refused = _delegate(guard, args)
    assert refused["action"] == "block" and "Hermes profile 'worker'" in refused["message"]
    assert events[-1].decision == "DENY"
    assert guard._planned_children == {}                       # no grant was staged for it


def test_a_task_that_stays_here_is_delegated_as_before():
    guard, _ = _guard(routing=lambda task, index: None)
    assert _delegate(guard, {"goal": "x"}) is None
    assert _delegate(guard, {"tasks": [{"goal": "a"}, {"goal": "b"}]}, session="s9") is None


def test_a_default_profile_set_in_hermes_config_is_refused_too():
    """No task names a profile; Hermes's own routing says where it goes."""
    guard, _ = _guard(routing=lambda task, index: "worker")
    refused = _delegate(guard, {"goal": "x"})
    assert refused is not None and "Hermes profile 'worker'" in refused["message"]


def test_an_unknown_destination_is_refused():
    def broken(task, index):
        raise RuntimeError("no route table")

    guard, _ = _guard(routing=broken)
    refused = _delegate(guard, {"goal": "x"})
    assert refused is not None and "could not tell" in refused["message"] and "RuntimeError" in refused["message"]


def test_the_operator_can_allow_routed_subagents():
    guard, _ = _guard(routing=lambda task, index: "worker", allow_routed_delegation=True)
    assert _delegate(guard, {"goal": "x", "profile": "worker"}) is None


def test_only_true_allows_it():
    guard, _ = _guard(allow_routed_delegation="yes")
    assert _delegate(guard, {"goal": "x", "profile": "worker"}) is not None


def test_log_only_mode_still_refuses_it():
    guard, _ = _guard(on_denial="log")
    assert _delegate(guard, {"goal": "x", "profile": "worker"}) is not None


def test_control_actions_and_other_tools_are_untouched():
    guard, _ = _guard(routing=lambda task, index: "worker")
    assert _delegate(guard, {"action": "list"}) is None
    assert guard.pre_tool_call("web_search", {"query": "q", "profile": "worker"}, session_id="s0") is not None  # unknown arg, by the warrant
    assert guard.pre_tool_call("web_search", {"query": "q"}, session_id="s0") is None


def test_a_refused_routed_delegation_gives_its_use_back():
    from hermes_tenuo.delegation import parse_plan

    plan = parse_plan({
        "version": 1,
        "root": {"tools": {"web_search": {}, "delegate_task": {}}},
        "levels": [{"ttl_seconds": 60, "tools": {"web_search": {}, "delegate_task": {"max_uses": 1}}},
                   {"ttl_seconds": 30, "tools": {"web_search": {}}}],
    })
    guard, _ = _guard(delegation_plan=plan)
    assert _delegate(guard, {"goal": "child"}) is None
    guard.on_subagent_start(parent_session_id="s0", child_session_id="s1", child_goal="child")
    assert _delegate(guard, {"goal": "g", "profile": "worker"}, session="s1") is not None
    assert _delegate(guard, {"goal": "g"}, session="s1") is None            # the one use is still there


# hermes_tenuo.routing against Hermes's delegation strategy interface.

class _Provider:
    def __init__(self, route, name="default", parameters=None):
        self.route, self.name, self.parameters = route, name, parameters or {}

    def task_parameters(self, config):
        return self.parameters

    def route_task(self, task, config):
        return self.route(task, config) if callable(self.route) else self.route


def _fake_hermes(monkeypatch, provider=None, error=None, config=None, others=(), unavailable=(), pinning=True):
    """Hermes's delegation interface: *provider* is the saved strategy, *others* are installed beside it."""
    class DelegationRouteError(ValueError):
        pass

    def get_active_provider(cfg):
        if error == "route":
            raise DelegationRouteError("backend missing")
        if error:
            raise RuntimeError(error)
        return provider

    installed = {p.name: p for p in ([provider] if provider else []) + list(others)}

    def backend_status(name):
        return installed.get(name), ("cannot run here" if name in unavailable else "")

    monkeypatch.setitem(sys.modules, "agent", types.ModuleType("agent"))
    monkeypatch.setitem(sys.modules, "agent.delegation_provider", types.SimpleNamespace(
        DelegationRouteError=DelegationRouteError, RESERVED_TASK_PARAMETERS=frozenset({"goal", "context", "index", "model"})))
    monkeypatch.setitem(sys.modules, "agent.delegation_registry",
                        types.SimpleNamespace(get_active_provider=get_active_provider, backend_status=backend_status))
    monkeypatch.setitem(sys.modules, "agent.delegation_backends", types.SimpleNamespace(
        list_backends=lambda: [types.SimpleNamespace(name=name) for name in installed]) if pinning else None)
    monkeypatch.setattr("hermes_tenuo._home.load_hermes_config", lambda: {"delegation": config or {}})
    return DelegationRouteError


def test_routing_reads_the_configured_strategy(monkeypatch):
    seen = {}

    def route(task, config):
        seen["config"] = config
        return {"profile": "worker", "label": "worker"}

    _fake_hermes(monkeypatch, _Provider(route, "profile_routes"), config={"backend": "profile_routes"})
    found = routing.other_profile({"goal": "x"})
    assert found == "worker" and found.backend == "profile_routes"
    assert seen["config"] == {"backend": "profile_routes"}


def test_routing_says_none_for_the_parents_route_and_for_a_model_route(monkeypatch):
    _fake_hermes(monkeypatch, _Provider({}))
    assert routing.other_profile({"goal": "x"}) is None
    _fake_hermes(monkeypatch, _Provider({"model": "fast", "provider": "openrouter"}))
    assert routing.other_profile({"goal": "x"}) is None


def test_a_named_profile_needs_no_lookup(monkeypatch):
    _fake_hermes(monkeypatch, error="must not be asked")
    assert routing.other_profile({"goal": "x", "profile": " worker "}) == "worker"


def test_a_route_hermes_itself_refuses_is_left_to_hermes(monkeypatch):
    _fake_hermes(monkeypatch, error="route")
    assert routing.other_profile({"goal": "x"}) is None


def test_any_other_failure_is_raised(monkeypatch):
    _fake_hermes(monkeypatch, error="boom")
    with pytest.raises(RuntimeError):
        routing.other_profile({"goal": "x"})


def test_a_hermes_without_delegation_strategies_runs_every_child_here(monkeypatch):
    monkeypatch.setitem(sys.modules, "agent", None)
    monkeypatch.setitem(sys.modules, "agent.delegation_provider", None)
    assert routing.other_profile({"goal": "x"}) is None


def test_the_strategy_is_asked_the_way_hermes_asks_it(monkeypatch):
    """goal, context, the task's place in the batch, and only the parameters the strategy declares."""
    seen = []
    provider = _Provider(lambda task, config: seen.append(task) or {}, "routes",
                         parameters={"lane": {"type": "string"}, "model": {"type": "string"}, "Bad-Name": {}, "raw": "x"})
    _fake_hermes(monkeypatch, provider)
    task = {"goal": "g", "context": "c", "lane": "fast", "model": "m", "Bad-Name": 1, "raw": 2, "extra": 3, "index": 7}
    assert routing.other_profile(task, 1) is None
    assert seen == [{"goal": "g", "context": "c", "index": 1, "lane": "fast"}]


def test_a_route_that_depends_on_the_place_in_the_batch_is_seen(monkeypatch):
    second = _Provider(lambda task, config: {"profile": "worker"} if task["index"] == 1 else {}, "by_place")
    _fake_hermes(monkeypatch, second, config={"backend": "by_place"})
    assert routing.other_profile({"goal": "a"}, 0) is None
    assert routing.other_profile({"goal": "b"}, 1) == "worker"
    guard, _ = _guard(routing=routing.other_profile)
    assert _delegate(guard, {"tasks": [{"goal": "a"}]}) is None
    refused = _delegate(guard, {"tasks": [{"goal": "a"}, {"goal": "b"}]}, session="s2")
    assert refused is not None and "Hermes profile 'worker'" in refused["message"]


def test_a_batch_task_does_not_take_the_calls_context(monkeypatch):
    """Hermes hands its strategy a batch task as written; only the single-goal form carries the call's context."""
    by_context = _Provider(lambda task, config: {} if task["context"] == "stay" else {"profile": "worker"}, "by_context")
    _fake_hermes(monkeypatch, by_context, config={"backend": "by_context"})
    guard, _ = _guard(routing=routing.other_profile)
    assert _delegate(guard, {"goal": "a", "context": "stay"}) is None
    assert _delegate(guard, {"tasks": [{"goal": "a", "context": "stay"}]}, session="s2") is None
    refused = _delegate(guard, {"context": "stay", "tasks": [{"goal": "a"}]}, session="s3")
    assert refused is not None and "Hermes profile 'worker'" in refused["message"]
    refused = _delegate(guard, {"context": "stay", "tasks": json.dumps([{"goal": "a"}])}, session="s4")
    assert refused is not None and "Hermes profile 'worker'" in refused["message"]


def test_a_single_goal_is_routed_on_its_goal_and_context_only(monkeypatch):
    seen = []
    provider = _Provider(lambda task, config: seen.append(task) or {}, "routes", parameters={"lane": {"type": "string"}})
    _fake_hermes(monkeypatch, provider, config={"backend": "routes"})
    guard, _ = _guard(routing=routing.other_profile)
    assert _delegate(guard, {"goal": "a", "context": "c", "lane": "far"}) is None
    assert seen == [{"goal": "a", "context": "c", "index": 0}]


def test_a_strategy_the_session_may_still_be_using_is_asked_too(monkeypatch):
    """delegation.backend was changed to default; a running session keeps routing on the one it started with."""
    seen = {}

    def route(task, config):
        seen["backend"] = config["backend"]
        return {"profile": "worker"}

    _fake_hermes(monkeypatch, _Provider({}, "default"), config={"backend": "default"},
                 others=[_Provider(route, "profile_routes")])
    found = routing.other_profile({"goal": "x"})
    assert found == "worker" and found.backend == "profile_routes" and seen["backend"] == "profile_routes"
    guard, _ = _guard(routing=routing.other_profile)
    refused = _delegate(guard, {"goal": "x"})
    assert "Hermes profile 'worker' (delegation backend 'profile_routes')" in refused["message"]


def test_installed_strategies_that_keep_tasks_here_change_nothing(monkeypatch):
    _fake_hermes(monkeypatch, _Provider({}, "default"),
                 others=[_Provider({}, "profile_routes"), _Provider({"model": "fast"}, "model_map")])
    assert routing.other_profile({"goal": "x"}) is None


def test_a_strategy_that_cannot_run_is_not_asked(monkeypatch):
    _fake_hermes(monkeypatch, _Provider({}, "default"), others=[_Provider({"profile": "worker"}, "broken")],
                 unavailable={"broken"})
    assert routing.other_profile({"goal": "x"}) is None


def test_a_saved_strategy_that_cannot_run_does_not_hide_the_others(monkeypatch):
    _fake_hermes(monkeypatch, error="route", others=[_Provider({"profile": "worker"}, "profile_routes")])
    assert routing.other_profile({"goal": "x"}) == "worker"


def test_a_strategy_that_refuses_the_task_starts_nothing(monkeypatch):
    def refuse(task, config):
        raise DelegationRouteError("no such lane")

    DelegationRouteError = _fake_hermes(monkeypatch, _Provider(refuse, "default"))
    assert routing.other_profile({"goal": "x"}) is None


def test_a_failing_strategy_is_an_unknown_destination(monkeypatch):
    def fail(task, config):
        raise KeyError("routes")

    _fake_hermes(monkeypatch, _Provider({}, "default"), others=[_Provider(fail, "other")])
    with pytest.raises(KeyError):
        routing.other_profile({"goal": "x"})
    guard, _ = _guard(routing=routing.other_profile)
    assert "could not tell" in _delegate(guard, {"goal": "x"})["message"]


def test_a_hermes_where_sessions_keep_no_strategy_asks_the_saved_one(monkeypatch):
    _fake_hermes(monkeypatch, _Provider({"profile": "worker"}, "profile_routes"), pinning=False)
    assert routing.other_profile({"goal": "x"}) == "worker"


def test_the_setting_is_off_unless_exactly_true(monkeypatch):
    from hermes_tenuo import _config

    for raw, expected in ((True, True), (False, False), ("true", False), (1, False), (None, False)):
        monkeypatch.setattr(_config, "_get_plugin_entry", lambda ctx, raw=raw: {"allow_routed_delegation": raw})
        assert _config.get_allow_routed_delegation(None) is expected


# doctor: Hermes running from an environment that does not contain the plugin.

@pytest.fixture(autouse=True)
def _not_hermes_python(monkeypatch):
    """These tests run outside Hermes's Python unless one says which install is running."""
    monkeypatch.setitem(sys.modules, "pm", None)
    monkeypatch.setitem(sys.modules, "pm.environments", None)
    monkeypatch.setitem(sys.modules, "pm.paths", None)


def _running_install(monkeypatch, home, install):
    """Hermes's own answer to "which install is this process"."""
    monkeypatch.setitem(sys.modules, "pm", types.ModuleType("pm"))
    monkeypatch.setitem(sys.modules, "pm.paths", types.SimpleNamespace(install_root=lambda: home / "checkout"))
    monkeypatch.setitem(sys.modules, "pm.environments",
                        types.SimpleNamespace(install_state_dir=lambda root: home / "installs" / install))


def _managed(home, with_plugin, install="abc"):
    env = home / "installs" / install / "environments" / "e1" / "venv"
    site = env / "lib" / "python3.14" / "site-packages"
    site.mkdir(parents=True)
    if with_plugin:
        (site / "hermes_tenuo-0.4.2.dist-info").mkdir()
    (home / "installs" / install / "facts.json").write_text(json.dumps({"packages": {"venv": {"environment": str(env)}}}))
    return env


def test_a_managed_environment_without_the_plugin_is_reported(tmp_path, monkeypatch):
    from hermes_tenuo import _home

    monkeypatch.setattr(_home, "hermes_home", lambda: tmp_path)
    assert _home.managed_environments_without_plugin() == []          # Hermes runs from where it was installed
    env = _managed(tmp_path, with_plugin=False)
    assert _home.managed_environments_without_plugin() == [env]
    (tmp_path / "plugins" / "hermes-tenuo").mkdir(parents=True)        # installed through Hermes instead
    assert _home.managed_environments_without_plugin() == []


def test_a_managed_environment_with_the_plugin_is_fine(tmp_path, monkeypatch):
    from hermes_tenuo import _home

    monkeypatch.setattr(_home, "hermes_home", lambda: tmp_path)
    _managed(tmp_path, with_plugin=True)
    assert _home.managed_environments_without_plugin() == []


def test_a_named_profile_looks_at_the_install_it_belongs_to(tmp_path, monkeypatch):
    from hermes_tenuo import _home

    profile = tmp_path / "profiles" / "worker"
    profile.mkdir(parents=True)
    monkeypatch.setattr(_home, "hermes_home", lambda: profile)
    env = _managed(tmp_path, with_plugin=False)
    assert _home.managed_environments_without_plugin() == [env]


def test_a_copy_in_the_default_home_does_not_cover_a_named_profile(tmp_path, monkeypatch):
    """Hermes loads directory plugins from the active profile's own plugins folder."""
    from hermes_tenuo import _home

    profile = tmp_path / "profiles" / "worker"
    profile.mkdir(parents=True)
    (tmp_path / "plugins" / "hermes-tenuo").mkdir(parents=True)
    monkeypatch.setattr(_home, "hermes_home", lambda: profile)
    env = _managed(tmp_path, with_plugin=False)
    assert _home.managed_environments_without_plugin() == [env]
    (profile / "plugins" / "hermes-tenuo").mkdir(parents=True)
    assert _home.managed_environments_without_plugin() == []


def test_only_the_running_install_is_looked_at(tmp_path, monkeypatch):
    """Another Hermes checkout that shares the home has its own environment; it says nothing about this one."""
    from hermes_tenuo import _home

    monkeypatch.setattr(_home, "hermes_home", lambda: tmp_path)
    other = _managed(tmp_path, with_plugin=False, install="other")
    mine = _managed(tmp_path, with_plugin=True, install="mine")
    assert _home.managed_environments_without_plugin() == [other]       # outside Hermes's Python: every record
    _running_install(monkeypatch, tmp_path, "mine")
    assert _home.managed_environments_without_plugin() == []
    _running_install(monkeypatch, tmp_path, "other")
    assert _home.managed_environments_without_plugin() == [other]
    _running_install(monkeypatch, tmp_path, "never-managed")
    assert _home.managed_environments_without_plugin() == []
    assert mine.is_dir()

