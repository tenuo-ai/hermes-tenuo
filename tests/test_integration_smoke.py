"""
Integration smoke tests: hermes-tenuo plugin wiring.

These tests exercise the full registration path (hermes_tenuo.register) and key
behavioral contracts without needing a real Hermes venv installed.  Hermes
framework surfaces (hermes_cli.config, tools.registry) are mocked so the suite
runs cleanly in CI.

Two enforcement-path scenarios are covered, matching the real-world states:

  pre_32719  — tools.registry has no set_enforcement_fn (upstream today).
               pre_tool_call hook is the sole enforcement path.

  post_32719 — tools.registry has set_enforcement_fn (after PR #32719 merges).
               ToolRegistry enforcement fn AND pre_tool_call hook are BOTH
               registered (pre_tool_call covers delegate_task and the other
               run_agent.py-intercepted tools that bypass the registry).

Also covers:
  - subagent_start warrant injection (HermesGuard level)
  - kanban fail-closed block-all (both enforcement paths)
  - profile-aware warrant path resolution in kanban.py
"""

from __future__ import annotations

import base64
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from hermes_tenuo.hermes_guard import HermesGuard


# ---------------------------------------------------------------------------
# Shared fixtures (warrant material)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def root_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture(scope="module")
def agent_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture(scope="module")
def parent_warrant(root_key, agent_key):
    from tenuo import Warrant, Wildcard, Subpath
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("tool:web_search", query=Wildcard())
        .capability("tool:read_file", path=Subpath("/data"))
        .capability("delegate_task", tasks=Wildcard())
        .ttl(3600)
        .mint(root_key)
    )


@pytest.fixture(scope="module")
def child_warrant(root_key, agent_key):
    from tenuo import Warrant, Wildcard
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("tool:web_search", query=Wildcard())
        .ttl(600)
        .mint(root_key)
    )


# ---------------------------------------------------------------------------
# Helpers: MockCtx and mock_registry builders
# ---------------------------------------------------------------------------


class MockCtx:
    """Minimal Hermes plugin context that records registered hooks."""

    def __init__(self):
        self.hooks: dict[str, list] = {}
        self.skills: dict[str, Any] = {}

    def register_skill(self, name: str, path: Any) -> None:
        self.skills[name] = path

    def register_hook(self, name: str, fn) -> None:
        self.hooks.setdefault(name, []).append(fn)

    def registered(self, name: str) -> bool:
        return bool(self.hooks.get(name))

    def call_hook(self, name: str, **kwargs) -> Optional[Any]:
        """Call the first registered handler for a hook; return its result."""
        handlers = self.hooks.get(name, [])
        for handler in handlers:
            result = handler(**kwargs)
            if result is not None:
                return result
        return None


class _EnforcementDenied(Exception):
    """Stand-in for tools.registry.EnforcementDenied."""


class _StubRegistry:
    """Minimal registry stub with no set_enforcement_fn (pre-#32719 world)."""
    def dispatch(self, tool_name, args, **kwargs):  # pragma: no cover
        raise NotImplementedError


class _EnforcementRegistry:
    """Minimal registry stub with set_enforcement_fn (post-#32719 world)."""
    def __init__(self):
        self._enforcement_fn_store: list = []

    def set_enforcement_fn(self, fn) -> None:
        self._enforcement_fn_store.append(fn)

    def dispatch(self, tool_name, args, **kwargs):  # pragma: no cover
        raise NotImplementedError


def _make_mock_registry_module(has_enforcement_fn: bool):
    """Return a fake tools.registry module.

    Uses plain stub objects (not MagicMock) so that hasattr() behaves correctly:
    MagicMock auto-creates arbitrary attributes, which would make
    hasattr(registry, 'set_enforcement_fn') always return True regardless
    of the has_enforcement_fn flag.
    """
    mod = ModuleType("tools.registry")
    if has_enforcement_fn:
        registry = _EnforcementRegistry()
        mod.EnforcementDenied = _EnforcementDenied
    else:
        registry = _StubRegistry()
    mod.registry = registry
    return mod


@contextmanager
def _plugin_ctx(
    parent_warrant_b64: str,
    agent_key,
    root_key,
    has_registry_enforcement_fn: bool = False,
    env_overrides: Optional[dict] = None,
):
    """Context manager that sets up full register() execution environment.

    Yields (ctx, mock_tools_registry_module) — the mock registry module exposes
    _enforcement_fn_store if has_registry_enforcement_fn is True.
    """
    mock_registry_mod = _make_mock_registry_module(has_registry_enforcement_fn)
    mock_tools_mod = ModuleType("tools")

    # Registration tests only need TENUO_WARRANT set — signing key is not required
    # to build the guard (it's optional; the guard hard-blocks without one, which is
    # fine for verifying that hooks are registered and enforcement fns are called).
    env = {"TENUO_WARRANT": parent_warrant_b64}
    if env_overrides:
        env.update(env_overrides)

    extra_modules = {
        "tools": mock_tools_mod,
        "tools.registry": mock_registry_mod,
    }
    # Remove any pre-existing stubs so our mocks are used
    saved = {k: sys.modules.pop(k, None) for k in extra_modules}

    try:
        sys.modules.update(extra_modules)
        with patch("hermes_tenuo._config._get_plugin_entry", return_value={}):
            with patch.dict(os.environ, env, clear=False):
                ctx = MockCtx()
                # Import fresh each time — avoids stale module-level state
                import importlib
                import hermes_tenuo
                importlib.reload(hermes_tenuo)
                hermes_tenuo.register(ctx)
                yield ctx, mock_registry_mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


# ---------------------------------------------------------------------------
# Helper: raw b64 from a warrant object
# ---------------------------------------------------------------------------


def _warrant_b64(warrant) -> str:
    return base64.b64encode(warrant.to_bytes()).decode()


# ---------------------------------------------------------------------------
# TestHookRegistration
# ---------------------------------------------------------------------------


class TestHookRegistration:
    """Verify which hooks are registered under each enforcement scenario."""

    def test_pre_tool_call_registered_pre_32719(
        self, parent_warrant, agent_key, root_key
    ):
        """pre_tool_call must be registered when set_enforcement_fn is NOT available."""
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
            has_registry_enforcement_fn=False,
        ) as (ctx, _):
            assert ctx.registered("pre_tool_call"), (
                "pre_tool_call hook must be registered on the hook-only path"
            )
            assert "tenuo-scope" in ctx.skills
            skill_md = Path(ctx.skills["tenuo-scope"])
            assert skill_md.is_file()
            assert skill_md.name == "SKILL.md"

    def test_pre_tool_call_registered_post_32719(
        self, parent_warrant, agent_key, root_key
    ):
        """pre_tool_call must be registered even when set_enforcement_fn IS available.

        This is the critical regression guard: delegate_task and the other
        run_agent.py-intercepted tools are never covered by the registry
        enforcement fn — pre_tool_call is their only protection.
        """
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
            has_registry_enforcement_fn=True,
        ) as (ctx, _):
            assert ctx.registered("pre_tool_call"), (
                "pre_tool_call hook must be registered alongside set_enforcement_fn "
                "(needed to cover delegate_task which bypasses the registry)"
            )

    def test_registry_fn_registered_when_available(
        self, parent_warrant, agent_key, root_key
    ):
        """set_enforcement_fn is called exactly once when the registry exposes it."""
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
            has_registry_enforcement_fn=True,
        ) as (ctx, reg_mod):
            store = reg_mod.registry._enforcement_fn_store
            assert len(store) == 1, (
                "set_enforcement_fn should have been called exactly once"
            )
            assert callable(store[0])

    def test_subagent_start_hook_registered(
        self, parent_warrant, agent_key, root_key
    ):
        """subagent_start must always be registered for child warrant injection."""
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
        ) as (ctx, _):
            assert ctx.registered("subagent_start"), (
                "subagent_start hook must be registered"
            )

    def test_session_lifecycle_hooks_registered(
        self, parent_warrant, agent_key, root_key
    ):
        """on_session_start and on_session_end must be registered."""
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
        ) as (ctx, _):
            assert ctx.registered("on_session_start")
            assert ctx.registered("on_session_end")

    def test_unconfigured_register_warns_and_registers_nothing(
        self, parent_warrant, agent_key, root_key, caplog
    ):
        """Enabled-but-empty must be loud: WARNING, no enforcement hooks."""
        import logging
        with caplog.at_level(logging.WARNING, logger="hermes_tenuo"):
            with _plugin_ctx(
                _warrant_b64(parent_warrant), agent_key, root_key,
                env_overrides={"TENUO_WARRANT": "", "TENUO_CONNECT_TOKEN": ""},
            ) as (ctx, _):
                assert not ctx.registered("pre_tool_call")
                assert not ctx.registered("subagent_start")
        assert any("NOT enforced" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# TestEnforcementBehavior
# ---------------------------------------------------------------------------


class TestEnforcementBehavior:
    """Behavioral tests for both enforcement paths via the pre_tool_call hook."""

    @pytest.fixture
    def guard(self, parent_warrant, agent_key, root_key):
        g = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
        )
        g._primary_session_id = "s1"
        return g

    def test_hook_path_blocks_unauthorized_tool_pre_32719(self, guard):
        """pre_tool_call hook blocks a tool not in the warrant."""
        result = guard.pre_tool_call("tool:terminal", {"command": "ls"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"

    def test_hook_path_allows_authorized_tool_pre_32719(self, guard):
        """pre_tool_call hook allows a tool that is in the warrant."""
        result = guard.pre_tool_call("tool:web_search", {"query": "x"}, session_id="s1")
        assert result is None

    def test_registry_fn_raises_enforcement_denied_post_32719(
        self, parent_warrant, agent_key, root_key
    ):
        """After #32719, the enforcement fn raises EnforcementDenied on a denial.

        Uses _plugin_ctx — no signing key configured, so the guard hard-blocks
        everything.  terminal is not in the warrant either way; both reasons cause
        EnforcementDenied, which is exactly the contract we need to verify.
        """
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
            has_registry_enforcement_fn=True,
        ) as (ctx, reg_mod):
            enforcement_fn = reg_mod.registry._enforcement_fn_store[0]
            with pytest.raises(_EnforcementDenied):
                enforcement_fn("tool:terminal", {"command": "ls"}, session_id="s1")

    def test_registry_fn_allows_authorized_tool_post_32719(
        self, parent_warrant, agent_key, root_key
    ):
        """After #32719, the enforcement fn does not raise for an authorized tool.

        Uses PluginGuard directly with a real warrant + signing key + trusted root
        so the guard is in full enforcement mode (not hard-blocked by missing key).
        """
        from hermes_tenuo._guard import PluginGuard

        guard_inner = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
        )
        guard_inner._primary_session_id = "s1"
        guard = PluginGuard(guard_inner)

        enforcement_fn_store = []
        mock_reg = _EnforcementRegistry()

        # Simulate what register() does when it finds set_enforcement_fn
        def _enforcement_fn(tool_name: str, args: dict, **kwargs: Any) -> None:
            result = guard.pre_tool_call_hook(
                tool_name=tool_name, args=args,
                session_id=str(kwargs.get("session_id") or ""),
                task_id="", tool_call_id="",
            )
            if result and result.get("action") == "block":
                raise _EnforcementDenied(result.get("message", "denied"))

        mock_reg.set_enforcement_fn(_enforcement_fn)

        # tool:web_search IS in the warrant — must not raise
        mock_reg._enforcement_fn_store[0]("tool:web_search", {"query": "x"}, session_id="s1")

    def test_delegate_task_covered_by_hook_post_32719(
        self, parent_warrant, agent_key, root_key
    ):
        """delegate_task is covered by the pre_tool_call hook, not the registry fn.

        The registry enforcement fn is never called for delegate_task because
        run_agent.py intercepts it before registry.dispatch().  The pre_tool_call
        hook is the only gate — this test confirms it is registered and authorizes
        delegate_task correctly when the tool is in the warrant.

        Uses PluginGuard directly with full enforcement (signing key + trusted root)
        to avoid the hard-block-due-to-missing-key confound.
        """
        from hermes_tenuo._guard import PluginGuard

        guard_inner = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
        )
        guard_inner._primary_session_id = "s1"
        guard = PluginGuard(guard_inner)

        result = guard.pre_tool_call_hook(
            tool_name="delegate_task",
            args={"tasks": ["research climate change"]},
            session_id="s1",
            task_id="",
            tool_call_id="tc1",
        )
        assert result is None, (
            "delegate_task in warrant must be allowed via the pre_tool_call hook"
        )


# ---------------------------------------------------------------------------
# TestSubagentStartWarrantInjection
# ---------------------------------------------------------------------------


class TestSubagentStartWarrantInjection:
    """Verify that on_subagent_start injects child session warrants correctly.

    These tests operate at the HermesGuard level — no Hermes venv needed.
    """

    @pytest.fixture
    def guard_with_child(self, parent_warrant, child_warrant, agent_key, root_key):
        g = HermesGuard(
            warrant=parent_warrant,
            signing_key=agent_key,
            child_warrant=child_warrant,
            trusted_roots=[root_key.public_key],
        )
        g._primary_session_id = "parent"
        return g

    def test_pending_child_warrant_claimed_for_child_session(
        self, guard_with_child, child_warrant
    ):
        """on_subagent_start claims a pending child warrant and registers it."""
        with guard_with_child._pending_lock:
            guard_with_child._pending_child_warrants[("parent", 0)] = (child_warrant, None)

        guard_with_child.on_subagent_start(
            parent_session_id="parent",
            child_session_id="child-1",
        )

        warrant, _ = guard_with_child._resolve_warrant("child-1")
        assert warrant is child_warrant

    def test_child_blocked_for_parent_only_tool_after_injection(
        self, guard_with_child, child_warrant, agent_key
    ):
        """After subagent_start injects a child warrant, read_file is blocked for child."""
        with guard_with_child._pending_lock:
            guard_with_child._pending_child_warrants[("parent", 0)] = (child_warrant, None)

        guard_with_child.on_subagent_start(
            parent_session_id="parent",
            child_session_id="child-1",
        )

        result = guard_with_child.pre_tool_call(
            "tool:read_file", {"path": "/data/x"}, session_id="child-1"
        )
        assert result is not None
        assert result["action"] == "block"

    def test_child_allowed_for_delegated_tool_after_injection(
        self, guard_with_child, child_warrant
    ):
        """After subagent_start injects a child warrant, web_search is allowed."""
        with guard_with_child._pending_lock:
            guard_with_child._pending_child_warrants[("parent", 0)] = (child_warrant, None)

        guard_with_child.on_subagent_start(
            parent_session_id="parent",
            child_session_id="child-1",
        )

        result = guard_with_child.pre_tool_call(
            "tool:web_search", {"query": "climate"}, session_id="child-1"
        )
        assert result is None

    def test_noop_when_ids_missing(self, guard_with_child):
        """on_subagent_start does nothing when parent or child session id is absent."""
        guard_with_child.on_subagent_start(
            parent_session_id=None, child_session_id="child-1"
        )
        guard_with_child.on_subagent_start(
            parent_session_id="parent", child_session_id=None
        )
        with guard_with_child._session_lock:
            assert "child-1" not in guard_with_child._session_warrants

    def test_no_double_injection_on_repeated_call(
        self, guard_with_child, child_warrant
    ):
        """A second on_subagent_start for the same child is idempotent — no crash."""
        with guard_with_child._pending_lock:
            guard_with_child._pending_child_warrants[("parent", 0)] = (child_warrant, None)
            guard_with_child._pending_child_warrants[("parent", 1)] = (child_warrant, None)

        guard_with_child.on_subagent_start("parent", "child-1")
        guard_with_child.on_subagent_start("parent", "child-1")  # second call — no crash


# ---------------------------------------------------------------------------
# TestKanbanFailClosed
# ---------------------------------------------------------------------------


class TestKanbanFailClosed:
    """Verify that a kanban worker with no task warrant blocks all tool calls."""

    def test_block_all_hook_registered_when_kanban_has_no_warrant(
        self, parent_warrant, agent_key, root_key
    ):
        """register() installs a block-all pre_tool_call hook when HERMES_KANBAN_TASK
        is set but no per-task warrant file exists."""
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
            has_registry_enforcement_fn=False,
            env_overrides={"HERMES_KANBAN_TASK": "task-xyz-missing"},
        ) as (ctx, _):
            # The kanban task has no warrant file → guard is None → block-all hook
            assert ctx.registered("pre_tool_call"), (
                "block-all pre_tool_call hook must be registered for a kanban worker with no warrant"
            )

    def test_block_all_hook_actually_blocks_every_tool(
        self, parent_warrant, agent_key, root_key
    ):
        """The block-all hook returns {'action': 'block'} for every tool name."""
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
            has_registry_enforcement_fn=False,
            env_overrides={"HERMES_KANBAN_TASK": "task-xyz-missing"},
        ) as (ctx, _):
            for tool in ["web_search", "read_file", "terminal", "delegate_task", "execute_code"]:
                result = ctx.call_hook("pre_tool_call", tool_name=tool, args={}, session_id="s1")
                assert result is not None, f"block-all must block {tool}"
                assert result.get("action") == "block", f"block-all action must be 'block' for {tool}"

    def test_block_all_via_registry_fn_when_post_32719(
        self, parent_warrant, agent_key, root_key
    ):
        """When set_enforcement_fn is available, block-all uses it (bypass-immune path)."""
        with _plugin_ctx(
            _warrant_b64(parent_warrant), agent_key, root_key,
            has_registry_enforcement_fn=True,
            env_overrides={"HERMES_KANBAN_TASK": "task-xyz-missing"},
        ) as (ctx, reg_mod):
            store = reg_mod.registry._enforcement_fn_store
            assert len(store) == 1, (
                "block-all should have been installed via set_enforcement_fn"
            )
            block_fn = store[0]
            with pytest.raises(_EnforcementDenied):
                block_fn("web_search", {}, session_id="s1")


# ---------------------------------------------------------------------------
# TestProfileAwareWarrantPath
# ---------------------------------------------------------------------------


class TestProfileAwareWarrantPath:
    """Verify kanban.task_warrant_path() is profile-aware after the #53570 fix."""

    def test_uses_profile_home_when_hermes_constants_available(self, tmp_path):
        """When hermes_constants.get_hermes_home() is importable, warrants live under it."""
        fake_home = tmp_path / "hermes_profile_home"

        mock_hermes_constants = ModuleType("hermes_constants")
        mock_hermes_constants.get_hermes_home = lambda: fake_home

        saved = sys.modules.pop("hermes_constants", None)
        try:
            sys.modules["hermes_constants"] = mock_hermes_constants
            # Re-import to pick up the mocked module
            import importlib
            import hermes_tenuo.kanban as kanban_mod
            importlib.reload(kanban_mod)

            path = kanban_mod.task_warrant_path("my-task")
            assert path == fake_home / "tenuo" / "warrants" / "my-task.warrant"
        finally:
            if saved is None:
                sys.modules.pop("hermes_constants", None)
            else:
                sys.modules["hermes_constants"] = saved
            import hermes_tenuo.kanban as kanban_mod
            importlib.reload(kanban_mod)

    def test_falls_back_to_default_hermes_home(self):
        """When hermes_constants is not importable, path falls back to ~/.hermes."""
        saved = sys.modules.pop("hermes_constants", None)
        try:
            import importlib
            import hermes_tenuo.kanban as kanban_mod
            importlib.reload(kanban_mod)

            path = kanban_mod.task_warrant_path("my-task")
            assert str(path).endswith("tenuo/warrants/my-task.warrant")
            assert "hermes" in str(path)
        finally:
            if saved is not None:
                sys.modules["hermes_constants"] = saved
            import hermes_tenuo.kanban as kanban_mod
            importlib.reload(kanban_mod)

    def test_different_profiles_yield_different_paths(self, tmp_path):
        """Switching the active profile changes the resolved warrant path."""
        profile_a = tmp_path / "profile_a"
        profile_b = tmp_path / "profile_b"

        results = []
        for profile_home in (profile_a, profile_b):
            mock_hermes_constants = ModuleType("hermes_constants")
            mock_hermes_constants.get_hermes_home = lambda h=profile_home: h
            saved = sys.modules.pop("hermes_constants", None)
            try:
                sys.modules["hermes_constants"] = mock_hermes_constants
                import importlib
                import hermes_tenuo.kanban as kanban_mod
                importlib.reload(kanban_mod)
                results.append(kanban_mod.task_warrant_path("task-1"))
            finally:
                if saved is None:
                    sys.modules.pop("hermes_constants", None)
                else:
                    sys.modules["hermes_constants"] = saved
                import hermes_tenuo.kanban as kanban_mod
                importlib.reload(kanban_mod)

        assert results[0] != results[1], (
            "Warrant paths must differ between profiles"
        )
        assert str(results[0]).startswith(str(profile_a))
        assert str(results[1]).startswith(str(profile_b))
