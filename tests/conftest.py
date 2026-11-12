"""Test isolation: never read or write the developer's real ~/.hermes."""

from __future__ import annotations

import sys

import pytest

_TENUO_ENV = (
    "TENUO_WARRANT", "TENUO_SIGNING_KEY", "TENUO_TRUSTED_ROOT", "TENUO_CHILD_WARRANT",
    "TENUO_AUDIT_LOG", "TENUO_CONNECT_TOKEN", "TENUO_REQUIRE_SESSION_WARRANT",
    "HERMES_KANBAN_TASK",
)


@pytest.fixture(autouse=True)
def _isolated_hermes_home(tmp_path, monkeypatch):
    """Every test gets its own empty HERMES_HOME and no inherited TENUO_* env."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    for name in _TENUO_ENV:
        monkeypatch.delenv(name, raising=False)
    yield


@pytest.fixture(autouse=True)
def _no_device_outlives_its_test(monkeypatch):
    """A Hands device a test left serving is ended with the test, while the test's own
    environment is still in place, so its thread never runs into a later test."""
    yield
    shared = sys.modules.get("tests.test_hands")
    left = shared.end_devices() if shared is not None else []
    assert not left, f"{len(left)} Hands device thread(s) still running after the test ended"
