"""Test isolation: never read or write the developer's real ~/.hermes."""

from __future__ import annotations

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
