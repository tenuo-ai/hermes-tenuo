"""The Hermes hook must never turn an enforcement failure into an allow."""

import logging

from hermes_tenuo._guard import PluginGuard


class _Guard:
    has_warrant = True

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def pre_tool_call(self, **_kwargs):
        if self.error is not None:
            raise self.error
        return self.result


def test_authorization_exception_becomes_block_without_echoing_details(caplog):
    secret = "sensitive-argument-value"
    guard = PluginGuard(_Guard(error=RuntimeError(secret)))

    with caplog.at_level(logging.ERROR, logger="hermes_tenuo._guard"):
        result = guard.pre_tool_call_hook("terminal", {"command": secret})

    assert result == {
        "action": "block",
        "message": "tenuo: authorization check failed (RuntimeError); call blocked",
    }
    assert secret not in caplog.text


def test_malformed_guard_result_fails_closed():
    result = PluginGuard(_Guard(result=True)).pre_tool_call_hook("terminal", {"command": "ls"})
    assert result is not None
    assert result["action"] == "block"
    assert "TypeError" in result["message"]


def test_denial_survives_kanban_bookkeeping_failure(monkeypatch, caplog):
    denied = {"action": "block", "message": "not authorized"}
    guard = PluginGuard(_Guard(result=denied))

    def fail_bookkeeping(*_args):
        raise OSError("database unavailable")

    monkeypatch.setattr(guard, "_auto_block_kanban_task", fail_bookkeeping)
    with caplog.at_level(logging.ERROR, logger="hermes_tenuo._guard"):
        result = guard.pre_tool_call_hook("write_file", {"path": "/tmp/x"})

    assert result is denied
    assert result["action"] == "block"
    assert "call remains blocked" in caplog.text


def test_allow_result_is_unchanged():
    assert PluginGuard(_Guard()).pre_tool_call_hook("web_search", {"query": "q"}) is None
