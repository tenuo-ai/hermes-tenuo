"""The plugin hook blocks when the authorization check itself fails.

Hermes lets a tool call through when a pre_tool_call hook raises, so the
hook must turn any error into a block.
"""

from hermes_tenuo._guard import PluginGuard


class _Exploding:
    has_warrant = True

    def pre_tool_call(self, **kwargs):
        raise RuntimeError("boom")


def test_error_in_the_check_blocks_the_call():
    result = PluginGuard(_Exploding()).pre_tool_call_hook(tool_name="terminal", args={"command": "ls"})
    assert result is not None
    assert result["action"] == "block"
    assert "check failed" in result["message"]
