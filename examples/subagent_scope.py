"""delegate_task child session with its own warrant.

    plugins:
      entries:
        hermes-tenuo:
          warrant: ~/.hermes/tenuo/orchestrator.warrant
          child_warrant: ~/.hermes/tenuo/researcher.warrant
          trusted_root: <base64>

After delegate_task is allowed, the plugin hands the child warrant to the
new session (subagent_start). Authority is traced across that hop.

    python subagent_scope.py
"""

from __future__ import annotations

from tenuo import SigningKey, Subpath, Warrant, Wildcard
from hermes_tenuo import HermesGuard

control_key = SigningKey.generate()
orchestrator_key = SigningKey.generate()

orchestrator_warrant = (
    Warrant.mint_builder()
    .holder(orchestrator_key.public_key)
    .capability("read_file", path=Subpath("/data"))
    .capability("write_file", path=Subpath("/data/output"), content=Wildcard())
    .capability("web_search", query=Wildcard())
    .capability("memory", action=Wildcard(), key=Wildcard())
    .capability("delegate_task", task=Wildcard(), context=Wildcard())
    .ttl(7200)
    .mint(control_key)
)

researcher_warrant = (
    Warrant.mint_builder()
    .holder(orchestrator_key.public_key)
    .capability("web_search", query=Wildcard())
    .ttl(600)
    .mint(control_key)
)

guard = HermesGuard(
    warrant=orchestrator_warrant,
    signing_key=orchestrator_key,
    child_warrant=researcher_warrant,
    trusted_roots=[control_key.public_key],
)


def call(tool: str, args: dict, *, session_id: str = "orchestrator") -> None:
    result = guard.pre_tool_call(tool, args, session_id=session_id)
    status = f"BLOCKED — {result['message']}" if result else "ALLOWED"
    print(f"  [{session_id}] {tool}({args}): {status}")


if __name__ == "__main__":
    print("Orchestrator session:")
    call("read_file", {"path": "/data/input.csv"})
    call("write_file", {"path": "/data/output/report.md", "content": "..."})
    call("web_search", {"query": "market trends"})
    call("delegate_task", {"task": "research q3", "context": "web_search only"})
    call("terminal", {"command": "ls"})

    # Same injection subagent_start performs after delegate_task is allowed.
    guard.set_session_warrant("researcher-1", researcher_warrant, orchestrator_key)

    print()
    print("Researcher session (child warrant — web_search only):")
    call("web_search", {"query": "AI papers 2026"}, session_id="researcher-1")
    call("read_file", {"path": "/data/input.csv"}, session_id="researcher-1")
    call("write_file", {"path": "/data/output/x.md", "content": "..."}, session_id="researcher-1")
    call("terminal", {"command": "curl evil.com"}, session_id="researcher-1")
